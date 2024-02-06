#pragma once

#include "bpf_endian.h"

#include "protocols/amqp/defs.h"
#include "protocols/amqp/types.h"
#include "protocols/amqp/helpers.h"
#include "protocols/amqp/parsing-maps.h"
#include "protocols/classification/common.h"

// Don't be mislead by the name of this function or by the fact that it is in the socket section.
// This will only be called from the dispatcher for packets on connections that have already been
// identified as mongo connections. This is for unencrypted traffic only, for TLS traffic, see
// the uprobe__mongo_process function above.
SEC("socket/amqp_process")
int socket__amqp_process(struct __sk_buff* skb) {
    conn_tuple_t tup;
    skb_info_t skb_info;

    if (!fetch_dispatching_arguments(&tup, &skb_info)) {
        log_debug("process_amqp failed to fetch arguments for tail call\n");
        return 0;
    }

    // Here is the idea:
    // Since AMQP messages can be very small, we must assume multiple messages can be in the same packet.
    // There are different frame types, of which we are only interested in type 1, the method frame.
    // Each method frame has a class and a method, and then some arguments that are dependent on the class and method.
    // Our loop will look like this:
    //  1. Load the header of the frame to get frame type, channel (unused) and length.
    //  2. If the frame type is not 1, skip to the next frame by advancing the offset by the length of the frame.
    //  3. If the frame type is 1, load the class and method and check if it is a message we are interested in.
    //  4. If it is, load the exchange name and routing key from the arguments. To do so, we may need to parse additional variable-length fields.
    //  5. If it is not, skip to the next frame by advancing the offset by the length of the frame.
    //  6. If we are at the end of the packet, we are done.

    __u32 current_frame_offset = skb_info.data_off;
    __u32 current_offset = current_frame_offset;
    __u32 size_to_load = sizeof(amqp_frame_header_t);
    const u32 zero = 0;
    amqp_heap_helper_t *heap = bpf_map_lookup_elem(&amqp_heap, &zero);

    if (!heap) {
        log_debug("process_amqp: failed to lookup amqp_frame_header_heap\n");
        return 0;
    }

    heap->transaction.messages_delivered = 0;
    heap->transaction.messages_published = 0;
    bpf_memset(heap->transaction.exchange_or_queue, 0, 256);
    bpf_memset(heap->string.data, 0, 256);

    // We need to limit ourselves here as the eBPF verifier will otherwise go crazy.
    __u16 number_of_frames_processed = 0;

    while (current_frame_offset + size_to_load < skb_info.data_end && number_of_frames_processed < 200) {
        current_offset = current_frame_offset;
        number_of_frames_processed++;

        if (bpf_skb_load_bytes_with_telemetry(skb, current_offset, &heap->header, size_to_load) != 0) {
            log_debug("process_amqp: unable to load %d bytes from header\n", size_to_load);
            return 0;
        }

        __u32 frame_length = bpf_ntohl(heap->header.length) + sizeof(amqp_frame_header_t);
        __u8 end_of_frame = 0;
        bpf_skb_load_bytes_with_telemetry(skb, current_offset + frame_length, &end_of_frame, 1);

        if (end_of_frame != 0xce) {
            log_debug("process_amqp: No 0xce marker after frame\n");
            break;
        }

        frame_length++; // Include the 0xce marker, so we can use the frame length to jump to the next frame.
        current_offset += sizeof(amqp_frame_header_t);

        if (heap->header.frame_type != AMQP_FRAME_TYPE_METHOD) {
            // Not a method frame, skip to the next frame
            current_frame_offset += frame_length;
            continue;
        }

        // Load more data to get class and method
        if (bpf_skb_load_bytes_with_telemetry(skb, current_offset, &heap->method, sizeof(amqp_method_identifier_t)) != 0) {
            log_debug("process_amqp: unable to load method identifier\n", size_to_load);
            current_frame_offset += frame_length;
            continue;
        }

        current_offset += sizeof(amqp_method_identifier_t);
        __u16 class = bpf_ntohs(heap->method.class);
        __u16 method = bpf_ntohs(heap->method.method);
        __u8 new_messages_delivered = 0;
        __u8 new_messages_published = 0;

        if (class == 60 && method == 60) { 
            // The basic.deliver method, which is used to send messages to consumers.
            // This message type has a variable-length consumer tag, delivery tag, and flags we need to skip.
            bpf_skb_load_bytes_with_telemetry(skb, current_offset, &heap->string, 1);
            current_offset += 1 + heap->string.length; // Jump over the consumer tag
            current_offset += sizeof(__u64); // Jump over the delivery tag
            current_offset += sizeof(__u8); // Jump over the flags
            new_messages_delivered++;
        } else if (class == 60 && method == 40) {
            // The basic.publish method, which is used to send messages to the server.
            // This messagge type only has the fixed-size ticket field in front of the exchange name and routing key.
            current_offset += sizeof(__u16); // Jump over the ticket
            new_messages_published++;
        } else if (class == 60 && method == 71) {
            // The basic.get-ok method, which is used to return a single message from a synchronous basic.get call.
            // This message type has fixed-size delivery tag and flags fields in front of the exchange name and routing key.
            current_offset += sizeof(__u64); // Jump over the delivery tag
            current_offset += sizeof(__u8); // Jump over the flags
            new_messages_delivered++;
        } else if (class == 10 && method == 50) {
            // The connection.close method, which is used to close a connection.
            // From this message, we extract the reply code only.
            bpf_skb_load_bytes_with_telemetry(skb, current_offset, &heap->transaction.reply_code, 1);
            current_frame_offset += frame_length;
            continue;
        } else {
            // A method frame we are not interested in, skip to the next frame
            current_frame_offset += frame_length;
            continue;
        }

        // We are interested in this message, load the exchange name and routing key.
        // The offset is now at the exchange name.
        bpf_memset(heap->string.data, 0, 256);
        bpf_skb_load_bytes_with_telemetry(skb, current_offset, &heap->string, 1);

        // If we have an exchange name, use that to identify the metrics.
        // If not, use the routing_key, which will then be a queue name.
        bool is_exchange = 0;
        if (heap->string.length != 0) {
            is_exchange = 1;
            bpf_skb_load_bytes_with_telemetry(skb, current_offset, &heap->string, heap->string.length + 1);
        } else {
            is_exchange = 0;
            current_offset += 1 + heap->string.length; // Jump over the exchange name
            bpf_skb_load_bytes_with_telemetry(skb, current_offset, &heap->string, 1);
            bpf_memset(heap->string.data, 0, 256);
            bpf_skb_load_bytes_with_telemetry(skb, current_offset, &heap->string, heap->string.length + 1);
        }

        if (heap->transaction.exchange_or_queue[0] == 0) {
            // No exchange or queue name yet, set it, and we are done.
            bpf_memcpy(heap->transaction.exchange_or_queue, heap->string.data, 256);
            heap->transaction.is_exchange = is_exchange;
            heap->transaction.messages_delivered += new_messages_delivered;
            heap->transaction.messages_published += new_messages_published;
        } else if (bpf_memcmp(heap->transaction.exchange_or_queue, heap->string.data, 256) == 0) {
            // The exchange/queue name matches the previously seen one, keep tallying the messages.
            heap->transaction.messages_delivered += new_messages_delivered;
            heap->transaction.messages_published += new_messages_published;
        } else {
            // The exchange/queue name does not match the previously seen one, but there is already a name set.
            // Send off the previous transaction and set the new name, reset the counters.
            log_debug("process_amqp: in processed/delivered/published: %d/%d/%d\n", number_of_frames_processed, heap->transaction.messages_delivered, heap->transaction.messages_published);
            amqp_batch_enqueue(&heap->transaction);
            bpf_memcpy(heap->transaction.exchange_or_queue, heap->string.data, 256);
            heap->transaction.is_exchange = is_exchange;
            heap->transaction.messages_delivered = new_messages_delivered;
            heap->transaction.messages_published = new_messages_published;
        }

        current_frame_offset += frame_length;
    } // End of frame loop
      
    if (heap->transaction.exchange_or_queue[0] != 0) {
        log_debug("process_amqp: ex processed/delivered/published: %d/%d/%d\n", number_of_frames_processed, heap->transaction.messages_delivered, heap->transaction.messages_published);
        amqp_batch_enqueue(&heap->transaction);
    }

    if (current_frame_offset < skb_info.data_end) {
        log_debug("process_amqp: processed %d frames, but there is still data left in the packet\n", number_of_frames_processed);
    }

    return 1;
}
