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

    // We need to limit ourselves here as the eBPF verifier will otherwise go crazy.
    __u8 number_of_frames_processed = 0;

    while (current_frame_offset + size_to_load < skb_info.data_end && number_of_frames_processed < 15) {
        current_offset = current_frame_offset;
        number_of_frames_processed++;

        if (bpf_skb_load_bytes_with_telemetry(skb, current_offset, &heap->header, size_to_load) != 0) {
            log_debug("process_amqp: unable to load %d bytes from header\n", size_to_load);
            return 0;
        }

        __u32 frame_length = bpf_ntohl(heap->header.length);
        current_offset += sizeof(amqp_frame_header_t);

        if (heap->header.frame_type == AMQP_FRAME_TYPE_METHOD) {
            log_debug("process_amqp: found method frame\n");
            // Load more data to get class and method

            if (bpf_skb_load_bytes_with_telemetry(skb, current_offset, &heap->method, sizeof(amqp_method_identifier_t)) != 0) {
                log_debug("process_amqp: unable to load method identifier\n", size_to_load);
                current_frame_offset += frame_length;
                continue;
            }

            current_offset += sizeof(amqp_method_identifier_t);
            __u16 class = bpf_ntohs(heap->method.class);
            __u16 method = bpf_ntohs(heap->method.method);
            log_debug("process_amqp: class: %d, method: %d\n", class, method);

            if (class == 60 && method == 60) {
                // The basic.deliver method, which is used to send messages to consumers.
                // This message type has a variable-length consumer tag, delivery tag, and flags we need to skip.
                bpf_skb_load_bytes_with_telemetry(skb, current_offset, &heap->string, 1);
                current_offset += 1 + heap->string.length; // Jump over the consumer tag
                current_offset += sizeof(__u64); // Jump over the delivery tag
                current_offset += sizeof(__u8); // Jump over the flags
            }

            bpf_skb_load_bytes_with_telemetry(skb, current_offset, &heap->string, 1);
            bpf_skb_load_bytes_with_telemetry(skb, current_offset, &heap->string, 1 + heap->string.length);

            if (heap->string.length == 0) {
                bpf_memcpy(&heap->string.data, "(default exchange)", sizeof("(default exchange)"));
            }

            log_debug("process_amqp: Exchange name: %s", heap->string.data);
            bpf_memset(&heap->string.data, 0, sizeof(heap->string.data));
            current_offset += 1 + heap->string.length; // Jump over the exchange name

            bpf_skb_load_bytes_with_telemetry(skb, current_offset, &heap->string, 1);
            bpf_skb_load_bytes_with_telemetry(skb, current_offset, &heap->string, 1 + heap->string.length);
            log_debug("process_amqp: Routing key: %s", heap->string.data);
            current_offset += 1 + heap->string.length; // Jump over the routing key
        }

        current_frame_offset += frame_length;
    }

    return 1;
}
