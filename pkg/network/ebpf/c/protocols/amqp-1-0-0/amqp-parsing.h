#ifndef __AMQP_1_0_0_PARSING_H
#define __AMQP_1_0_0_PARSING_H


#include "bpf_endian.h"
#include "bpf_unified_buffer_access.h"

#include "protocols/amqp-1-0-0/types.h"
#include "protocols/amqp-1-0-0/helpers.h"
#include "protocols/amqp-1-0-0/parsing-maps.h"
#include "protocols/classification/common.h"


// Actual processing logic for AMQP 1.0.0 messages.
// We only care for frames with the "flow" performative and extract the Delivery-Count value. 
static __always_inline int amqp_1_0_0_process(conn_tuple_t *tup, const bpf_buffer_desc_t *buf) {
    __u32 current_frame_offset = 0;
    __u32 current_offset = current_frame_offset;
    __u32 size_to_load = sizeof(amqp_1_0_0_frame_header_t);
    amqp_1_0_0_frame_header_t header = {};
    amqp_1_0_0_transaction_batch_entry_t batch_entry = {};

    // Normalize the connection tuple so that the direction is always from client to server.
    normalize_tuple(tup);

    // We need to limit ourselves here as the eBPF verifier will otherwise go crazy.
    __u16 number_of_frames_processed = 0;

    while (number_of_frames_processed < 200) {
        current_offset = current_frame_offset;
        number_of_frames_processed++;

        if (bpf_load_data(buf, current_offset, &header, size_to_load) != 0) {
            // Unable to load more data, probably because we are at the end of the packet.
            break;
        }

        __u32 frame_length = bpf_ntohl(header.length);
        current_offset += sizeof(amqp_1_0_0_frame_header_t);

        if (header.type != 0x00) {
            // Not an AMQP frame frame, skip to the next frame
            current_frame_offset += frame_length;
            continue;
        }

        // Load more data to get the performative.
        // The first to bytes here are actually the constructor, but since we are interested in the flow performative only,
        // we can just match the whole 3-byte pattern.
        static const __u8 flow_performative_identifer[] = {0x00, 0x53, 0x13};
        __u8 performative[3] = {};

        if (bpf_load_data(buf, current_offset, performative, 3) != 0) {
            log_debug("amqp_1_0_0_process: unable to load performative\n");
            current_frame_offset += frame_length;
            continue;
        }

        if (bpf_memcmp(performative, flow_performative_identifer, 3) != 0) {
            // Not a flow performative, skip to the next frame
            current_frame_offset += frame_length;
            continue;
        }

        current_offset += 3; // Skip the performative

        amqp_1_0_0_list32 arguments = {};
        if (bpf_load_data(buf, current_offset, &arguments, sizeof(amqp_1_0_0_list32)) != 0) {
            log_debug("amqp_1_0_0_process: unable to load arguments list header\n");
            current_frame_offset += frame_length;
            continue;
        }

        log_debug("amqp_1_0_0_process: arguments.size=%u, arguments.count=%u\n", arguments.size, arguments.count);

        if (arguments.count != 9) {
            log_debug("amqp_1_0_0_process: unexpected number of arguments\n");
            current_frame_offset += frame_length;
            continue;
        }

        current_offset += sizeof(amqp_1_0_0_list32);
        /* 
        // We are interested in the delivery count, which is the 5th argument.
        // Since the arguments are variable-length, we need to parse them one by one.
        __u8 current_argument = 0;
        __u8 constructor = 0;
        __u8 argument_size = 1;
        while (current_argument <= 5) {
            if (bpf_load_data(buf, current_offset, &constructor, 1) != 0) {
                log_debug("amqp_1_0_0_process: unable to load constructor for argument %u\n", current_argument);
                current_frame_offset += frame_length;
                break;
            }

            constructor = constructor & 0xf0; // Mask out the lower 4 bits
            switch (constructor)
            {
            case 0x40:
                // Constructor with no additional data
                argument_size = 1;
                break;
            case 0x50:
                // Constructor with one byte of additional data
                argument_size = 2;
                break;
            case 0x60:
                // Constructor with two bytes of additional data
                argument_size = 3;
                break;
            case 0x70:
                // Constructor with four bytes of additional data
                argument_size = 5;
                break;
            case 0x80:
                // Constructor with eight bytes of additional data
                argument_size = 9;
                break;
            default:
                argument_size = 0;
                break;
            }

            if (argument_size == 0) {
                log_debug("amqp_1_0_0_process: unexpected constructor for argument %u\n", current_argument);
                break;
            }

            current_offset += argument_size;
            current_argument++;
        }

        if (current_argument != 5) {
            log_debug("amqp_1_0_0_process: failed to parse arguments\n");
            current_frame_offset += frame_length;
            continue;
        }

        // We are now at the delivery count argument
        current_offset -= argument_size - 1; // Go back to the start of the delivery count argument
        __u64 delivery_count = 0;
        if (bpf_load_data(buf, current_offset, &delivery_count, argument_size - 1) != 0) {
            log_debug("amqp_1_0_0_process: unable to load constructor for argument %u\n", current_argument);
            current_frame_offset += frame_length;
            break;
        }

        // If we read less than 8 bytes, we need to shift the value to the right to get the actual value.
        delivery_count = delivery_count >> (sizeof(delivery_count) - (argument_size - 1)) * 8;
        delivery_count = bpf_ntohll(delivery_count);
        log_debug("amqp_1_0_0_process: delivery_count=%u\n", delivery_count);
        */

        current_frame_offset += frame_length;
    } // End of frame loop
      
    amqp_1_0_0_batch_enqueue(&batch_entry);

    return 0;
}


// This is our entry point for AMQP 1.0.0 over TLS traffic.
// The TLS dispatcher gives a different context from the unencrypted one, so we need to do a little
// dance here get to the AMQP header.
SEC("uprobe/amqp_1_0_0_process")
int uprobe__amqp_1_0_0_process(struct pt_regs *ctx) {
    const __u32 zero = 0;
    tls_dispatcher_arguments_t *args = bpf_map_lookup_elem(&tls_dispatcher_arguments, &zero);

    if (args == NULL) {
        log_debug("uprobe__amqp_1_0_0_process failed to fetch arguments for tail call\n");
        return 0;
    }

    bpf_buffer_desc_t buf = {
        .type = BPF_BUFFER_TYPE_USER,
        .ptr = args->buffer_ptr,
        .data_offset = 0
    };

    return amqp_1_0_0_process(&args->tup, &buf);
}


// Don't be mislead by the name of this function or by the fact that it is in the socket section.
// This will only be called from the dispatcher for packets on connections that have already been
// identified as AMQP connections. This is for unencrypted traffic only, for TLS traffic, see
// the uprobe__amqp_process function above.
SEC("socket/amqp_1_0_0_process")
int socket__amqp_1_0_0_process(struct __sk_buff* skb) {
    conn_tuple_t tup;
    skb_info_t skb_info;

    if (!fetch_dispatching_arguments(&tup, &skb_info)) {
        log_debug("socket__amqp_1_0_0_process failed to fetch arguments for tail call\n");
        return 0;
    }

    bpf_buffer_desc_t buf = {
        .type = BPF_BUFFER_TYPE_SKB,
        .ptr = skb,
        .data_offset = skb_info.data_off
    };

    return amqp_1_0_0_process(&tup, &buf);
}

#endif