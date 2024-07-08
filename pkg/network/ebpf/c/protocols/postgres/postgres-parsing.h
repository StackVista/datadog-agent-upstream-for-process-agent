#ifndef __POSTGRES_PARSING_H
#define __POSTGRES_PARSING_H


#include "bpf_endian.h"
#include "bpf_unified_buffer_access.h"

#include "protocols/postgres/defs.h"
#include "protocols/postgres/types.h"
#include "protocols/postgres/helpers.h"
#include "protocols/postgres/maps.h"
#include "protocols/classification/common.h"


static __always_inline int postgres_process(conn_tuple_t *tup, const bpf_buffer_desc_t *buf) {
    __u32 current_frame_offset = 0;
    __u32 current_offset = current_frame_offset;
    postgres_message_header_t header = {};
    __u32 size_to_load = sizeof(postgres_message_header_t);

    // If the destination port was ephemeral, we are either witnessing incoming traffic on the client side
    // or outgoing traffic on the server side. In both cases, the content of the message originates from the backend (= server). 
    bool backend_message = normalize_tuple(tup);
    bool frontend_message = !backend_message;

    log_debug("postgres_process: Processing %s message\n", frontend_message ? "frontend" : "backend");


    postgres_connection_state_t state = {};
    postgres_connection_state_t *saved_state = bpf_map_lookup_elem(&postgres_connection_states, tup);

    if (saved_state != NULL) {
        state = *saved_state;
        log_debug("postgres_process: Connection state loaded\n");
    }

    // FIXME: Generate event
    /*
    heap->transaction.tup = *tup;
    heap->transaction.reply_code = 0;
    heap->transaction.messages_delivered = 0;
    heap->transaction.messages_published = 0;
    bpf_memset(heap->transaction.exchange_or_queue, 0, 256);
    bpf_memset(heap->string.data, 0, 256);
    */

    // We need to limit ourselves here as the eBPF verifier will otherwise go crazy.
    __u16 number_of_frames_processed = 0;

    while (number_of_frames_processed < 200) {
        current_offset = current_frame_offset;
        number_of_frames_processed++;

        if (bpf_load_data(buf, current_offset, &header, size_to_load) != 0) {
            // Unable to load more data, probably because we are at the end of the packet.
            break;
        }

        int frame_length = bpf_ntohl(header.length) + 1;

        if (current_offset == 0) {
            // This is the first message, which is a startup message and does not have the one-byte identifier.
            // Check if the version matches.
            postgres_startup_message_t startup_message = {};
            bpf_load_data(buf, current_offset, &startup_message, sizeof(startup_message));
            if (bpf_ntohl(startup_message.version) == PG_STARTUP_VERSION) {
                // This is a startup message. Just hop to the next message.
                current_frame_offset += sizeof(startup_message);
                continue;
            }
        }

        if (header.identifier < '0' || header.identifier > 'z') {
            // Out of range, this is not a valid message.
            break;
        }

        if (frontend_message && (header.identifier == 'Q' || header.identifier == 'E')) {
            // This is a query (either a simple query or the execution of a bound query).
            // We record the timestamp and wait for a response to calculate the latency.
            // We do not need to parse the query itself.
            state.request_timestamp = bpf_ktime_get_boot_ns();
        } else if (backend_message && (header.identifier == 'I' || header.identifier == 'C' || header.identifier == 'E')) {
            // This is an answer to a query. We can calculate the latency.
            // Note that E from the backend indicates an error response, while E from the frontend is an execute message.
            if (state.request_timestamp != 0) {
                __u64 current_time = bpf_ktime_get_boot_ns();
                __maybe_unused __u64 latency = current_time - state.request_timestamp;
                state.request_timestamp = 0; // Reset to not double-count when additional responses arrive.
                log_debug("postgres_process: Latency: %llu ms\n", latency/1000);
            } else {
                log_debug("postgres_process: Could not find request timestamp for connection\n");
            }
        }

        bpf_map_update_elem(&postgres_connection_states, tup, &state, BPF_ANY);

        log_debug("postgres_process: Origin: %s, message type %c, length %d\n", frontend_message ? "Frontend" : "Backend", header.identifier, frame_length);     
        current_frame_offset += frame_length;
    } // End of frame loop
    
    /*
    if (heap->transaction.exchange_or_queue[0] != 0) {
        postgres_batch_enqueue(&heap->transaction);
    }
    */

    return 0;
}


// This is our entry point for Postgres over TLS traffic.
// The TLS dispatcher gives a different context from the unencrypted one, so we need to do a little
// dance here get to the Postgres header.
SEC("uprobe/postgres_process")
int uprobe__postgres_process(struct pt_regs *ctx) {
    const __u32 zero = 0;
    tls_dispatcher_arguments_t *args = bpf_map_lookup_elem(&tls_dispatcher_arguments, &zero);

    if (args == NULL) {
        log_debug("uprobe__postgres_process: failed to fetch arguments for tail call\n");
        return 0;
    }

    bpf_buffer_desc_t buf = {
        .type = BPF_BUFFER_TYPE_USER,
        .ptr = args->buffer_ptr,
        .data_offset = 0
    };

    return postgres_process(&args->tup, &buf);
}


SEC("socket/postgres_process")
int socket__postgres_process(struct __sk_buff* skb) {
    conn_tuple_t tup;
    skb_info_t skb_info;

    if (!fetch_dispatching_arguments(&tup, &skb_info)) {
        log_debug("socket__postgres_process: failed to fetch arguments for tail call\n");
        return 0;
    }

    bpf_buffer_desc_t buf = {
        .type = BPF_BUFFER_TYPE_SKB,
        .ptr = skb,
        .data_offset = skb_info.data_off
    };

    return postgres_process(&tup, &buf);
}

#endif