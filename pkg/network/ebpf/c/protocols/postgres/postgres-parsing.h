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
        log_debug("postgres_process: Header loaded. Frame length: %d\n", frame_length);

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
        } else if (header.identifier == 'I' || header.identifier == 'C' || header.identifier == 'E') { // Needs an `&& backend_message`, but the detection does not work at the moment.
            postgres_transaction_batch_entry_t entry = {
                .tup = *tup,
                .latency = 0,
                .response_type = header.identifier,
                .details = {0}
            };

            // For CommandComplete messages, we can extract the command type and number of rows affected.
            // Format looks like <command> <rows>, with some exceptions.
            // Can be used in user space to tally the number of rows affected by each command.
            // See https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-COMMANDCOMPLETE
            // This is a text-based protocol, and for an arbitrary number of affected rows, it can become arbitraryly long.
            // We limit ourselves to 32 bytes.
            if (header.identifier == 'C') {
                bpf_load_data(buf, current_offset + sizeof(postgres_message_header_t), entry.details, 32);
            } 

            // For ErrorResponse messages, additional error details are provided.
            // The message can contain multiple fields, in no specific order, but we will just grab the first one.
            // Format is <field identifier> <field value>, where <field identifier> is a single char and <field value> is a zero-terminated string. 
            // Again, we limit ourselves to 32 bytes.
            // (Currently does nothing, since there is also a front-end message with identifier 'E' and we will never reach this code until we fix the detection.)
            if (header.identifier == 'E') {
                bpf_load_data(buf, current_offset + sizeof(postgres_message_header_t), entry.details, 32);
                // Yes, this is the same code as above for 'C', but parsing would go here.
            } 

            log_debug("postgres_process: Details for response type %c: %s\n", header.identifier, entry.details);

            // This is an answer to a query. We can calculate the latency.
            // Note that E from the backend indicates an error response, while E from the frontend is an execute message.
            if (state.request_timestamp != 0) {
                __u64 current_time = bpf_ktime_get_boot_ns();
                __maybe_unused __u64 latency = current_time - state.request_timestamp;
                state.request_timestamp = 0; // Reset to not double-count when additional responses arrive.
                entry.latency = latency;
                log_debug("postgres_process: Latency: %llu ms\n", latency/1000);
            } else {
                log_debug("postgres_process: Could not find request timestamp for connection\n");
            }

            if (entry.latency > 0) {
                // Only enqueue if we have a valid latency.
                // Could add additional cases to carry errors, connection, authentication, etc.
                postgres_batch_enqueue(&entry);
            }

        }

        bpf_map_update_elem(&postgres_connection_states, tup, &state, BPF_ANY);

        log_debug("postgres_process: Origin: %s, message type %c, length %d\n", frontend_message ? "Frontend" : "Backend", header.identifier, frame_length);     
        current_frame_offset += frame_length;
    } // End of frame loop
    
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