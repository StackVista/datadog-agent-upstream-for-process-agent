#ifndef __POSTGRES_DECODING_H
#define __POSTGRES_DECODING_H

#include "bpf_builtins.h"
#include "bpf_telemetry.h"

#include "protocols/sockfd.h"

#include "protocols/helpers/pktbuf.h"
#include "protocols/postgres/decoding-maps.h"
#include "protocols/postgres/defs.h"
#include "protocols/postgres/types.h"
#include "protocols/postgres/usm-events.h"
#include "protocols/read_into_buffer.h"

static __always_inline __maybe_unused bool postgres_read_tuple(pktbuf_t pkt, conn_tuple_t *tup) {
    const __u32 zero = 0;
    switch (pkt.type) {
    case PKTBUF_SKB: {
        dispatcher_arguments_t *args = bpf_map_lookup_elem(&dispatcher_arguments, &zero);
        if (args == NULL) {
            return false;
        }
        bpf_memcpy(tup, &args->tup, sizeof(conn_tuple_t));
        break;
    }
    case PKTBUF_TLS: {
        tls_dispatcher_arguments_t *args = bpf_map_lookup_elem(&tls_dispatcher_arguments, &zero);
        if (args == NULL) {
            return false;
        }
        bpf_memcpy(tup, &args->tup, sizeof(conn_tuple_t));
        break;
    }
    }
    normalize_tuple(tup);
    return true;
}

// Enqueues a batch of events to the user-space. To spare stack size, we take a scratch buffer from the map, copy
// the connection tuple and the transaction to it, and then enqueue the event.
static __always_inline void postgres_batch_enqueue_wrapper(pktbuf_t pkt, postgres_transaction_t *tx, bool delete_in_flight) {
    u32 zero = 0;
    postgres_event_t *event = bpf_map_lookup_elem(&postgres_scratch_buffer, &zero);
    if (!event) {
        return;
    }

    if (!postgres_read_tuple(pkt, &event->tuple)) {
        return;
    }

    if (delete_in_flight) {
        // the tuple must be normalized
        bpf_map_delete_elem(&postgres_in_flight, &event->tuple);
    }

    bpf_memcpy(&event->tx, tx, sizeof(postgres_transaction_t));
    postgres_batch_enqueue(event);
}

static __always_inline void postgres_handle_startup(pktbuf_t pkt, struct pg_startup_header *header) {
    // we now have the parameters.
    // https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-STARTUPMESSAGE
    // The parameters are a pairs of key-value. Each string is `\0` terminated.
    // example: user\0postgres\0database\0default\0\0
    debug_postgres("startup: tcp_seq %u", pkt.skb_info->tcp_seq);
    postgres_transaction_t t = {};
    // we create a fake header so that the userspace doesn't need handle it differently.
    struct pg_message_header *fake_hdr = (struct pg_message_header *)t.request_fragment;
    fake_hdr->message_tag = POSTGRES_STARTUP_FAKE_MAGIC_BYTE;
    // we remove the len of the protocol version from the message length.
    fake_hdr->message_len = bpf_htonl(bpf_ntohl(header->message_len) - 4);
    pktbuf_advance(pkt, sizeof(struct pg_startup_header));
    pktbuf_safe_load_bytes_from_current_offset(pkt, &t.request_fragment[sizeof(struct pg_message_header)], POSTGRES_BUFFER_SIZE - sizeof(struct pg_message_header));
    postgres_batch_enqueue_wrapper(pkt, &t, false);
}

static __always_inline void postgres_handle_parse(pktbuf_t pkt) {
    debug_postgres("parse: tcp_seq %u", pkt.skb_info->tcp_seq);
    postgres_transaction_t t = {};
    pktbuf_safe_load_bytes_from_current_offset(pkt, t.request_fragment, POSTGRES_BUFFER_SIZE);
    postgres_batch_enqueue_wrapper(pkt, &t, false);
}

static __always_inline void postgres_handle_termination(pktbuf_t pkt) {
    debug_postgres("termination: tcp_seq %u", pkt.skb_info->tcp_seq);
    postgres_transaction_t t = {};
    struct pg_message_header *fake_hdr = (struct pg_message_header *)t.request_fragment;
    fake_hdr->message_tag = POSTGRES_TCP_TERMINATION_FAKE_MAGIC_BYTE;
    fake_hdr->message_len = bpf_htonl(4);
    postgres_batch_enqueue_wrapper(pkt, &t, true);
}

static __always_inline void postgres_store_transaction(pktbuf_t pkt) {
    conn_tuple_t conn_tuple = {};
    if (!postgres_read_tuple(pkt, &conn_tuple)) {
        return;
    }
    postgres_transaction_t t = {};
    t.request_started = bpf_ktime_get_ns();
    pktbuf_safe_load_bytes_from_current_offset(pkt, t.request_fragment, POSTGRES_BUFFER_SIZE);
    debug_postgres("store '%c': tcp_seq %u", t.request_fragment[0], pkt.skb_info->tcp_seq);
    bpf_map_update_elem(&postgres_in_flight, &conn_tuple, &t, BPF_ANY);
}

static __always_inline void postgres_send_transaction(pktbuf_t pkt) {
    conn_tuple_t conn_tuple = {};
    if (!postgres_read_tuple(pkt, &conn_tuple)) {
        return;
    }
    postgres_transaction_t *transaction = bpf_map_lookup_elem(&postgres_in_flight, &conn_tuple);
    if (!transaction) {
        return;
    }
    transaction->response_last_seen = bpf_ktime_get_ns();
    debug_postgres("send '%c': tcp_seq %u", transaction->request_fragment[0], pkt.skb_info->tcp_seq);
    postgres_batch_enqueue_wrapper(pkt, transaction, true);
}

static __always_inline void postgres_handle_c_tag(pktbuf_t pkt, struct pg_message_header *header) {
    debug_postgres("'C' tag: tcp_seq %u", pkt.skb_info->tcp_seq);
    uint32_t len = bpf_ntohl(header->message_len);
    // we want to skip the entire message here and see if we have a parse message
    // +1 to skip the first byte.
    pktbuf_advance(pkt, len + 1);
    pktbuf_safe_load_bytes_from_current_offset(pkt, header, sizeof(struct pg_message_header));
    if (header->message_tag == POSTGRES_PARSE_MAGIC_BYTE) {
        // We are interested in the close message because usually after a close statement we have
        // a new parse in the same TCP segment. We want to store the parse if it is there.
        postgres_handle_parse(pkt);
    } else if (header->message_tag == POSTGRES_READY_FOR_QUERY_MAGIC_BYTE) {
        // it means we had a Command Complete message, we can send the transaction.
        postgres_send_transaction(pkt);
    }
}

static __always_inline void postgres_handle_ready_for_query(pktbuf_t pkt, struct pg_message_header *header) {
    // When the backend completes a transaction, it sends a `Z` message.
    // These are usually the last 6 bytes of the packet (`Z` + 4 bytes of len + 1 byte of status).
    // https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-READYFORQUERY
    u32 data_end = pktbuf_data_end(pkt);
    pktbuf_load_bytes(pkt, data_end - 6, header, sizeof(struct pg_message_header));
    // we check also the len just to be sure we didn't read a random 'Z' message.
    if (header->message_tag == POSTGRES_READY_FOR_QUERY_MAGIC_BYTE &&
        header->message_len == bpf_htonl(5)) {
        debug_postgres("'Z' tag: tcp_seq %u", pkt.skb_info->tcp_seq);
        postgres_send_transaction(pkt);
    }
}

// Reads the first message header and decides what to do based on the
// message tag.
static __always_inline void postgres_handle(pktbuf_t pkt) {
    // we don't know if we are a startup message or a regular message so we need to check it.

    ////////////////////////////
    // Startup message detection
    ////////////////////////////
    struct pg_startup_header startup_hdr = { 0 };
    // We use the safe version because we could have a packet with just 5 bytes (e.g. Sync message).
    // We will reuse these bytes later so we want to be sure to read them.
    pktbuf_safe_load_bytes_from_current_offset(pkt, &startup_hdr, sizeof(struct pg_startup_header));
    // checking the version is enough because we are already sure we are a postgres connection, and the version
    // in big endian cannot collide with other message code.
    // the version is `0x00030000` and there are no codes corresponding to `0x00`
    if (is_postgres_version(&startup_hdr)) {
        postgres_handle_startup(pkt, &startup_hdr);
        return;
    }

    ////////////////////////////
    // Regular message detection
    ////////////////////////////

    // We are not in a startup message, so we can assume we are in a regular message.
    // Since the normal header is smaller than the startup one we can simply recast.
    struct pg_message_header *header = (struct pg_message_header *)&startup_hdr;
    switch (header->message_tag) {
        //////////////////////////
        // Frontend messages
        //////////////////////////

    case POSTGRES_PARSE_MAGIC_BYTE:
        postgres_handle_parse(pkt);
        break;

    case POSTGRES_QUERY_MAGIC_BYTE:
    case POSTGRES_BIND_MAGIC_BYTE:
        // Approx, we start to count the latency when we see the bind message and not the Execute one since usually the Bind is the first message.
        postgres_store_transaction(pkt);
        break;

    //////////////////////////
    // Backend messages
    //////////////////////////
    case POSTGRES_BIND_COMPLETE_MAGIC_BYTE:
        postgres_send_transaction(pkt);
        break;

    //////////////////////////
    // Both
    //////////////////////////
    // Since `Close` and `Command complete` share the same byte `C`
    // we need to do some extra steps to decide what do to.
    case 'C':
        postgres_handle_c_tag(pkt, header);
        break;

    default:
        // As a last resort we check for it.
        postgres_handle_ready_for_query(pkt, header);
        break;
    }

    return;
}

// Entrypoint to process plaintext Postgres traffic.
SEC("socket/postgres_handle")
int socket__postgres_handle(struct __sk_buff *skb) {
    skb_info_t skb_info = {};
    if (!fetch_skb_info(&skb_info)) {
        return 0;
    }

    pktbuf_t pkt = pktbuf_from_skb(skb, &skb_info);

    if (is_tcp_termination(&skb_info)) {
        postgres_handle_termination(pkt);
        return 0;
    }

    postgres_handle(pkt);
    return 0;
}

// Entrypoint to process TLS Postgres traffic.
SEC("uprobe/postgres_tls_handle")
int uprobe__postgres_tls_handle(struct pt_regs *ctx) {
    const __u32 zero = 0;

    tls_dispatcher_arguments_t *args = bpf_map_lookup_elem(&tls_dispatcher_arguments, &zero);
    if (args == NULL) {
        return 0;
    }

    pktbuf_t pkt = pktbuf_from_tls(ctx, args);
    postgres_handle(pkt);
    return 0;
}

// Handles connection termination for a TLS Postgres connection.
SEC("uprobe/postgres_tls_termination")
int uprobe__postgres_tls_termination(struct pt_regs *ctx) {
    const __u32 zero = 0;

    tls_dispatcher_arguments_t *args = bpf_map_lookup_elem(&tls_dispatcher_arguments, &zero);
    if (args == NULL) {
        return 0;
    }

    pktbuf_t pkt = pktbuf_from_tls(ctx, args);
    postgres_handle_termination(pkt);
    return 0;
}

#endif
