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

// `bpf_skb_load_bytes` and `bpf_probe_read_user` return 0 only when we can read all `len` bytes. 
// In all other cases they return EFAULT. 
// So it's very important to check that `len` is not greater than the left payload in the packet otherwise we will face EFAULT.
// It would be nice to create a unique helper for all protocols that takes a compile-time `len` instead of hardcoding the `POSTGRES_BUFFER_SIZE` value
// but this seems very hard to achieve on kernel 5.4.293.
// For some reason the verifier doesn't force the upper bound of R4 even if it is a constant.
// `R4=inv(id=0,umin_value=2,umax_value=4294967295,var_off=(0x0; 0xffffffff))`
static __always_inline __maybe_unused long postgres_pktbuf_safe_load_bytes_from_current_offset(pktbuf_t pkt, void *to) {
    // we truncate the read to the left payload in the packet.
    // `left_payload = 1` is needed by the verifier to understand the min value is 1.
    #define LEFT_PAYLOAD(end, start)                   \
    ({                                             \
        s64 left_payload = (s64)end - (s64)start;  \
        if (left_payload > POSTGRES_BUFFER_SIZE) { \
            left_payload = POSTGRES_BUFFER_SIZE;   \
        }                                          \
        if (left_payload < 1) {                    \
            left_payload = 1;                      \
        }                                          \
        asm volatile("" ::: "memory");             \
        left_payload;                              \
    })

    switch (pkt.type) {
    case PKTBUF_SKB:
        return bpf_skb_load_bytes(pkt.skb, pkt.skb_info->data_off, to, LEFT_PAYLOAD(pkt.skb_info->data_end, pkt.skb_info->data_off));
    case PKTBUF_TLS:
        return bpf_probe_read_user(to, LEFT_PAYLOAD(pkt.tls->data_end, pkt.tls->data_off), pkt.tls->buffer_ptr + pkt.tls->data_off);
    }

    pktbuf_invalid_operation();
    return 0;
}

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
    // we read the full packet
    postgres_transaction_t t = {};
    postgres_pktbuf_safe_load_bytes_from_current_offset(pkt, &t.request_fragment);

    // Now at the beginning of `t.request_fragment` we have 8 bytes -> `struct pg_startup_header`
    // we want to overwrite it with a postgres "normal" header so that the userspace can parse it as a normal message.
    struct pg_message_header *fake_hdr = (struct pg_message_header *)t.request_fragment;
    fake_hdr->message_tag = POSTGRES_STARTUP_FAKE_MAGIC_BYTE;
    // we remove `4` because `1` is for the first byte (the tag) and `3` is for the 3 bytes of junk.
    fake_hdr->message_len = bpf_htonl(bpf_ntohl(header->message_len) - 4);
    // we overwrite 5 bytes, there are still 3 bytes that contains junk and the userspace should skip them.
    // after the first 8 bytes (5+3) the userspace will find parameters.
    // https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-STARTUPMESSAGE
    // The parameters are a pairs of key-value. Each string is `\0` terminated.
    // example: user\0postgres\0database\0default\0\0
    debug_postgres("startup: tcp_seq %u", pkt.skb_info->tcp_seq);
    postgres_batch_enqueue_wrapper(pkt, &t, false);
}

static __always_inline void postgres_handle_parse(pktbuf_t pkt) {
    postgres_transaction_t t = {};
    postgres_pktbuf_safe_load_bytes_from_current_offset(pkt, t.request_fragment);
    debug_postgres("'P': tcp_seq %u", pkt.skb_info->tcp_seq);
    postgres_batch_enqueue_wrapper(pkt, &t, false);
}

static __always_inline void postgres_handle_termination(pktbuf_t pkt) {
    conn_tuple_t tuple = {};
    if (!postgres_read_tuple(pkt, &tuple)) {
        return;
    }
    // the tuple is normalized
    debug_postgres("termination: tcp_seq %u", pkt.skb_info->tcp_seq);
    bpf_map_delete_elem(&postgres_in_flight, &tuple);
}

static __always_inline void postgres_store_transaction(pktbuf_t pkt) {
    conn_tuple_t conn_tuple = {};
    if (!postgres_read_tuple(pkt, &conn_tuple)) {
        return;
    }
    postgres_transaction_t t = {};
    t.request_started = bpf_ktime_get_ns();
    postgres_pktbuf_safe_load_bytes_from_current_offset(pkt, t.request_fragment);
    debug_postgres("store '%c': tcp_seq %u", t.request_fragment[0], pkt.skb_info->tcp_seq);
    bpf_map_update_elem(&postgres_in_flight, &conn_tuple, &t, BPF_ANY);
}

static __always_inline void postgres_send_transaction(pktbuf_t pkt) {
    conn_tuple_t conn_tuple = {};
    if (!postgres_read_tuple(pkt, &conn_tuple)) {
        return;
    }
    postgres_transaction_t *t = bpf_map_lookup_elem(&postgres_in_flight, &conn_tuple);
    if (!t) {
        return;
    }
    t->response_last_seen = bpf_ktime_get_ns();
    debug_postgres("send '%c': tcp_seq %u", t->request_fragment[0], pkt.skb_info->tcp_seq);
    postgres_batch_enqueue_wrapper(pkt, t, true);
}

static __always_inline void postgres_handle_c_tag(pktbuf_t pkt, struct pg_message_header *header) {
    debug_postgres("'C' tag: tcp_seq %u", pkt.skb_info->tcp_seq);
    uint32_t len = bpf_ntohl(header->message_len);
    // we want to skip the entire message here and see if we have a parse message
    // +1 to skip the first byte.
    pktbuf_advance(pkt, len + 1);
    // we try to read the next message header, if there are no bytes to read it is fine the header
    // will be zeroed and we will skip the following checks.
    pktbuf_load_bytes_from_current_offset(pkt, header, sizeof(struct pg_message_header));
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
// See the design doc for more details:
// https://stackstate.atlassian.net/browse/STAC-22668
static __always_inline void postgres_handle(pktbuf_t pkt) {
    // we don't know if we are a startup message or a regular message so we need to check it.

    ////////////////////////////
    // Startup message detection
    ////////////////////////////
    struct pg_startup_header startup_hdr = { 0 };
    // this method could return EFAULT if the are not enough bytes in the packet.
    // it is fine because it means we are not in a startup message and moreover the helper will
    // memset to zero the `startup_hdr` struct, so we cannot fall in false positives.
    // https://github.com/torvalds/linux/blob/a86bf2283d2c9769205407e2b54777c03d012939/net/core/filter.c#L1753
    pktbuf_load_bytes_from_current_offset(pkt, &startup_hdr, sizeof(struct pg_startup_header));
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
    struct pg_message_header header = { 0 };
    // in this case we are sure we have enough bytes in the packet because we are in a regular message postgres message so the header should always be there.
    pktbuf_load_bytes_from_current_offset(pkt, &header, sizeof(struct pg_message_header));
    switch (header.message_tag) {
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
        postgres_handle_c_tag(pkt, &header);
        break;

    default:
        // As a last resort we check for it.
        postgres_handle_ready_for_query(pkt, &header);
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
