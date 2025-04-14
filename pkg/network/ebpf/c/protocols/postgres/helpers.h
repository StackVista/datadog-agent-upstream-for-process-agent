#ifndef __POSTGRES_HELPERS_H
#define __POSTGRES_HELPERS_H

#include "defs.h"
#include "protocols/sql/helpers.h"

// is_postgres_connect checks if the buffer is a Postgres startup message.
static __always_inline bool is_postgres_connect(const char *buf, __u32 buf_size) {
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, buf_size, POSTGRES_STARTUP_MIN_LEN);

    struct pg_startup_header *hdr = (struct pg_startup_header *)buf;

    if (hdr->version != bpf_htonl(PG_STARTUP_VERSION)) {
        return false;
    }

    // Check if we can find the user param. Postgres uses C-style strings, so
    // we also check for the terminating null byte.
    return !bpf_memcmp(buf + sizeof(*hdr), PG_STARTUP_USER_PARAM, sizeof(PG_STARTUP_USER_PARAM));
}

// Ideally we would like to catch the bind message but we can only assert against
// the first byte of the message (== 'B'). This is not enough to avoid false positives.
// For this reason we check the bind complete message instead where we can assert at least 5 bytes.
// https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-BINDCOMPLETE
static __always_inline bool is_bind_complete(struct pg_message_header *hdr) {
    return hdr->message_tag == POSTGRES_BIND_COMPLETE_MAGIC_BYTE && hdr->message_len == bpf_htonl(4);
    // we could also improve the assertion looking at the next message code but let's see if we really need it
    // https://github.com/coroot/coroot-node-agent/blob/4a2859b211ecd88a7ed0bd909712d31e133f418e/ebpftracer/ebpf/l7/postgres.c#L34-L47
}

// is_postgres_query checks if the buffer is a regular Postgres message.
static __always_inline bool is_postgres_query(const char *buf, __u32 buf_size) {
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, buf_size, sizeof(struct pg_message_header));

    struct pg_message_header *hdr = (struct pg_message_header *)buf;

    if(is_bind_complete(hdr)) {
        return true;
    }
    
    // We only classify queries for now
    // Relying only on the first byte to be 'C' or 'Q' is probably not enough, could cause many false positives.
    // That's why we also add some checks on the SQL query  at the end of the method
    if (hdr->message_tag != POSTGRES_QUERY_MAGIC_BYTE && hdr->message_tag != POSTGRES_COMMAND_COMPLETE_MAGIC_BYTE) {
        return false;
    }

    __u32 message_len = bpf_ntohl(hdr->message_len);
    if (message_len < POSTGRES_MIN_PAYLOAD_LEN || message_len > POSTGRES_MAX_PAYLOAD_LEN) {
        return false;
    }

    return is_sql_command(buf + sizeof(*hdr), buf_size - sizeof(*hdr));
}

static __always_inline bool is_postgres(const char *buf, __u32 buf_size) {
    // putting `is_postgres_connect` before should reduce the execution time because for new connections we should always face the startup message first, but it also increase the number of instructions in the verifier ~+500 so at the moment we keep them in this order.
    return is_postgres_query(buf, buf_size) || is_postgres_connect(buf, buf_size);
}

#endif // __POSTGRES_HELPERS_H
