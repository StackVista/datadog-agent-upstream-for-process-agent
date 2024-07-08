#ifndef __POSTGRES_HELPERS_H
#define __POSTGRES_HELPERS_H

#include "defs.h"
#include "protocols/sql/helpers.h"
#include "protocols/postgres/maps.h"

// is_postgres_connect checks if the buffer is a Postgres startup message.
static __always_inline bool is_postgres_connect(const char *buf, __u32 buf_size) {
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, buf_size, POSTGRES_STARTUP_MIN_LEN);

    struct pg_startup_header *hdr = (struct pg_startup_header *)buf;

    if (bpf_ntohl(hdr->version) != PG_STARTUP_VERSION) {
        return false;
    }

    log_debug("is_postgres_connect: version=%u, ", bpf_ntohl(hdr->version));

    // Check if we can find the user param. Postgres uses C-style strings, so
    // we also check for the terminating null byte.
    return !bpf_memcmp(buf + sizeof(*hdr), PG_STARTUP_USER_PARAM, sizeof(PG_STARTUP_USER_PARAM));
}

// is_postgres_query checks if the buffer is a regular Postgres message.
static __always_inline bool is_postgres_query(const char *buf, __u32 buf_size) {
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, buf_size, sizeof(struct pg_message_header));

    struct pg_message_header *hdr = (struct pg_message_header *)buf;

    // We only classify queries for now
    if (hdr->message_tag != POSTGRES_QUERY_MAGIC_BYTE && hdr->message_tag != POSTGRES_COMMAND_COMPLETE_MAGIC_BYTE) {
        return false;
    }

    __u32 message_len = bpf_ntohl(hdr->message_len);
    if (message_len < POSTGRES_MIN_PAYLOAD_LEN || message_len > POSTGRES_MAX_PAYLOAD_LEN) {
        return false;
    }

    log_debug("is_postgres_query: message_len=%u, ", message_len);

    return is_sql_command(buf + sizeof(*hdr), buf_size - sizeof(*hdr));
}

static __always_inline bool is_postgres(conn_tuple_t *tup, const char *buf, __u32 buf_size) {
    void *data = bpf_map_lookup_elem(&postgres_connection_states, tup);
    if (data != NULL) {
        // If the connection is in the map, it has to be a Postgres connection.
        // We do not care about the actual state, as we only need to know if it is a Postgres connection.
        return true;
    }

    // If the reverse tuple is a Postgres connection, we can assume that this is a Postgres connection as well.
    flip_tuple(tup);
    data = bpf_map_lookup_elem(&postgres_connection_states, tup);
    flip_tuple(tup);
    if (data != NULL) {
        return true;
    }
 
    return is_postgres_query(buf, buf_size) || is_postgres_connect(buf, buf_size);
}

#endif // __POSTGRES_HELPERS_H
