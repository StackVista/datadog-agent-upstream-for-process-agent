#ifndef __POSTGRES_HELPERS_H
#define __POSTGRES_HELPERS_H

#include "defs.h"
#include "protocols/sql/helpers.h"

static __always_inline bool is_postgres_version(struct pg_startup_header *hdr) {
    return hdr->version == bpf_htonl(PG_STARTUP_VERSION);
}

static __always_inline bool is_startup(const char *buf) {
    struct pg_startup_header *hdr = (struct pg_startup_header *)buf;

    if (!is_postgres_version(hdr)) {
        return false;
    }

    // This is an approximation to avoid a for loop. 
    // We cannot say the `user` or the `database` will be the first parameters. 
    // The official documentation says `Parameters can appear in any order.`
    // https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-STARTUPMESSAGE
    // It's up the client chose the order of the parameters. Some examples below
    // - libqp put always the user first: https://github.com/postgres/postgres/blob/0ff95e0a5be1372bfba9db284ea17c8e0e5da3a0/src/interfaces/libpq/fe-protocol3.c#L2364-L2365
    // - pq go library doesn't force a precise order (go map iteration) https://github.com/lib/pq/blob/b7ffbd3b47da4290a4af2ccd253c74c2c22bfabf/conn.go#L1165
    // - pgx go library doesn't force a precise order (go map iteration): https://github.com/jackc/pgx/blob/9e7f38cd50ecb627ed4a7a392664e342b7235ca1/pgproto3/startup_message.go#L67
    //
    // So this implementation is not 100% correct but it should be good enough for most of the cases since usually user and database
    // are the most common parameters used in the authentication.
    // todo!: use a foor loop to check all the parameters and not just the first two.
    return (bpf_memcmp(buf + sizeof(struct pg_startup_header), PG_STARTUP_USER_PARAM, sizeof(PG_STARTUP_USER_PARAM)) == 0 ||
            bpf_memcmp(buf + sizeof(struct pg_startup_header), PG_STARTUP_DATABASE_PARAM, sizeof(PG_STARTUP_DATABASE_PARAM)) == 0);
}

static __always_inline bool is_response(const char *buf) {
    struct pg_message_header *hdr = (struct pg_message_header *)buf;
    char tag = hdr->message_tag;

    // These messages have fixed length of 4 bytes
    // https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-BINDCOMPLETE
    // https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-PARSECOMPLETE
    // https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-CLOSECOMPLETE
    return (tag == POSTGRES_BIND_COMPLETE_MAGIC_BYTE || 
            tag == POSTGRES_PARSE_COMPLETE_MAGIC_BYTE || 
            tag == POSTGRES_CLOSE_COMPLETE_MAGIC_BYTE) 
            && 
            hdr->message_len == bpf_htonl(4);

    // todo!: we could also improve the assertion looking at the next message tag like here but not sure this stricly necessary:
    // https://github.com/coroot/coroot-node-agent/blob/4a2859b211ecd88a7ed0bd909712d31e133f418e/ebpftracer/ebpf/l7/postgres.c#L34-L47
}

static __always_inline bool is_simple_query(const char *buf) {
    struct pg_message_header *hdr = (struct pg_message_header *)buf;

    // todo!: the sync detection made by coroot is pretty effective but we don't have access to the full payload. 
    // In our case we just have the first 24 bytes so we cannot search for the sync.
    // https://github.com/coroot/coroot-node-agent/blob/4a2859b211ecd88a7ed0bd909712d31e133f418e/ebpftracer/ebpf/l7/postgres.c#L33

    // Relying only on the first byte to be 'Q' is not enough, could cause many false positives.
    // That's why we also add some checks on the SQL query.
    if (hdr->message_tag != POSTGRES_QUERY_MAGIC_BYTE) {
        return false;
    }

    // we can also remove some command if we see that the complexity increases
    return is_sql_command(buf + sizeof(*hdr));
}

// In the socket filter case the buf contains at most 24 bytes because we limit it and the buf_size is the size
// of our internal buffer not the real size of the payload. So we cannot rely on the end of the packet here.
static __always_inline bool is_postgres(const char *buf) {
    if(buf == NULL) {
        return false;
    }

    // Frontend message detection
    if(is_simple_query(buf)) {
        return true;
    }

    // Backend message detection
    if(is_response(buf)) {
        return true;
    }

    // Startup message detection. This a message sent by the frontend but we want to leave it 
    // as the last check since it is the least common.
    if(is_startup(buf)) {
        return true;
    }

    return false;
}

#endif // __POSTGRES_HELPERS_H
