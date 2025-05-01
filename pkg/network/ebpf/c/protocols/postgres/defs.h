#ifndef __POSTGRES_DEFS_H
#define __POSTGRES_DEFS_H

// Postgres protocol version, in big endian, as described in the protocol
// specification. This is version "3.0". Version "3.0" of the protocol has been
// in use since PostgreSQL 7.4, released more than 20 years ago, so we will focus on this.
// https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-STARTUPMESSAGE
#define PG_STARTUP_VERSION 196608
#define PG_STARTUP_USER_PARAM "user"
#define PG_STARTUP_DATABASE_PARAM "database"

// Frontend messages
#define POSTGRES_QUERY_MAGIC_BYTE 'Q'
#define POSTGRES_BIND_MAGIC_BYTE 'B'
#define POSTGRES_PARSE_MAGIC_BYTE 'P'

// Backend messages
#define POSTGRES_PARSE_COMPLETE_MAGIC_BYTE '1'
#define POSTGRES_BIND_COMPLETE_MAGIC_BYTE '2'
// When we use a connection pool before sending the statement usually we close ('C') the previous one.
// So in the response we can see a close complete message as a first message.
#define POSTGRES_CLOSE_COMPLETE_MAGIC_BYTE '3'
#define POSTGRES_READY_FOR_QUERY_MAGIC_BYTE 'Z'

// Fake Postgres codes created by us to uniform Startup message and TCP termination to postgres standard format message.
#define POSTGRES_STARTUP_FAKE_MAGIC_BYTE '+'
#define POSTGRES_TCP_TERMINATION_FAKE_MAGIC_BYTE '='

// Regular format of postgres message: | byte tag | int32_t len | string payload |
// From https://www.postgresql.org/docs/current/protocol-overview.html:
// The first byte of a message identifies the message type, and the next four
// bytes specify the length of the rest of the message (this length count
// includes itself, but not the message-type byte). The remaining contents of
// the message are determined by the message type
struct pg_message_header {
    __u8 message_tag;
    __u32 message_len; // Big-endian: use bpf_ntohl to read this field
} __attribute__((packed));

// Postgres Startup Message (used when a client connects to the server) differs
// from other messages by not having a message tag.
struct pg_startup_header {
    __u32 message_len; // Big-endian: use bpf_ntohl to read this field
    __u32 version; // Big-endian: use bpf_ntohl to read this field
};

#endif // __POSTGRES_DEFS_H
