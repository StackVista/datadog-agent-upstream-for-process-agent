#ifndef __POSTGRES_TYPES_H
#define __POSTGRES_TYPES_H

#pragma pack(push, 1)

typedef struct {
    __u64 request_timestamp; // 0 if no request in flight.
} postgres_connection_state_t;

// Every batch entry represents a measurement of one query-response pair.
typedef struct {
    conn_tuple_t tup;
    __u64 latency; // Latency in nanosconds.
    char response_type; // Straight from the wire, see https://www.postgresql.org/docs/current/protocol-message-formats.html for values.
    char details[32]; // Additional details, such as the command type and number of rows affected. May be truncated.
} postgres_transaction_batch_entry_t;

// All messages in Postgres start with a message header, except
// for the very first message, which is a startup message and does not have the one-byte identifier.
typedef struct {
    int length;
    int version; // We only support "196608" here.
} postgres_startup_message_t;

typedef struct {
    char identifier;
    int length;
} postgres_message_header_t;

#pragma pack(pop)

#endif