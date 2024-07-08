#ifndef __POSTGRES_TYPES_H
#define __POSTGRES_TYPES_H

#pragma pack(push, 1)

typedef struct {
    __u64 request_timestamp; // 0 if no request in flight.
} postgres_connection_state_t;

typedef struct {
    conn_tuple_t tup;
    __u32 commands_performed; // Number of commands performed. This is an approximation, see is_sql_command for limitations.
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