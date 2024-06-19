#ifndef __POSTGRES_TYPES_H
#define __POSTGRES_TYPES_H

#pragma pack(push, 1)

typedef struct {
    conn_tuple_t tup;
    __u32 commands_performed; // Number of commands performed. This is an approximation, see is_sql_command for limitations.
} postgres_transaction_batch_entry_t;

#pragma pack(pop)

#endif