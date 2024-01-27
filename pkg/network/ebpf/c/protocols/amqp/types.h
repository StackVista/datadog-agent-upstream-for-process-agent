#pragma once

typedef struct {
    __u16 class_id;
    __u16 method_id;
} amqp_header;

typedef struct {
    conn_tuple_t tup;
    __u64 placeholder;
} amqp_transaction_batch_entry_t;
