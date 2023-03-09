#ifndef __PROTOCOL_CLASSIFICATION_STRUCTS_H
#define __PROTOCOL_CLASSIFICATION_STRUCTS_H

#include "ktypes.h"

#include "conn_tuple.h"

typedef struct {
    conn_tuple_t tup;
    skb_info_t skb_info;
} dispatcher_arguments_t;

typedef struct {
    conn_tuple_t tup;
    __u64 tags;
    char *buffer_ptr;
    size_t len;
} tls_dispatcher_arguments_t;

#endif
