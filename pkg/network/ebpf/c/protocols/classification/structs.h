#ifndef __PROTOCOL_CLASSIFICATION_STRUCTS_H
#define __PROTOCOL_CLASSIFICATION_STRUCTS_H

#include "ktypes.h"

#include "conn_tuple.h"

typedef struct {
    conn_tuple_t tup;
    skb_info_t skb_info;
} dispatcher_arguments_t;

// tls_dispatcher_arguments_t is used by the TLS dispatcher as a common argument
// passed to the individual protocol decoders.
typedef struct {
    conn_tuple_t tup;
    __u64 tags;
    char *buffer_ptr;
    size_t len;
} tls_dispatcher_arguments_t;

#endif
