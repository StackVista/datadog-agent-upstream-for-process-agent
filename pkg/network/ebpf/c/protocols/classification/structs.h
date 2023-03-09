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
    __u64 tags; // connection tags (i.e TLS library kind)
    char *buffer_ptr; // pointer to the user buffer
    size_t data_end; // represents the end of the user buffer
    size_t data_off; // current read offset in the user buffer
    // size_t len; // todo!: we can remove this we can now use `data_end`
} tls_dispatcher_arguments_t;

#endif
