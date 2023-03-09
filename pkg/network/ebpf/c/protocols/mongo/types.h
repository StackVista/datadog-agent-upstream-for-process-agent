#ifndef __MONGO_TYPES_H
#define __MONGO_TYPES_H

typedef struct {
    __s32   message_length; // total message size, including this
    __s32   request_id;     // identifier for this message
    __s32   response_to;    // requestID from the original request (used in responses from db)
    __s32   op_code;        // request type - see table below for details
} mongo_msg_header;

typedef struct {
    conn_tuple_t tup;
    __u64 mongo_latency_ns;
} mongo_transaction_batch_entry_t;

// The key used in mongo_request_id set.
typedef struct {
    conn_tuple_t tup;
    __s32 req_id;
} mongo_key;

#endif
