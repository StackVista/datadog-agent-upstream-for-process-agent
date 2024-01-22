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

// Mongo transaction information associated to a certain socket (tuple_t)
typedef struct {
    // this field is used to disambiguate segments in the context of keep-alives
    // we populate it with the TCP seq number of the request and then the response segments
    __u32 tcp_seq;

    __u32 current_offset_in_request_fragment;
    mongo_transaction_batch_entry_t base;
} mongo_transaction_t;

// The key used in mongo_request_id set.
typedef struct {
    conn_tuple_t tup;
    __s32 req_id;
} mongo_key;

#endif
