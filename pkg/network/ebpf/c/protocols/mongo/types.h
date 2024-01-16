#ifndef __MONGO_TYPES_H
#define __MONGO_TYPES_H

#include "defs.h"

// The standard mongo header, every message will have this.
// STS/JGT: The docs call the fields "int", but they seem to be unsigned.
// STS/JGT: On the wire, the fields are always little-endian, even though network byte order is traditionally big-endian.
typedef struct {
    __u32 message_length;
    __u32 request_id;
    __u32 response_to; // Only valid for responses
    __u32 op_code;
} __attribute__ ((packed)) mongo_header_t;

#define MONGO_MIN_LENGTH (sizeof(mongo_header_t))

typedef struct {
    __u8 section_type;
    __u32 section_size; // In bytes
    // C string follows
    // BSON follows
}  __attribute__ ((packed)) mongo_message_section_t;

// Header for messages of op_type MONGO_OP_MSG
typedef struct {
    mongo_header_t header; // standard message header
    __u32 flagBits; // message flags
    mongo_message_section_t sections[]; // data sections
    // optional CRC-32C checksum follows
}  __attribute__ ((packed)) mongo_message_header_t;

typedef struct {
    conn_tuple_t tup;
    __u32 mongo_request_id;
    __u32 mongo_response_to;
} mongo_transaction_batch_entry_t;

// Mongo transaction information associated to a certain socket (tuple_t)
typedef struct {
    // this field is used to disambiguate segments in the context of keep-alives
    // we populate it with the TCP seq number of the request and then the response segments
    __u32 tcp_seq;

    __u32 current_offset_in_request_fragment;
    mongo_transaction_batch_entry_t base;
} mongo_transaction_t;

#endif
