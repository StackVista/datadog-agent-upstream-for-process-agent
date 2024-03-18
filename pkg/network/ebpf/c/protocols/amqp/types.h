#ifndef __AMQP_TYPES_H
#define __AMQP_TYPES_H

#pragma pack(push, 1)

typedef enum {
  AMQP_VERSION_UNKNOWN = 0,
  AMQP_VERSION_0_9_1 = 1,
  AMQP_VERSION_1_0_0 = 2,
  AMQP_VERSION_UNSUPPORTED = 3 // We detected the version, but do not support it.
} amqp_version_t;

typedef struct {
  __u8 length; // Length of following string
  char data[256]; // String data
} amqp_short_string_t;

// AMQP 0-9-1 frame header
typedef struct {
  __u8 frame_type;       
  __u16 channel;
  __u32 length;
} amqp_frame_header_t;

// AMQP 1.0 frame header
typedef struct {
  __u32 length;
  __u8 doff;
  __u8 type;
  __u16 channel; 
  // Performative follows
} amqp_frame_header_v1_t;

typedef struct {
  __u16 class;
  __u16 method;
} amqp_method_identifier_t;

typedef enum {
  AMQP_IDENTIFIER_TYPE_QUEUE = 0, // identifier is an AMQP 0.9.1 queue name
  AMQP_IDENTIFIER_TYPE_EXCHANGE = 1, // identifier is an AMQP 0.9.1 exchange name
  AMQP_IDENTIFIER_TYPE_ADDRESS = 2, // identifier is an AMQP 1.0 address
} amqp_identifier_t;

typedef struct {
    conn_tuple_t tup;
    __u32 messages_delivered; // Messages delivered to the client on this connection. This is the count of messages traveling from the server to the client.
    __u32 messages_published; // Messages published on this connection. This is the count of messages traveling from the client to the server.
    __u8 reply_code; // AMQP reply code. Only transmitted when a connection is closed, 0 otherwise.
    __u8 identifier[256]; // Name of the exchange, queue (for AMQP 0.9.1) or address (for AMQP 1.0.0)
    amqp_identifier_t identifier_type:8; // 1 if the name above is for an exchange, 0 if it is for a queue
} amqp_transaction_batch_entry_t;

typedef struct {
  amqp_frame_header_t header;
  amqp_method_identifier_t method;
  amqp_short_string_t string;
  amqp_transaction_batch_entry_t transaction;
} amqp_heap_helper_t; // This is a helper struct to be used in the BPF program to load the string from the packet.

typedef struct {
    __u8 preamble[4]; // "AMQP"
    __u8 protocol_id; // 2 before TLS handshake, then 0 inside. 
    __u8 major;
    __u8 minor;
    __u8 revision;
} amqp_protocol_identifier;

#pragma pack(pop)

#endif