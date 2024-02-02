#pragma once

#pragma pack(push, 1)

typedef struct {
  __u8 length; // Length of following string
  char data[256]; // String data
} amqp_short_string_t;

typedef struct {
  __u16 ticket; // unused
  amqp_short_string_t queue;
} amqp_consume_parameters_t;

typedef struct {
  __u16 ticket; // unused
  amqp_short_string_t exchange;
  // amqp_short_string_t routing_key; follows, but neet to parse exchange.length fo find it.
} amqp_publish_parameters_t;

typedef struct {
  __u8 frame_type;       
  __u16 channel;
  __u32 length;
} amqp_frame_header_t;

typedef struct {
  __u16 class;
  __u16 method;
} amqp_method_identifier_t;

typedef struct {
  amqp_frame_header_t header;
  amqp_method_identifier_t method;
  amqp_short_string_t string;
} amqp_heap_helper_t; // This is a helper struct to be used in the BPF program to load the string from the packet.


typedef struct {
    __u8 preamble[5]; // "AMQP\0"
    __u8 major;
    __u8 minor;
    __u8 revision;
} amqp_protocol_identifier;

#pragma pack(pop)

typedef enum {
  AMQP_FRAME_TYPE_METHOD = 1,
  AMQP_FRAME_TYPE_CONTENT_HEADER = 2,
  AMQP_FRAME_TYPE_CONTENT_BODY = 3,
  AMQP_FRAME_TYPE_HEARTBEAT = 8
} amqp_frame_type_t;

typedef struct {
    conn_tuple_t tup;
    char exchange[256];
    char routing_key[256];
    __u64 messages_delivered; // AMQP connections created on this TCP connection
    __u64 transaction_latency_ns;
} amqp_transaction_batch_entry_t;
