#ifndef __AMQP_1_0_0_TYPES_H
#define __AMQP_1_0_0_TYPES_H

// Only defines the minimal set of types required for parsing the AMQP 1.0.0 protocol down to the flow performative.
// Ref: https://www.oasis-open.org/standard/amqp/

#pragma pack(push, 1)

typedef struct {
  __u32 length; // Length of the frame, including the header and footer.
  __u8 doff; // Data offset in 32-bit words. Cannot be less than 2. Must point to somewhere within length.
  __u8 type; // 0x00 for AMQP, not interested in others
  __u16 channel; // 0 for connection-wide
} amqp_1_0_0_frame_header_t;

typedef struct {
    conn_tuple_t tup;
    __u16 channel; // Channel number
    __u32 handle; // Handle of the link
    __u32 delivery_count; // Number of deliveries that have been sent to the link endpoint.
} amqp_1_0_0_transaction_batch_entry_t;

typedef struct {
  __u8 map_type; // Always 0xd0
  __u8 size; // Total size of the elements
  __u8 count; // Number of elements
} amqp_1_0_0_list8;

typedef struct {
  __u8 map_type; // Always 0xc0
  __u32 size; // Total size of the elements
  __u32 count; // Number of elements
} amqp_1_0_0_list32;


#pragma pack(pop)

#endif