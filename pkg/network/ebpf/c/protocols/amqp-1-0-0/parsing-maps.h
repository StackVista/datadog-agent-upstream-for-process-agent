#ifndef __AMQP_1_0_0_PARSING_MAPS_H
#define __AMQP_1_0_0_PARSING_MAPS_H

#include "protocols/amqp-1-0-0/types.h"

BPF_PERCPU_ARRAY_MAP(amqp_1_0_0_heap, __u32, amqp_1_0_0_transaction_batch_entry_t, 1)

/// @brief This map is used to store the evidence that we are in the middle of an AMQP 1.0.x connection.
/// The key is the connection tuple and the value is the evidence.
BPF_LRU_MAP(amqp_1_0_0_detection_evidence, conn_tuple_t, __u8, 1)

#endif