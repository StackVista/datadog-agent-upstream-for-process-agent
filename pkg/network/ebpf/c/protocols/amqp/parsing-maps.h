#ifndef __AMQP_PARSING_MAPS_H
#define __AMQP_PARSING_MAPS_H

#include "protocols/amqp/types.h"

BPF_PERCPU_ARRAY_MAP(amqp_heap, __u32, amqp_heap_helper_t, 1)

/// @brief This map is used to store the evidence that we are in the middle of an AMQP connection.
/// The key is the connection tuple and the value is the evidence.
BPF_LRU_MAP(amqp_detection_evidence, conn_tuple_t, __u8, 1)

#endif