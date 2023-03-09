#ifndef __AMQP_PARSING_MAPS_H
#define __AMQP_PARSING_MAPS_H

#include "protocols/amqp/types.h"

BPF_PERCPU_ARRAY_MAP(amqp_heap, __u32, amqp_heap_helper_t, 1)

#endif