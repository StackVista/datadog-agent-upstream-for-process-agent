#pragma once

#include "protocols/amqp/types.h"

BPF_PERCPU_ARRAY_MAP(amqp_heap, __u32, amqp_heap_helper_t, 1)
BPF_PERCPU_ARRAY_MAP(amqp_short_string_heap, __u32, amqp_short_string_t, 1)
