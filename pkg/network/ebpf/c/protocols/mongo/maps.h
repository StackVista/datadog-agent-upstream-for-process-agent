#pragma once

#include "map-defs.h"

#include "protocols/classification/defs.h"
#include "protocols/mongo/types.h"

// A map storing the initial observation timestamps for each mongodb connection.
// This is used to calculate the latency of the requests.
// We can keep track of up to 1024 open transaction (requests without a response).
BPF_LRU_MAP(mongo_request_timestamps, mongo_key, __u64, 0)

// A map storing the number of times we've seen a connection tuple.
// For every connection, we will try to classify it as a mongodb connection a few
// times, before we give up on it. This is done because the MongoDB protocol provides
// very little information in the first few packets that would allow us to classify 
// it securely. If we kept trying forever, many connections would be misclassified.
// This map can be pretty small. Its may happen then that we drop an entry during 
// classification, but this is fine, the affected connection will just get more tries.
BPF_LRU_MAP(mongo_connection_classification_tries, conn_tuple_t, __u32, 0)
