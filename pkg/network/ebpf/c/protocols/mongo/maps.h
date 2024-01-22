#pragma once

#include "map-defs.h"

#include "protocols/classification/defs.h"
#include "protocols/mongo/types.h"

// A map storing the initial observation timestamps for each mongodb connection.
// This is used to calculate the latency of the requests.
// We can keep track of up to 1024 open transaction (requests without a response).
BPF_LRU_MAP(mongo_request_timestamps, mongo_key, __u64, 1024)

// A map storing the number of times we've seen a connection tuple.
// For every connection, we will try to classify it as a mongodb connection a few
// times, before we give up on it. This is done because the MongoDB protocol provides
// very little information in the first few packets that would allow us to classify 
// it securely. If we kept trying forever, many connections would be misclassified.
BPF_LRU_MAP(mongo_connection_classification_tries, conn_tuple_t, __u32, 1024)

// Basically a transaction template.
BPF_PERCPU_ARRAY_MAP(mongo_heap, __u32, mongo_transaction_t, 1)

// This map help us to avoid processing the same traffic twice.
// It holds the last tcp sequence number for each connection.
BPF_HASH_MAP(mongo_last_tcp_seq_per_connection, conn_tuple_t, __u32, 1)
