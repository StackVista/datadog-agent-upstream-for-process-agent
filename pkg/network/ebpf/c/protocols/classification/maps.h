#ifndef __PROTOCOL_CLASSIFICATION_MAPS_H
#define __PROTOCOL_CLASSIFICATION_MAPS_H

#include "map-defs.h"

#include "protocols/classification/defs.h"
#include "protocols/classification/structs.h"

// A map storing the initial observation timestamps for each mongodb connection.
// This is used to calculate the latency of the requests.   
BPF_HASH_MAP(mongo_request_timestamps, mongo_key, __u64, 1024)

#endif
