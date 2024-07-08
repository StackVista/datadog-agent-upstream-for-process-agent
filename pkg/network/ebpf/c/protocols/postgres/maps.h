#ifndef __POSTGRES_MAPS_H
#define __POSTGRES_MAPS_H

#include "map-defs.h"

#include "protocols/classification/defs.h"
#include "protocols/postgres/types.h"

// A map storing the last observed request timestamps for each postgres connection.
// This is used to calculate the latency of the requests.
// We calculate the latency as the time between the request 
// and the response, so we need to store the request timestamp.
// A PostgreSQL server may have much more than 64 connections, but as long as we have the request timestamp
// still in the map when the first response arrives, we are good.
BPF_LRU_MAP(postgres_connection_states, conn_tuple_t, postgres_connection_state_t, 64)

#endif