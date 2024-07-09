#ifndef __POSTGRES_USM_EVENTS_H
#define __POSTGRES_USM_EVENTS_H

#include "protocols/events.h"
#include "protocols/postgres/types.h"

// Every PostgreSQL USM event is one pair of request-response.
// Internally, there is a BPF map keeping track of requests seen so far (see maps.h).
// If more than the size of that map number of requests are open at the same time, some will be unaccounted for.
// If we see a response without a corresponding request, we just ignore it.
// For a query with multiple responses, we define the latency to be the time between the query and the first response.
USM_EVENTS_INIT(postgres, postgres_transaction_batch_entry_t, POSTGRES_BATCH_SIZE);

#endif