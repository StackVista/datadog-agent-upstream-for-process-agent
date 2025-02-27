#ifndef __MONGO_USM_EVENTS
#define __MONGO_USM_EVENTS

#include "protocols/mongo/types.h"
#include "protocols/events.h"

// todo!: why `MONGO_BATCH_SIZE` is 15 and not the maximum allowed size like in REDIS?
USM_EVENTS_INIT(mongo, mongo_transaction_batch_entry_t, MONGO_BATCH_SIZE);

#endif
