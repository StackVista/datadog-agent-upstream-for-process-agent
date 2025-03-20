#ifndef __MONGO_USM_EVENTS
#define __MONGO_USM_EVENTS

#include "protocols/mongo/types.h"
#include "protocols/events.h"

USM_EVENTS_INIT(mongo, mongo_transaction_batch_entry_t, MAX_BATCH_SIZE(mongo_transaction_batch_entry_t));

#endif
