#ifndef __POSTGRES_USM_EVENTS_H
#define __POSTGRES_USM_EVENTS_H

#include "protocols/events.h"
#include "protocols/postgres/types.h"

// FIXME: What about incomplete events
USM_EVENTS_INIT(postgres, postgres_transaction_batch_entry_t, POSTGRES_BATCH_SIZE);

#endif