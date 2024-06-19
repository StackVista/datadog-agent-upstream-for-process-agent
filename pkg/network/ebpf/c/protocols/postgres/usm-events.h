#ifndef __POSTGRES_USM_EVENTS_H
#define __POSTGRES_USM_EVENTS_H

#include "protocols/postgres/defs.h"
#include "protocols/events.h"

USM_EVENTS_INIT(POSTGRES, postgres_transaction_batch_entry_t, POSTGRES_BATCH_SIZE);

#endif