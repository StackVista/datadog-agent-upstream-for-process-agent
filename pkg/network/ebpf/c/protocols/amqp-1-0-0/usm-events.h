#ifndef __AMQP_1_0_0_USM_EVENTS_H
#define __AMQP_1_0_0_USM_EVENTS_H

#include "protocols/amqp-1-0-0/defs.h"
#include "protocols/amqp-1-0-0/types.h"
#include "protocols/events.h"

USM_EVENTS_INIT(amqp_1_0_0, amqp_1_0_0_transaction_batch_entry_t, AMQP_1_0_0_BATCH_SIZE);

#endif