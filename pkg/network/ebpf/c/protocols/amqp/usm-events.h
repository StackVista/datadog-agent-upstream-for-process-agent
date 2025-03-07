#ifndef __AMQP_USM_EVENTS_H
#define __AMQP_USM_EVENTS_H

#include "protocols/amqp/types.h"
#include "protocols/events.h"

USM_EVENTS_INIT(amqp, amqp_transaction_batch_entry_t, MAX_BATCH_SIZE(amqp_transaction_batch_entry_t));

#endif