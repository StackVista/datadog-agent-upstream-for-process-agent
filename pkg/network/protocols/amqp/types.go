// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build ignore

package amqp

/*
#include "../../ebpf/c/conn_tuple.h"
#include "../../ebpf/c/protocols/amqp/types.h"
*/
import "C"

type ConnTuple C.conn_tuple_t

type EbpfTx C.amqp_transaction_batch_entry_t

type AMQPIdentifierType int

const (
	AMQP_IDENTIFIER_TYPE_QUEUE AMQPIdentifierType = iota
	AMQP_IDENTIFIER_TYPE_EXCHANGE
	AMQP_IDENTIFIER_TYPE_ADDRESS
)
