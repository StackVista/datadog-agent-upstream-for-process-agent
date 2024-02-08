// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package amqp

import (
	"bytes"

	"github.com/DataDog/datadog-agent/pkg/network/types"
)

func (tx *EbpfTx) ConnTuple() types.ConnectionKey {
	return types.ConnectionKey{
		SrcIPHigh: tx.Tup.Saddr_h,
		SrcIPLow:  tx.Tup.Saddr_l,
		DstIPHigh: tx.Tup.Daddr_h,
		DstIPLow:  tx.Tup.Daddr_l,
		SrcPort:   tx.Tup.Sport,
		DstPort:   tx.Tup.Dport,
		NetNs:     tx.Tup.Netns,
	}
}

func (tx *EbpfTx) MessagesDelivered() uint32 {
	return tx.Messages_delivered
}

func (tx *EbpfTx) MessagesPublished() uint32 {
	return tx.Messages_published
}

func (tx *EbpfTx) ExchangeOrQueueName() string {
	n := bytes.IndexByte(tx.Exchange_or_queue[:], 0)
	return string(tx.Exchange_or_queue[:n])
}

func (tx *EbpfTx) ReplyCode() uint8 {
	return tx.Reply_code
}
