// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package mongo

import "github.com/DataDog/datadog-agent/pkg/network/types"

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

func (tx *EbpfTx) RequestId() uint32 {
	return tx.Request_id
}

func (tx *EbpfTx) ResponseTo() uint32 {
	return tx.Response_to
}

func (tx *EbpfTx) ObservationTimestamp() uint64 {
	return tx.Timestamp_ns
}
