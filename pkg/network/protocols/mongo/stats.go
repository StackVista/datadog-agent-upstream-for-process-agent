// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package mongo

import (
	"github.com/DataDog/datadog-agent/pkg/network/types"
	"github.com/DataDog/datadog-agent/pkg/process/util"
)

// Key is an identifier for a Mongo resquest/response pair
type Key struct {
	RequestId int32
	types.ConnectionKey
}

// NewKey generates a new Key
func NewKey(saddr, daddr util.Address, sport, dport uint16, netns uint32, topicName string, requestId int32) Key {
	return Key{
		ConnectionKey: types.NewConnectionKey(saddr, daddr, sport, dport, netns),
		RequestId:     requestId,
	}
}

// RequestStat stores stats for Kafka requests to a particular key
type RequestStat struct {
	Count int
}

type TransactionObservation struct {
	// This field holds the value (in nanoseconds) of the operation.
	// Latency is measured from the time the first byte of the request is sent to the server until the time the first byte of the response is received.
	LatencyNs float64
	Key       Key
}
