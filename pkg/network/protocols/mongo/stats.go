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

// RequestStat stores stats for Mongo requests to a particular key
type RequestStat struct {
	Count int
}

// CombineWith merges the data in 2 RequestStats objects
// newStats is kept as it is, while the method receiver gets mutated
func (r *RequestStat) CombineWith(newStats *RequestStat) {
	r.Count += newStats.Count
}
