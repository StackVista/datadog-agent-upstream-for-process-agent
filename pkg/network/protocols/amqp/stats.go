// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package amqp

import (
	"github.com/DataDog/datadog-agent/pkg/network/types"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/sketches-go/ddsketch"
)

// RelativeAccuracy defines the acceptable error in quantile values calculated by DDSketch.
// For example, if the actual value at p50 is 100, with a relative accuracy of 0.01 the value calculated
// will be between 99 and 101
const RelativeAccuracy = 0.01

// Key is an identifier for a Mongo connection
// Many requests and responses will generally be observed over a single connection
type Key struct {
	types.ConnectionKey
}

// NewKey generates a new Key
func NewKey(saddr, daddr util.Address, sport, dport uint16, netns uint32, topicName string, requestId uint32) Key {
	return Key{
		ConnectionKey: types.NewConnectionKey(saddr, daddr, sport, dport, netns),
	}
}

// RequestStat stores stats for a given Mongo connection
type RequestStat struct {
	Latencies *ddsketch.DDSketch
}

func (r *RequestStat) initSketch() (err error) {
	r.Latencies, err = ddsketch.NewDefaultDDSketch(RelativeAccuracy)
	if err != nil {
		log.Debugf("error recording AMQP transaction latency: could not create new ddsketch: %v", err)
	}
	return
}

// CombineWith merges the data in 2 RequestStats objects
// newStats is kept as it is, while the method receiver gets mutated
func (r *RequestStat) CombineWith(newStats *RequestStat) {
	err := r.Latencies.MergeWith(newStats.Latencies)
	if err != nil {
		log.Debugf("error merging AMQP transactions: %v", err)
	}
}
