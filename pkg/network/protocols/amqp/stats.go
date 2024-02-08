// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package amqp

import (
	"github.com/DataDog/datadog-agent/pkg/network/types"
)

// RelativeAccuracy defines the acceptable error in quantile values calculated by DDSketch.
// For example, if the actual value at p50 is 100, with a relative accuracy of 0.01 the value calculated
// will be between 99 and 101
const RelativeAccuracy = 0.01

// Key is an identifier for a Mongo connection
// Many requests and responses will generally be observed over a single connection
type Key struct {
	types.ConnectionKey
	ExchangeName string
	QueueName    string
}

// RequestStat stores stats for a given Mongo connection
type RequestStat struct {
	MessagesDelivered uint64
	MessagesPublished uint64
	ReplyCode         uint8
}

func (r *RequestStat) initSketch() (err error) {
	r.MessagesDelivered = 0
	r.MessagesPublished = 0
	r.ReplyCode = 0
	return
}

// CombineWith merges the data in 2 RequestStats objects
// newStats is kept as it is, while the method receiver gets mutated
func (r *RequestStat) CombineWith(newStats *RequestStat) {
	r.MessagesDelivered += newStats.MessagesDelivered
	r.MessagesPublished += newStats.MessagesPublished
	if newStats.ReplyCode != 0 {
		r.ReplyCode = newStats.ReplyCode
	}
}
