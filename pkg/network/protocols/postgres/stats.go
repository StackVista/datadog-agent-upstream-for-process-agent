// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package postgres

import (
	"github.com/DataDog/datadog-agent/pkg/network/types"
)

// RelativeAccuracy defines the acceptable error in quantile values calculated by DDSketch.
// For example, if the actual value at p50 is 100, with a relative accuracy of 0.01 the value calculated
// will be between 99 and 101
const RelativeAccuracy = 0.01

// Key is an identifier for a PostgreSQL connection
// We will generally just map every TCP connection tuple to a connection
type Key struct {
	types.ConnectionKey
}

// Stats for a particular PostgreSQL connection
type RequestStat struct {
	StatementsExecuted uint64
}

func (r *RequestStat) initSketch() (err error) {
	r.StatementsExecuted = 0
	return
}

// CombineWith merges the data in 2 RequestStats objects
// newStats is kept as it is, while the method receiver gets mutated
func (r *RequestStat) CombineWith(newStats *RequestStat) {
	r.StatementsExecuted += newStats.StatementsExecuted
}
