// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package postgres

import (
	"github.com/DataDog/sketches-go/ddsketch"

	"github.com/DataDog/datadog-agent/pkg/network/types"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// This file contains the structs used to store and combine the stats for the Postgres protocol.
// The file does not have any build tag, so it can be used in any build as it is used by the tracer package.

// Key is an identifier for a group of Postgres transactions
type Key struct {
	Operation    Operation
	TableName    string
	DatabaseName string
	types.ConnectionKey
}

// NewKey creates a new postgres key
func NewKey(saddr, daddr util.Address, sport, dport uint16, operation Operation, tableName string, netns uint32, databaseName string) Key {
	return Key{
		ConnectionKey: types.NewConnectionKey(saddr, daddr, sport, dport, netns),
		Operation:     operation,
		TableName:     tableName,
		DatabaseName:  databaseName,
	}
}

func NewKeyFromConnection(conn *types.ConnectionKey, operation Operation, tableName string, databaseName string) Key {
	return Key{
		ConnectionKey: *conn,
		Operation:     operation,
		TableName:     tableName,
		DatabaseName:  databaseName,
	}
}

// RequestStat represents a group of Postgres transactions that has a shared key.
type RequestStat struct {
	// this field order is intentional to help the GC pointer tracking
	Latencies          *ddsketch.DDSketch
	FirstLatencySample float64
	Count              int
	StaticTags         uint64
}

// CombineWith merges the data in 2 RequestStats objects
// newStats is kept as it is, while the method receiver gets mutated
func (r *RequestStat) CombineWith(newStats *RequestStat) {
	r.Count += newStats.Count
	r.StaticTags |= newStats.StaticTags
	// If the receiver has no latency sample, use the newStats sample
	if r.FirstLatencySample == 0 {
		r.FirstLatencySample = newStats.FirstLatencySample
	}
	// If newStats has no ddsketch latency, we have nothing to merge
	if newStats.Latencies == nil {
		return
	}
	// If the receiver has no ddsketch latency, use the newStats latency
	if r.Latencies == nil {
		r.Latencies = newStats.Latencies.Copy()
	} else if newStats.Latencies != nil {
		// Merge the ddsketch latencies
		if err := r.Latencies.MergeWith(newStats.Latencies); err != nil {
			logPostgres(log.DebugLvl, "could not add request latency to ddsketch: %v", err)
		}
	}
}

func newRequestStats(latency float64) (*RequestStat, error) {
	req := &RequestStat{
		StaticTags: 0,
	}
	if err := req.initSketch(); err != nil {
		return nil, err
	}
	req.addLatency(latency)
	return req, nil
}

func (r *RequestStat) addLatency(latency float64) {
	// we don't increment the count if we fail
	if err := r.Latencies.Add(latency); err != nil {
		logPostgres(log.WarnLvl, "could not add request latency to ddsketch: %v", err)
		return
	}
	if r.Count == 0 {
		r.FirstLatencySample = latency
	}
	r.Count++
}
