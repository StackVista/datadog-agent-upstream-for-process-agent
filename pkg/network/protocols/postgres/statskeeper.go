// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package postgres

import (
	"sync"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// StatKeeper is a struct to hold the records for the postgres protocol
type StatKeeper struct {
	stats      map[Key]*RequestStat
	statsMutex sync.RWMutex
	maxEntries int
}

// NewStatkeeper creates a new StatKeeper
func NewStatkeeper(c *config.Config) (*StatKeeper, error) {
	if err := initializeCaches(); err != nil {
		return nil, err
	}

	newStatKeeper := &StatKeeper{
		maxEntries: c.MaxPostgresStatsBuffered,
	}
	newStatKeeper.resetNoLock()
	return newStatKeeper, nil
}

// Process processes the postgres transaction
func (s *StatKeeper) Process(tx *EventWrapper) {
	s.statsMutex.Lock()
	defer s.statsMutex.Unlock()

	isStatusOnly := tx.process()
	if isStatusOnly {
		return
	}

	key := Key{
		Operation:     tx.getSQLCommand(),
		TableName:     tx.getTableName(),
		ConnectionKey: tx.ConnTuple(),
		DatabaseName:  tx.getDatabaseName(),
	}

	if key.Operation == UnknownOP || key.TableName == UnobservedString {
		log.Debugf("[%s] Message '%c' (key:%s,table:%s,database:%s) fragment %s", key.String(), tx.getTag(), key.Operation.String(), key.TableName, key.DatabaseName, tx.getPayload())
	}

	requestStats, ok := s.stats[key]
	if !ok {
		if len(s.stats) >= s.maxEntries {
			return
		}
		requestStats = new(RequestStat)
		s.stats[key] = requestStats
	}

	if requestStats.Count == 0 {
		// This is the first transaction for this key
		// If we fail here we will try again at the next transaction so we don't increment the count
		if err := requestStats.initSketch(); err != nil {
			return
		}
		requestStats.FirstLatencySample = tx.RequestLatency()
	}
	// today we don't use tags
	requestStats.StaticTags = 0
	requestStats.Count++
	if err := requestStats.Latencies.Add(tx.RequestLatency()); err != nil {
		log.Debugf("could not add request latency to ddsketch: %v", err)
	}
}

// GetAndResetAllStats returns all the records and resets the statskeeper
func (s *StatKeeper) GetAndResetAllStats() map[Key]*RequestStat {
	s.statsMutex.RLock()
	defer s.statsMutex.RUnlock()
	ret := s.stats // No deep copy needed since `s.statskeeper` gets reset
	s.resetNoLock()
	return ret
}

func (s *StatKeeper) resetNoLock() {
	s.stats = make(map[Key]*RequestStat)
}
