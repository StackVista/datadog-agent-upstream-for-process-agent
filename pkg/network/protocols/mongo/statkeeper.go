// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package mongo

import (
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network/config"
)

type StatKeeper struct {
	stats             map[Key]*RequestStat
	statsMutex        sync.RWMutex
	maxEntries        int
	telemetry         *Telemetry
	requestStartTimes map[RequestLatencyKey]int64 // Start time for open requests, where we observed no response yet
}

// Read this as "the request with id `requestId` on the connection identified by `connection`"
type RequestLatencyKey struct {
	connection Key
	requestId  uint32
}

func NewStatkeeper(c *config.Config, telemetry *Telemetry) *StatKeeper {
	return &StatKeeper{
		stats:             make(map[Key]*RequestStat),
		maxEntries:        c.MaxMongoStatsBuffered,
		telemetry:         telemetry,
		requestStartTimes: make(map[RequestLatencyKey]int64),
	}
}

func (statKeeper *StatKeeper) Process(tx *EbpfTx) {
	// TODO/JGT: We would like to grab the timestamp at a lower level
	now := time.Now().UnixNano()

	statKeeper.statsMutex.Lock()
	defer statKeeper.statsMutex.Unlock()

	key := Key{
		ConnectionKey: tx.ConnTuple(),
	}
	requestStats, ok := statKeeper.stats[key]

	if !ok {
		if len(statKeeper.stats) >= statKeeper.maxEntries {
			statKeeper.telemetry.dropped.Add(1)
			return
		}
		requestStats = new(RequestStat)
		requestStats.initSketch()
		statKeeper.stats[key] = requestStats
	}

	request_id := tx.RequestId()
	latency_key := RequestLatencyKey{connection: key, requestId: request_id}
	start, found := statKeeper.requestStartTimes[latency_key]
	if !found {
		// TODO/JGT: Put a limit on the amount of open requests we track
		statKeeper.requestStartTimes[latency_key] = now
	} else {
		latency := now - start
		requestStats.Latencies.Add(float64(latency))
		delete(statKeeper.requestStartTimes, latency_key)
	}
}

func (statKeeper *StatKeeper) GetAndResetAllStats() map[Key]*RequestStat {
	statKeeper.statsMutex.RLock()
	defer statKeeper.statsMutex.RUnlock()
	ret := statKeeper.stats // No deep copy needed since `statKeeper.stats` gets reset
	statKeeper.stats = make(map[Key]*RequestStat)
	return ret
}
