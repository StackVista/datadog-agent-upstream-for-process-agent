// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package mongo

import (
	"sync"

	"github.com/DataDog/datadog-agent/pkg/network/config"
)

type StatKeeper struct {
	stats             map[Key]*RequestStat
	statsMutex        sync.RWMutex
	maxEntries        int // Max number of entries in `stats` before we start dropping, also the maximum number of entries in `requestStartTimes`
	telemetry         *Telemetry
	requestStartTimes map[RequestLatencyKey]uint64 // Start time for open requests, where we observed no response yet
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
		requestStartTimes: make(map[RequestLatencyKey]uint64),
	}
}

func (statKeeper *StatKeeper) Process(tx *EbpfTx) {
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

	// STS/JGT:
	// Every message has a request_id, even responses.
	// If a message has a response_to, it's a response and we do not consider it a request,
	// i.e. we do not add its request_id to the latency map.
	// (No responses to responses)

	response_to := tx.ResponseTo()
	latency_key := RequestLatencyKey{connection: key, requestId: response_to}
	start, found := statKeeper.requestStartTimes[latency_key]

	if found && response_to != 0 {
		latency := tx.ObservationTimestamp() - start
		requestStats.Latencies.Add(float64(latency))
		delete(statKeeper.requestStartTimes, latency_key)
		statKeeper.telemetry.transactionsObserved.Add(1)
	} else {
		// Could not match the response_to field to any open request
		// Consider this a request and add the request_id to the latency map

		request_id := tx.RequestId()

		if request_id != 0 {
			latency_key = RequestLatencyKey{connection: key, requestId: request_id}

			if len(statKeeper.requestStartTimes) >= statKeeper.maxEntries {
				// Remove a random entry from the map to make room for the new one
				// We could do a LRU cache, but that would introduce a bias agains long-running requests
				// (which are the ones we are most interested in).
				// Some bias remains anway, as every entry in requestStartTimes has a 1:n change of being evicted
				// every time a new entry is added without a response observed in between, favoring "younger" entries.
				for k := range statKeeper.requestStartTimes {
					delete(statKeeper.requestStartTimes, k)
					break
				}

				// Since we are now unable to match the response to this request when it comes in,
				// we count this as a dropped transaction.
				statKeeper.telemetry.dropped.Add(1)
			}

			statKeeper.requestStartTimes[latency_key] = tx.ObservationTimestamp()
		}

	}
}

func (statKeeper *StatKeeper) GetAndResetAllStats() map[Key]*RequestStat {
	statKeeper.statsMutex.RLock()
	defer statKeeper.statsMutex.RUnlock()
	ret := statKeeper.stats // No deep copy needed since `statKeeper.stats` gets reset
	statKeeper.stats = make(map[Key]*RequestStat)
	return ret
}
