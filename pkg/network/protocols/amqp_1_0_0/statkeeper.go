// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package amqp_1_0_0

import (
	"sync"

	"github.com/DataDog/datadog-agent/pkg/network/config"
)

type StatKeeper struct {
	stats      map[Key]*RequestStat
	statsMutex sync.RWMutex
	maxEntries int // Max number of entries in `stats` before we start dropping, also the maximum number of entries in `requestStartTimes`
	telemetry  *Telemetry
}

func NewStatkeeper(c *config.Config, telemetry *Telemetry) *StatKeeper {
	return &StatKeeper{
		stats:      make(map[Key]*RequestStat),
		maxEntries: c.MaxAMQPStatsBuffered,
		telemetry:  telemetry,
	}
}

func (statKeeper *StatKeeper) Process(tx *EbpfTx) {
	statKeeper.statsMutex.Lock()
	defer statKeeper.statsMutex.Unlock()

	/*
		key := Key{
			ConnectionKey: tx.ConnTuple(),
		}
	*/

	statKeeper.telemetry.transactionsObserved.Add(1)
}

func (statKeeper *StatKeeper) GetAndResetAllStats() map[Key]*RequestStat {
	statKeeper.statsMutex.RLock()
	defer statKeeper.statsMutex.RUnlock()
	ret := statKeeper.stats // No deep copy needed since `statKeeper.stats` gets reset
	statKeeper.stats = make(map[Key]*RequestStat)
	return ret
}
