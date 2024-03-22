// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package amqp

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

	key := Key{
		ConnectionKey: tx.ConnTuple(),
	}

	switch tx.IdentifierType() {
	case AMQP_IDENTIFIER_TYPE_EXCHANGE:
		key.ExchangeName = tx.EntityIdentifier()
	case AMQP_IDENTIFIER_TYPE_QUEUE:
		key.QueueName = tx.EntityIdentifier()
	case AMQP_IDENTIFIER_TYPE_ADDRESS:
		key.Address = tx.EntityIdentifier()
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

	requestStats.MessagesDelivered += uint64(tx.MessagesDelivered())
	requestStats.MessagesPublished += uint64(tx.MessagesPublished())
	if tx.ReplyCode() != 0 {
		requestStats.ReplyCode = tx.ReplyCode()
	}
	statKeeper.telemetry.transactionsObserved.Add(1)
}

func (statKeeper *StatKeeper) GetAndResetAllStats() map[Key]*RequestStat {
	statKeeper.statsMutex.RLock()
	defer statKeeper.statsMutex.RUnlock()
	ret := statKeeper.stats // No deep copy needed since `statKeeper.stats` gets reset
	statKeeper.stats = make(map[Key]*RequestStat)
	return ret
}
