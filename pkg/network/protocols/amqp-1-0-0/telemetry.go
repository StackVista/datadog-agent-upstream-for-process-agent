// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package amqp_1_0_0

import (
	libtelemetry "github.com/DataDog/datadog-agent/pkg/network/protocols/telemetry"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type Telemetry struct {
	metricGroup *libtelemetry.MetricGroup

	totalHits            *libtelemetry.Counter
	dropped              *libtelemetry.Counter // this happens when AMQPStatKeeper reaches capacity
	transactionsObserved *libtelemetry.Counter
}

func NewTelemetry() *Telemetry {
	metricGroup := libtelemetry.NewMetricGroup("usm.amqp_1_0_0", libtelemetry.OptStatsd)

	return &Telemetry{
		metricGroup: metricGroup,
		// these metrics are also exported as statsd metrics
		totalHits:            metricGroup.NewCounter("total_hits"),
		dropped:              metricGroup.NewCounter("dropped"),
		transactionsObserved: metricGroup.NewCounter("transactions_observed"),
	}
}

func (t *Telemetry) Count(_ *EbpfTx) {
	t.totalHits.Add(1)
}

func (t *Telemetry) Log() {
	log.Infof("AMQP 1.0.0 stats summary: %s", t.metricGroup.Summary())
}
