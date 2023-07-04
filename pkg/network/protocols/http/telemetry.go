// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build (windows && npm) || linux_bpf
// +build windows,npm linux_bpf

package http

import (
	"time"

	"go.uber.org/atomic"

	libtelemetry "github.com/DataDog/datadog-agent/pkg/network/telemetry"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type telemetry struct {
	then *atomic.Int64

	hits1XX, hits2XX, hits3XX, hits4XX, hits5XX *libtelemetry.Metric

	totalHits    *libtelemetry.Metric
	dropped      *libtelemetry.Metric // this happens when httpStatKeeper reaches capacity
	rejected     *libtelemetry.Metric // this happens when an user-defined reject-filter matches a request
	malformed    *libtelemetry.Metric // this happens when the request doesn't have the expected format
	aggregations *libtelemetry.Metric
	observations *libtelemetry.Metric

	requestFound, requestNotFound, requestLimitReached, requestPacketEnd     *libtelemetry.Metric
	responseFound, responseNotFound, responseLimitReached, responsePacketEnd *libtelemetry.Metric
}

func newTelemetry() (*telemetry, error) {
	metricGroup := libtelemetry.NewMetricGroup(
		"usm.http",
		libtelemetry.OptExpvar,
		libtelemetry.OptMonotonic,
	)

	t := &telemetry{
		then:         atomic.NewInt64(time.Now().Unix()),
		hits1XX:      metricGroup.NewMetric("hits1xx"),
		hits2XX:      metricGroup.NewMetric("hits2xx"),
		hits3XX:      metricGroup.NewMetric("hits3xx"),
		hits4XX:      metricGroup.NewMetric("hits4xx"),
		hits5XX:      metricGroup.NewMetric("hits5xx"),
		aggregations: metricGroup.NewMetric("aggregations"),
		observations: metricGroup.NewMetric("observations"),

		// these metrics are also exported as statsd metrics
		totalHits: metricGroup.NewMetric("total_hits", libtelemetry.OptStatsd),
		dropped:   metricGroup.NewMetric("dropped", libtelemetry.OptStatsd),
		rejected:  metricGroup.NewMetric("rejected", libtelemetry.OptStatsd),
		malformed: metricGroup.NewMetric("malformed", libtelemetry.OptStatsd),

		requestFound:         metricGroup.NewMetric("requestFound"),
		requestNotFound:      metricGroup.NewMetric("requestNotFound"),
		requestLimitReached:  metricGroup.NewMetric("requestLimitReached"),
		requestPacketEnd:     metricGroup.NewMetric("requestPacketEnd"),
		responseFound:        metricGroup.NewMetric("responseFound"),
		responseNotFound:     metricGroup.NewMetric("responseNotFound"),
		responseLimitReached: metricGroup.NewMetric("responseLimitReached"),
		responsePacketEnd:    metricGroup.NewMetric("responsePacketEnd"),
	}

	return t, nil
}

func (t *telemetry) count(tx httpTX) {
	switch tx.StatusClass() {
	case 100:
		t.hits1XX.Add(1)
	case 200:
		t.hits2XX.Add(1)
	case 300:
		t.hits3XX.Add(1)
	case 400:
		t.hits4XX.Add(1)
	case 500:
		t.hits5XX.Add(1)
	}
	t.totalHits.Add(1)
}

func (t *telemetry) log() {
	now := time.Now().Unix()
	then := t.then.Swap(now)

	totalRequests := t.totalHits.Delta()
	dropped := t.dropped.Delta()
	rejected := t.rejected.Delta()
	malformed := t.malformed.Delta()
	aggregations := t.aggregations.Delta()
	observations := t.observations.Delta()
	elapsed := now - then

	log.Infof(
		"http stats summary: requests_processed=%d(%.2f/s) requests_dropped=%d(%.2f/s) requests_rejected=%d(%.2f/s) requests_malformed=%d(%.2f/s) aggregations=%d observations=%d",
		totalRequests,
		float64(totalRequests)/float64(elapsed),
		dropped,
		float64(dropped)/float64(elapsed),
		rejected,
		float64(rejected)/float64(elapsed),
		malformed,
		float64(malformed)/float64(elapsed),
		aggregations,
		observations,
	)

	if t.requestFound.Get() > 0 || t.requestNotFound.Get() > 0 || t.requestLimitReached.Get() > 0 || t.requestPacketEnd.Get() > 0 {
		log.Infof("request observations summary: found=%d notFound=%d limitReached=%d packetEnd=%d",
			t.requestFound.Delta(), t.requestNotFound.Delta(), t.requestLimitReached.Delta(), t.requestPacketEnd.Delta())
		log.Infof("response observations summary: found=%d notFound=%d limitReached=%d packetEnd=%d",
			t.responseFound.Delta(), t.responseNotFound.Delta(), t.responseLimitReached.Delta(), t.responsePacketEnd.Delta())
	}
}
