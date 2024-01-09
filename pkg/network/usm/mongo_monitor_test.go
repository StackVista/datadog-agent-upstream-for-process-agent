// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package usm

import (
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network/protocols"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/ebpf/ebpftest"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/mongo"
)

const (
	mongoPort = "27017"
)

func TestMongoDetection(t *testing.T) {

	// We rely on port 27017 for the detection, so do not change it.
	//	require.NoError(t, mongo.RunServer(t, "localhost", mongoPort))
	client, err := mongo.NewClient(mongo.Options{ServerAddress: "localhost:" + mongoPort, Username: "root", Password: "password"})
	t.Logf("Waiting for mongo server to be ready, client error: %v", err)
	defer client.Stop()

	monitor := newMongoMonitor(t, getMongoTestConfiguration())
	expectedStatsCount := 1
	statsCount := PrintableInt(0)
	mongoStats := make(map[mongo.Key]*mongo.RequestStat)
	require.Eventually(t, func() bool {
		protocolStats := monitor.GetProtocolStats()
		mongoProtocolStats, exists := protocolStats[protocols.Mongo]
		// We might not have mongo stats, and it might be the expected case (to capture 0).
		if exists {
			currentStats := mongoProtocolStats.(map[mongo.Key]*mongo.RequestStat)
			for key, stats := range currentStats {
				prevStats, ok := mongoStats[key]
				if ok && prevStats != nil {
					prevStats.CombineWith(stats)
				} else {
					mongoStats[key] = currentStats[key]
				}
			}
		}
		statsCount = PrintableInt(len(mongoStats))
		return expectedStatsCount == len(mongoStats)
	}, time.Second*5, time.Millisecond*100, "Expected to find a %d stats, instead captured %v", expectedStatsCount, &statsCount)
}

func getMongoTestConfiguration() *config.Config {
	cfg := config.New()
	cfg.EnableKafkaMonitoring = false
	cfg.EnableMongoMonitoring = true
	cfg.MaxTrackedConnections = 1000
	return cfg
}

func newMongoMonitor(t *testing.T, cfg *config.Config) *Monitor {
	monitor, err := NewMonitor(cfg, nil, nil, nil)
	skipIfNotSupported(t, err)
	require.NoError(t, err)
	t.Cleanup(func() {
		monitor.Stop()
	})

	err = monitor.Start()
	require.NoError(t, err)
	return monitor
}

// This test will help us identify if there is any verifier problems while loading the Kafka binary in the CI environment
func TestLoadMongoBinary(t *testing.T) {
	skipTestIfKernelNotSupported(t)

	// ebpftest.RuntimeCompiled requires kernel header files to be present
	buildModesToTest := []ebpftest.BuildMode{ebpftest.Prebuilt, ebpftest.CORE}
	ebpftest.TestBuildModes(t, buildModesToTest, "", func(t *testing.T) {
		t.Run("debug", func(t *testing.T) {
			loadMongoBinary(t, true)
		})
		t.Run("release", func(t *testing.T) {
			loadMongoBinary(t, false)
		})
	})
}

func loadMongoBinary(t *testing.T, debug bool) {
	cfg := getMongoTestConfiguration()

	cfg.BPFDebug = debug

	newMongoMonitor(t, cfg)
}
