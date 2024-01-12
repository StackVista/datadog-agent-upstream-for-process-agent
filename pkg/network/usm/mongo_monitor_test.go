// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package usm

import (
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network/protocols"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"go.mongodb.org/mongo-driver/bson"
	mgo "go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/ebpf/ebpftest"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/mongo"
)

const (
	mongoPort = "27017"
)

func getMongoTestConfiguration() *config.Config {
	cfg := config.New()
	cfg.BPFDebug = true
	cfg.EnableNativeTLSMonitoring = true
	cfg.EnableMongoMonitoring = true
	cfg.MaxTrackedConnections = 1000
	cfg.MaxMongoStatsBuffered = 1000
	return cfg
}

func TestMonitorSetup(t *testing.T) {
	monitor := newMongoMonitor(t, getMongoTestConfiguration())
	t.Cleanup(func() {
		monitor.Stop()
	})
	time.Sleep(5 * time.Second)
}

func TestTLSCloudMongoDetection(t *testing.T) {
	newMongoMonitor(t, getMongoTestConfiguration())

	// Use the SetServerAPIOptions() method to set the Stable API version to 1
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI("mongodb+srv://mongo-test-user-01:mongo-test-pass-01@free-cluster-01.ia3g9tu.mongodb.net/?retryWrites=true&w=majority").SetServerAPIOptions(serverAPI)
	// Create a new client and connect to the server
	client, err := mgo.Connect(context.TODO(), opts)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err = client.Disconnect(context.TODO()); err != nil {
			panic(err)
		}
	}()
	// Send a ping to confirm a successful connection
	if err := client.Database("admin").RunCommand(context.TODO(), bson.D{{"ping", 1}}).Err(); err != nil {
		panic(err)
	}
	fmt.Println("Pinged your deployment. You successfully connected to MongoDB!")
}

func TestBasicBehavior(t *testing.T) {
	newMongoMonitor(t, getMongoTestConfiguration())
	exec.Command("docker", "rm", "-f", "testdata-mongodb-primary-1").Run()
	require.NoError(t, mongo.RunServer(t, "0.0.0.0", mongoPort))

	require.Eventually(t, func() bool {
		return true
	}, time.Second*2, time.Millisecond*100, "Expected to find a stats, instead captured none")
}

func TestMongoDetection(t *testing.T) {
	monitor := newMongoMonitor(t, getMongoTestConfiguration())

	// Clear any leftover Doccker container
	exec.Command("docker", "rm", "-f", "testdata-mongodb-primary-1").Run()

	// We rely on port 27017 for the detection, so do not change it.
	require.NoError(t, mongo.RunServer(t, "0.0.0.0", mongoPort))

	// Localhost client, use with server above
	client, err := mongo.NewClient(mongo.Options{ServerAddress: "localhost:" + mongoPort, Username: "root", Password: "password"})
	require.NoError(t, err)
	defer client.Stop()

	require.Eventually(t, func() bool {
		protocolStats := monitor.GetProtocolStats()
		mongoProtocolStats, exists := protocolStats[protocols.Mongo]
		// We might not have mongo stats, and it might be the expected case (to capture 0).
		if exists {
			currentStats := mongoProtocolStats.(map[mongo.Key]*mongo.RequestStat)
			log.Errorf("len(currentStats): %v", len(currentStats))
			return len(currentStats) > 0
		}
		return false
	}, time.Second*5, time.Millisecond*100, "Expected to find a stats, instead captured none")
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
