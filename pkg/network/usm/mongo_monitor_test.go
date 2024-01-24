// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package usm

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network/protocols"
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
	// To run this test, you need to have a TLS-enabled MongoDB instance running.
	// One way to do this is to use the MongoDB Atlas service, the free tier is enough.
	// Provide the URI of your MongoDB Atlas cluster in the MONGODB_URI environment variable.
	//
	// 	export MONGODB_URI="mongodb+srv://secret_user:secret_pass@free-cluster-01.mongodb.net/?retryWrites=true&w=majority"
	//
	mongoURI := os.Getenv("MONGODB_URI")

	if mongoURI == "" {
		t.Skip("MONGODB_URI not set, skipping test")
	}

	newMongoMonitor(t, getMongoTestConfiguration())

	// Use the SetServerAPIOptions() method to set the Stable API version to 1
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(mongoURI).SetServerAPIOptions(serverAPI)
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

func TestMongoDetection(t *testing.T) {
	monitor := newMongoMonitor(t, getMongoTestConfiguration())

	// We rely on port 27017 for the detection, so do not change it.
	require.NoError(t, mongo.RunServer(t, "0.0.0.0", mongoPort, "7"))

	// Localhost client, use with server above
	client, err := mongo.NewClient(mongo.Options{ServerAddress: "localhost:" + mongoPort, Username: "root", Password: "password"})
	require.NoError(t, err)
	defer client.Stop()

	client.GenerateLoad()

	require.Eventually(t, func() bool {
		protocolStats := monitor.GetProtocolStats()
		mongoProtocolStats, exists := protocolStats[protocols.Mongo]
		// We might not have mongo stats, and it might be the expected case (to capture 0).
		if exists {
			currentStats := mongoProtocolStats.(map[mongo.Key]*mongo.RequestStat)
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
