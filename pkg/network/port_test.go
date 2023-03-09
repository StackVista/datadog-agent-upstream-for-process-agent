// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package network

import (
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/testutil"

	"github.com/cihub/seelog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"

	netlinktestutil "github.com/DataDog/datadog-agent/pkg/network/netlink/testutil"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

var testRootNs uint32

func TestMain(m *testing.M) {
	rootNs, err := kernel.GetRootNetNamespace("/proc")
	if err != nil {
		log.Critical(err)
		os.Exit(1)
	}
	testRootNs, err = kernel.GetInoForNs(rootNs)
	if err != nil {
		log.Critical(err)
		os.Exit(1)
	}

	logLevel := os.Getenv("DD_LOG_LEVEL")
	if logLevel == "" {
		logLevel = "warn"
	}
	log.SetupLogger(seelog.Default, logLevel)

	os.Exit(m.Run())
}

func TestReadInitialTCPState(t *testing.T) {
	testutil.SkipIfStackState(t, "In a docker container we cannot setup network namespaces")
	nsName := netlinktestutil.AddNS(t)
	t.Cleanup(func() {
		err := exec.Command("testdata/teardown_netns.sh").Run()
		assert.NoError(t, err, "failed to teardown netns")
	})

	err := exec.Command("testdata/setup_netns.sh", nsName).Run()
	require.NoError(t, err, "setup_netns.sh failed")

	l, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	l6, err := net.Listen("tcp6", ":0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	ports := []uint16{
		getPort(t, l),
		getPort(t, l6),
		34567,
		34568,
	}

	ns, err := netns.GetFromName(nsName)
	require.NoError(t, err)
	defer ns.Close()

	nsIno, err := kernel.GetInoForNs(ns)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		initialPorts, err := ReadInitialState("/proc", TCP, true)
		require.NoError(t, err)
		for _, p := range ports[:2] {
			if _, ok := initialPorts[PortMapping{testRootNs, p}]; !ok {
				t.Errorf("PortMapping(testRootNs) returned false for port %d", p)
				return false
			}
		}
		for _, p := range ports[2:] {
			if _, ok := initialPorts[PortMapping{nsIno, p}]; !ok {
				t.Errorf("PortMapping(test ns) returned false for port %d", p)
				return false
			}
		}

		if _, ok := initialPorts[PortMapping{testRootNs, 999}]; ok {
			t.Errorf("expected PortMapping(testRootNs, 999) to not be in the map, but it was")
			return false
		}
		if _, ok := initialPorts[PortMapping{nsIno, 999}]; ok {
			t.Errorf("expected PortMapping(nsIno, 999) to not be in the map, but it was")
			return false
		}

		return true
	}, 3*time.Second, time.Second, "tcp/tcp6 ports are listening")
}

func TestReadInitialUDPState(t *testing.T) {
	testutil.SkipIfStackState(t, "In a docker container we cannot setup network namespaces")
	nsName := netlinktestutil.AddNS(t)
	ns, err = netns.GetFromName(nsName)
	require.NoError(t, err)
	t.Cleanup(func() { ns.Close() })
	rootNs, err = kernel.GetRootNetNamespace("/proc")
	require.NoError(t, err)
	t.Cleanup(func() { rootNs.Close() })

	var protos []string
	switch proto {
	case "tcp":
		protos = []string{"tcp4", "tcp6", "udp4", "udp6"}
	case "udp":
		protos = []string{"udp4", "udp6", "tcp4", "tcp6"}
	}

	var ports []uint16
	for _, proto := range protos {
		ports = append(ports, runServerProcess(t, proto, 0, rootNs))
	}

	for _, proto := range protos {
		ports = append(ports, runServerProcess(t, proto, 0, ns))
	}

	rootNsIno, err := kernel.GetInoForNs(rootNs)
	require.NoError(t, err)
	nsIno, err := kernel.GetInoForNs(ns)
	require.NoError(t, err)

	connType := TCP
	otherConnType := UDP
	if proto == "udp" {
		connType, otherConnType = otherConnType, connType
	}

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		initialPorts, err := ReadInitialState("/proc", connType, true)
		if !assert.NoError(collect, err) {
			return
		}

		// check ports corresponding to proto in root ns
		for _, p := range ports[:2] {
			assert.Containsf(collect, initialPorts, PortMapping{rootNsIno, p}, "PortMapping should exist for %s port %d in root ns", connType, p)
			assert.NotContainsf(collect, initialPorts, PortMapping{nsIno, p}, "PortMapping should not exist for %s port %d in test ns", connType, p)
		}

		// check ports not corresponding to proto in root ns
		for _, p := range ports[2:4] {
			assert.NotContainsf(collect, initialPorts, PortMapping{rootNsIno, p}, "PortMapping should not exist for %s port %d in root ns", otherConnType, p)
			assert.NotContainsf(collect, initialPorts, PortMapping{nsIno, p}, "PortMapping should not exist for %s port %d in root ns", otherConnType, p)
		}

		// check ports corresponding to proto in test ns
		for _, p := range ports[4:6] {
			assert.Containsf(collect, initialPorts, PortMapping{nsIno, p}, "PortMapping should exist for %s port %d in root ns", connType, p)
			assert.NotContainsf(collect, initialPorts, PortMapping{rootNsIno, p}, "PortMapping should not exist for %s port %d in test ns", connType, p)
		}

		// check ports not corresponding to proto in test ns
		for _, p := range ports[6:8] {
			assert.NotContainsf(collect, initialPorts, PortMapping{nsIno, p}, "PortMapping should not exist for %s port %d in root ns", otherConnType, p)
			assert.NotContainsf(collect, initialPorts, PortMapping{testRootNs, p}, "PortMapping should not exist for %s port %d in root ns", otherConnType, p)
		}

		assert.NotContainsf(collect, initialPorts, PortMapping{testRootNs, 999}, "expected PortMapping(testRootNs, 999) to not be in the map for root ns, but it was")
		assert.NotContainsf(collect, initialPorts, PortMapping{testRootNs, 999}, "expected PortMapping(nsIno, 999) to not be in the map for test ns, but it was")
	}, 3*time.Second, time.Second, "tcp/tcp6 ports are listening")
}
