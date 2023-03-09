// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package monitor

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"
	"go.uber.org/atomic"

	"github.com/DataDog/datadog-agent/pkg/network/protocols/telemetry"
	"github.com/DataDog/datadog-agent/pkg/util"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
)

func getProcessMonitor(t *testing.T) *ProcessMonitor {
	pm := GetProcessMonitor()
	require.NoError(t, pm.Initialize())

	t.Cleanup(func() {
		pm.Stop()
		telemetry.Clear()
	})
	return pm
}

func registerCallback(t *testing.T, pm *ProcessMonitor, isExec bool, callback *ProcessCallback) func() {
	registrationFunc := pm.SubscribeExit
	if isExec {
		registrationFunc = pm.SubscribeExec
	}
	unsubscribe := registrationFunc(*callback)
	t.Cleanup(unsubscribe)
	return unsubscribe
}

func getTestBinaryPath(t *testing.T) string {
	tmpFile, err := os.CreateTemp("", "echo")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.Remove(tmpFile.Name())
	})
	require.NoError(t, util.CopyFile("/bin/echo", tmpFile.Name()))

	return tmpFile.Name()
}

func TestProcessMonitorSingleton(t *testing.T) {
	// Making sure we get the same process monitor if we call it twice.
	pm := getProcessMonitor(t)
	pm2 := getProcessMonitor(t)

	require.Equal(t, pm, pm2)
}

func TestProcessMonitorSanity(t *testing.T) {
	pm := getProcessMonitor(t)
	numberOfExecs := atomic.Int32{}
	testBinaryPath := getTestBinaryPath(t)
	callback := func(pid uint32) { numberOfExecs.Inc() }
	registerCallback(t, pm, true, (*ProcessCallback)(&callback))

	require.NoError(t, exec.Command(testBinaryPath, "test").Run())
	require.Eventuallyf(t, func() bool {
		t.Logf("number of execs: %d", numberOfExecs.Load())
		return numberOfExecs.Load() >= 1
	}, time.Second, time.Millisecond*200, "didn't capture exec events")
}

func mkCallback(t *testing.T, c *atomic.Bool, index int) *ProcessCallback {
	f := func(pid uint32) {
		t.Logf("Storing %d for %d", pid, index)
		c.Store(true)
	}
	return (*ProcessCallback)(&f)
}

func TestProcessRegisterMultipleExecCallbacks(t *testing.T) {
	pm := getProcessMonitor(t)

	const iterations = 10
	counters := make([]*atomic.Bool, iterations)
	for i := 0; i < iterations; i++ {
		counters[i] = atomic.NewBool(false)
		c := counters[i]
		callback := func(pid uint32) { c.Store(true) }
		registerCallback(t, pm, true, (*ProcessCallback)(&callback))
	}

	t.Logf("Number of callbacks: %d", len(pm.processExecCallbacks))
	require.NoError(t, exec.Command("/bin/echo").Run())
	require.Eventuallyf(t, func() bool {
		ok := true
		for i := 0; i < iterations; i++ {
			if !counters[i].Load() {
				t.Logf("iter %d didn't capture event", i)
				ok = false
			}
		}
		return ok
	}, time.Second, time.Millisecond*200, "at least of the callbacks didn't capture events")
}

func TestProcessRegisterMultipleExitCallbacks(t *testing.T) {
	pm := getProcessMonitor(t)

	const iterations = 10
	counters := make([]*atomic.Int32, iterations)
	for i := 0; i < iterations; i++ {
		counters[i] = &atomic.Int32{}
		c := counters[i]
		// Sanity subscribing a callback.
		callback := func(pid uint32) { c.Inc() }
		registerCallback(t, pm, true, (*ProcessCallback)(&callback))
	}

	require.NoError(t, exec.Command("/bin/echo").Run())
	require.Eventuallyf(t, func() bool {
		for i := 0; i < iterations; i++ {
			if counters[i].Load() <= int32(0) {
				t.Logf("iter %d didn't capture event", i)
				return false
			}
		}
		return true
	}, time.Second, time.Millisecond*200, "at least of the callbacks didn't capture events")
}

func TestProcessMonitorRefcount(t *testing.T) {
	var pm *ProcessMonitor

	for i := 1; i <= 10; i++ {
		pm = GetProcessMonitor()
		pm.Initialize()
		require.Equal(t, int32(i), pm.refcount.Load())
	}

	for i := 1; i <= 10; i++ {
		pm.Stop()
		require.Equal(t, int32(10-i), pm.refcount.Load())
	}
}

func TestProcessMonitorInNamespace(t *testing.T) {
	execSet := sync.Map{}

	monNs, err := netns.New()
	require.NoError(t, err, "could not create network namespace for process monitor")
	t.Cleanup(func() { monNs.Close() })

	var pm *ProcessMonitor
	require.NoError(t, kernel.WithNS(monNs,
		func() error {
			pm = getProcessMonitor(t)
			return nil
		},
	), "could not start process monitor in netNS")

	callback := func(pid uint32) { execSet.Store(int(pid), struct{}{}) }
	registerCallback(t, pm, true, (*ProcessCallback)(&callback))

	// Process in root NS
	cmd := exec.Command("/bin/echo")
	require.NoError(t, cmd.Run(), "could not run process in root namespace")

	require.Eventually(t, func() bool {
		_, captured := execSet.Load(cmd.ProcessState.Pid())
		return captured
	}, time.Second, time.Millisecond*200, "did not capture process EXEC from root namespace")

	// Process in another NS
	cmdNs, err := netns.New()
	require.NoError(t, err, "could not create network namespace for process")
	defer cmdNs.Close()

	cmd = exec.Command("/bin/echo")
	require.NoError(t, kernel.WithNS(cmdNs, cmd.Run), "could not run process in other network namespace")

	require.Eventually(t, func() bool {
		_, captured := execSet.Load(cmd.ProcessState.Pid())
		return captured
	}, time.Second, 200*time.Millisecond, "did not capture process EXEC from other namespace")
}

func TestProcessMonitorRestartNetlink(t *testing.T) {
	// Making sure we get the same process monitor if we call it twice.
	pm := GetProcessMonitor()

	unsubscribe := pm.SubscribeExec(func(pid uint32) {})

	require.NoError(t, pm.Initialize())
	defer pm.Stop()

	// Make sure we can restart netlink
	require.NoError(t, pm.RestartNetLink())

	// making sure unsubscribe works and does not panic for the second unsubscription.
	unsubscribe()
	require.NotPanics(t, unsubscribe)
}

func TestProcessRestartNoDoublePid(t *testing.T) {
	execSet := sync.Map{}
	exitSet := sync.Map{}

	pm := GetProcessMonitor()

	tmpFile, err := ioutil.TempFile("", "sleep")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	err = util.CopyFile("/bin/sleep", tmpFile.Name())
	require.NoError(t, err)

	require.NoError(t, os.Chmod(tmpFile.Name(), 0500))

	require.NoError(t, pm.Initialize())
	defer pm.Stop()
	callbackExec := func(pid uint32) {
		if _, exists := execSet.Load(int(pid)); exists {
			require.Fail(t, "Same exec pid was reported twice")
		}
		execSet.Store(int(pid), struct{}{})
	}
	callbackExit := func(pid uint32) {
		if _, exists := exitSet.Load(int(pid)); exists {
			require.Fail(t, "Same exit pid was reported twice")
		}
		exitSet.Store(int(pid), struct{}{})
	}

	unsubscribeExec := pm.SubscribeExec(callbackExec)
	unsubscribeExit := pm.SubscribeExit(callbackExit)

	cmd := exec.Command(tmpFile.Name(), "10")
	require.NoError(t, cmd.Start())

	require.Eventuallyf(t, func() bool {
		_, execExists := execSet.Load(cmd.Process.Pid)
		_, exitExists := exitSet.Load(cmd.Process.Pid)
		return execExists && !exitExists
	}, time.Second, time.Millisecond*200, fmt.Sprintf("didn't capture exec and not exit"))

	require.NoError(t, pm.RestartNetLink())
	require.NoError(t, cmd.Process.Kill())
	require.Equal(t, "signal: killed", cmd.Wait().Error())

	require.Eventuallyf(t, func() bool {
		_, execExists := execSet.Load(cmd.ProcessState.Pid())
		_, exitExists := exitSet.Load(cmd.ProcessState.Pid())
		return execExists && exitExists
	}, time.Second, time.Millisecond*200, fmt.Sprintf("didn't capture exec and exit"))

	unsubscribeExit()
	unsubscribeExec()
}
