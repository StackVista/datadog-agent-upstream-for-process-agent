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
	"github.com/stretchr/testify/suite"
	"github.com/vishvananda/netns"
	"go.uber.org/atomic"

	"github.com/DataDog/datadog-agent/pkg/eventmonitor/consumers/testutil"
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

func waitForProcessMonitor(t *testing.T, pm *ProcessMonitor) {
	execCounter := atomic.NewInt32(0)
	execCallback := func(_ uint32) { execCounter.Inc() }
	registerCallback(t, pm, true, &execCallback)

	exitCounter := atomic.NewInt32(0)
	// Sanity subscribing a callback.
	exitCallback := func(_ uint32) { exitCounter.Inc() }
	registerCallback(t, pm, false, &exitCallback)

	require.Eventually(t, func() bool {
		_ = exec.Command("/bin/echo").Run()
		return execCounter.Load() > 0 && exitCounter.Load() > 0
	}, 10*time.Second, time.Millisecond*200)
}

// todo!: do we need to remove this? we deleted in the previous sync
func initializePM(t *testing.T, pm *ProcessMonitor, useEventStream bool) {
	require.NoError(t, pm.Initialize(useEventStream))
	if useEventStream {
		InitializeEventConsumer(testutil.NewTestProcessConsumer(t))
	}
	waitForProcessMonitor(t, pm)
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

type processMonitorSuite struct {
	suite.Suite
	useEventStream bool
}

// todo!: check if we need to apply patch to this one.
func (s *processMonitorSuite) TestProcessMonitorSanity() {
	t := s.T()
	pm := getProcessMonitor(t)
	execsMutex := sync.RWMutex{}
	execs := make(map[uint32]struct{})
	testBinaryPath := getTestBinaryPath(t)
	callback := func(pid uint32) {
		execsMutex.Lock()
		defer execsMutex.Unlock()
		execs[pid] = struct{}{}
	}
	registerCallback(t, pm, true, &callback)

	exitMutex := sync.RWMutex{}
	exits := make(map[uint32]struct{})
	exitCallback := func(pid uint32) {
		exitMutex.Lock()
		defer exitMutex.Unlock()
		exits[pid] = struct{}{}
	}
	registerCallback(t, pm, false, &exitCallback)

	initializePM(t, pm, s.useEventStream)
	cmd := exec.Command(testBinaryPath, "test")
	require.NoError(t, cmd.Run())
	require.Eventually(t, func() bool {
		execsMutex.RLock()
		_, execCaptured := execs[uint32(cmd.Process.Pid)]
		execsMutex.RUnlock()
		if !execCaptured {
			t.Logf("didn't capture exec event %d", cmd.Process.Pid)
		}

		exitMutex.RLock()
		_, exitCaptured := exits[uint32(cmd.Process.Pid)]
		exitMutex.RUnlock()
		if !exitCaptured {
			t.Logf("didn't capture exit event %d", cmd.Process.Pid)
		}
		return execCaptured && exitCaptured
	}, time.Second, time.Millisecond*200)
}

func mkCallback(t *testing.T, c *atomic.Bool, index int) *ProcessCallback {
	f := func(pid uint32) {
		t.Logf("Storing %d for %d", pid, index)
		c.Store(true)
	}
	return (*ProcessCallback)(&f)
}

func TestProcessMonitor(t *testing.T) {
	t.Run("netlink", func(t *testing.T) {
		suite.Run(t, &processMonitorSuite{useEventStream: false})
	})
	t.Run("event stream", func(t *testing.T) {
		suite.Run(t, &processMonitorSuite{useEventStream: true})
	})
}

func (s *processMonitorSuite) TestProcessRegisterMultipleCallbacks() {
	t := s.T()
	pm := getProcessMonitor(t)

	const iterations = 10
	execCountersMutexes := make([]sync.RWMutex, iterations)
	execCounters := make([]map[uint32]struct{}, iterations)
	exitCountersMutexes := make([]sync.RWMutex, iterations)
	exitCounters := make([]map[uint32]struct{}, iterations)
	for i := 0; i < iterations; i++ {
		execCountersMutexes[i] = sync.RWMutex{}
		execCounters[i] = make(map[uint32]struct{})
		c := execCounters[i]
		// Sanity subscribing a callback.
		callback := func(pid uint32) {
			execCountersMutexes[i].Lock()
			defer execCountersMutexes[i].Unlock()
			c[pid] = struct{}{}
		}
		registerCallback(t, pm, true, &callback)

		exitCountersMutexes[i] = sync.RWMutex{}
		exitCounters[i] = make(map[uint32]struct{})
		exitc := exitCounters[i]
		// Sanity subscribing a callback.
		exitCallback := func(pid uint32) {
			exitCountersMutexes[i].Lock()
			defer exitCountersMutexes[i].Unlock()
			exitc[pid] = struct{}{}
		}
		registerCallback(t, pm, false, &exitCallback)
	}

	// todo!: check it
	// initializePM(t, pm, s.useEventStream)
	cmd := exec.Command("/bin/sleep", "1")
	require.NoError(t, cmd.Run())
	require.Eventuallyf(t, func() bool {
		// Instead of breaking immediately when we don't find the event, we want logs to be printed for all iterations.
		found := true
		for i := 0; i < iterations; i++ {
			execCountersMutexes[i].RLock()
			if _, captured := execCounters[i][uint32(cmd.Process.Pid)]; !captured {
				t.Logf("iter %d didn't capture exec event", i)
				found = false
			}
			execCountersMutexes[i].RUnlock()

			exitCountersMutexes[i].RLock()
			if _, captured := exitCounters[i][uint32(cmd.Process.Pid)]; !captured {
				t.Logf("iter %d didn't capture exit event", i)
				found = false
			}
			exitCountersMutexes[i].RUnlock()
		}
		return found
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

// todo!: double check this test
func (s *processMonitorSuite) TestProcessMonitorInNamespace() {
	t := s.T()
	execSet := sync.Map{}
	exitSet := sync.Map{}

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
	cmd := exec.Command("/bin/sleep", "1")
	require.NoError(t, cmd.Run(), "could not run process in root namespace")
	pid := uint32(cmd.ProcessState.Pid())

	require.Eventually(t, func() bool {
		_, capturedExec := execSet.Load(pid)
		if !capturedExec {
			t.Logf("pid %d not captured in exec", pid)
		}
		_, capturedExit := exitSet.Load(pid)
		if !capturedExit {
			t.Logf("pid %d not captured in exit", pid)
		}
		return capturedExec && capturedExit
	}, time.Second, time.Millisecond*200, "did not capture process EXEC/EXIT from root namespace")

	// Process in another NS
	cmdNs, err := netns.New()
	require.NoError(t, err, "could not create network namespace for process")
	defer cmdNs.Close()

	cmd = exec.Command("/bin/sleep", "1")
	require.NoError(t, kernel.WithNS(cmdNs, cmd.Run), "could not run process in other network namespace")
	pid = uint32(cmd.ProcessState.Pid())

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
