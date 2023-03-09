// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package monitor

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/vishvananda/netlink"
	"go.uber.org/atomic"
	"runtime"
	"sync"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	processMonitorMaxEvents = 2048
)

var (
	once           sync.Once
	processMonitor *ProcessMonitor
)

// ProcessMonitor will subscribe to the netlink process events like Exec, Exit
// and call the subscribed callbacks
// Initialize() will scan the current process and will call the subscribed callbacks
//
// callbacks will be executed in parallel via a pool of goroutines (runtime.NumCPU())
// callbackRunner is callbacks queue. The queue size is set by processMonitorMaxEvents
//
// Multiple team can use the same ProcessMonitor,
// the callers need to guarantee calling each Initialize() Stop() one single time
// this maintain an internal reference counter
//
// ProcessMonitor require root or CAP_NET_ADMIN capabilities
type ProcessMonitor struct {
	m        sync.Mutex
	refcount atomic.Int32

	isInitialized bool

	// chan push done by vishvananda/netlink library
	events    chan netlink.ProcEvent
	done      chan struct{}
	isClosing *atomic.Bool
	wgNetLink sync.WaitGroup

	// callback registration and parallel execution management
	processExecCallbacks map[*ProcessCallback]struct{}
	processExitCallbacks map[*ProcessCallback]struct{}
	runningPids          map[uint32]struct{}
	callbackRunner       chan func()
	wgCBRunners          sync.WaitGroup
}

type ProcessCallback func(pid uint32)

// GetProcessMonitor create a monitor (only once) that register to netlink process events.
//
// This monitor can monitor.Subscribe(callback, filter) callback on particular event
// like process EXEC, EXIT. The callback will be called when the filter will match.
// Filter can be applied on :
//
//	process name (NAME)
//	by default ANY is applied
//
// Typical initialization:
//
//	mon := GetProcessMonitor()
//	mon.Subscribe(callback)
//	mon.Initialize()
//
// note: o GetProcessMonitor() will always return the same instance
//
//	  as we can only register once with netlink process event
//	o mon.Subscribe() will subscribe callback before or after the Initialization
//	o mon.Initialize() will scan current processes and call subscribed callback
//
//	o callback{Event: EXIT, Metadata: ANY}   callback is called for all exit events, system wide
//	o callback{Event: EXIT, Metadata: NAME}  callback will be called if we seen the process Exec event,
//	                                         the metadata will be saved between Exec and Exit event per pid
//	                                         then the Exit callback will evaluate the same metadata on Exit.
//	                                         We need to save the metadata here as /proc/pid doesn't exist anymore.
func GetProcessMonitor() *ProcessMonitor {
	once.Do(func() {
		processMonitor = &ProcessMonitor{
			isInitialized:        false,
			processExecCallbacks: make(map[*ProcessCallback]struct{}, 0),
			processExitCallbacks: make(map[*ProcessCallback]struct{}, 0),
			runningPids:          make(map[uint32]struct{}),
		}
	})

	return processMonitor
}

// Initialize will scan all running processes and execute matching callbacks
// Once it's done all new events from netlink socket will be processed by the main async loop
func (pm *ProcessMonitor) Initialize() error {
	pm.m.Lock()
	defer pm.m.Unlock()

	pm.refcount.Add(1)
	if pm.isInitialized {
		return nil
	}

	pm.callbackRunner = make(chan func(), runtime.NumCPU())

	for i := 0; i < runtime.NumCPU(); i++ {
		pm.wgCBRunners.Add(1)
		go func() {
			defer pm.wgCBRunners.Done()
			for call := range pm.callbackRunner {
				if call != nil {
					call()
				}
			}
		}()
	}

	err := pm.startNetlink()
	if err != nil {
		return err
	}

	// enable events to be processed
	pm.isInitialized = true
	return nil
}

func drainErrors(errors chan error, isClosing *atomic.Bool) {
	// Reads from the errors channel, logging any errors
	for err := range errors {
		if isClosing.Load() {
			log.Debugf("Process event monitor error during closing: %v", err)
		} else {
			log.Errorf("Unexpected netlink process event monitor error: %v", err)
		}
	}
}

func (pm *ProcessMonitor) RestartNetLink() error {
	pm.isClosing.Store(true)

	pm.stopNetLink()

	pm.m.Lock()
	defer pm.m.Unlock()
	return pm.startNetlink()
}

func (pm *ProcessMonitor) callExecCallbacks(pid uint32) {
	if _, exists := pm.runningPids[pid]; exists {
		return
	}

	pm.runningPids[pid] = struct{}{}

	for c, _ := range pm.processExecCallbacks {
		// Okey, here it goes: golang passes loop variables by reference to
		// closures. We need to assign to a variable first to capture
		cCaptured := *c
		pm.callbackRunner <- func() { cCaptured(pid) }
	}
}

func (pm *ProcessMonitor) callExitCallbacks(pid uint32) {
	_, exists := pm.runningPids[pid]
	if !exists {
		return
	}

	for c, _ := range pm.processExitCallbacks {
		// Okey, here it goes: golang passes loop variables by reference to
		// closures. We need to assign to a variable first to capture
		cCaptured := *c
		pm.callbackRunner <- func() { cCaptured(pid) }
	}

	delete(pm.runningPids, pid)
}

func (pm *ProcessMonitor) startNetlink() error {
	// Two channels, with different lifecycles, here it goes:

	// The event channel gets written by ProcEventMonitor and closed by ProcEventMonitor
	pm.events = make(chan netlink.ProcEvent, processMonitorMaxEvents)
	// The done channel is consumer by ProcEventMonitor and written/closed by ProcessMonitor
	pm.done = make(chan struct{})
	// Is this class doing a scheduled stop/shutdown?
	pm.isClosing = atomic.NewBool(false)

	// A separate error channel for this event monitor.
	errors := make(chan error, 10)
	go drainErrors(errors, pm.isClosing)

	err := kernel.WithRootNS(kernel.ProcFSRoot(), func() error {
		return netlink.ProcEventMonitor(pm.events, pm.done, errors)
	})

	if err != nil {
		close(errors)
		return fmt.Errorf("couldn't initialize process monitor: %s", err)
	}

	log.Infof("Starting netlink process")
	// This is the main async loop, where we process processes events from netlink socket
	// events are dropped until
	pm.wgNetLink.Add(1)
	go func() {
		defer func() {
			log.Info("netlink process monitor ended")
			pm.wgNetLink.Done()
			close(errors)
		}()
		for {
			// Okay, here it goes: We read both events and error from ProcEventMonitor. Shutdown or errors are tricky because
			// the event channel gets closed and the errors produced to in the case of shutdown or error (in both cases)
			// We wait for the event channel, reading from the error channel afterwards with some delay, to avoid missing the error message.
			event, ok := <-pm.events
			if !ok {
				log.Infof("Netlink event channel closed.")
				if pm.isClosing.Load() {
					// Scheduled shutdown, no restart
					log.Infof("Netlink event channel closed. Netlink is shutting down.")
				} else {
					log.Warnf("Netlink event channel closed unexpectedly, restarting.")
					go func() {
						errStart := pm.RestartNetLink()
						if errStart != nil {
							log.Errorf("process monitor error, unable to start netlink: %v", errStart)
						}
					}()
				}
				return
			}

			pm.m.Lock()

			switch ev := event.Msg.(type) {
			case *netlink.ExecProcEvent:
				pm.callExecCallbacks(ev.ProcessPid)
			case *netlink.ExitProcEvent:
				pm.callExitCallbacks(ev.ProcessPid)
			}
			pm.m.Unlock()
		}
	}()

	var notRunningPids = make(map[uint32]bool)

	for pid, _ := range pm.runningPids {
		notRunningPids[pid] = true
	}

	fn := func(pid int) error {
		delete(notRunningPids, uint32(pid))
		pm.callExecCallbacks(uint32(pid))
		return nil
	}

	if err := kernel.WithAllProcs(kernel.HostProc(), fn); err != nil {
		return fmt.Errorf("process monitor init, scanning all process failed %s", err)
	}

	// Remove the pids that were not observed.
	for notActive, _ := range notRunningPids {
		pm.callExitCallbacks(notActive)
	}

	return nil
}

// SubscribeExec register an exec callback and returns unsubscribe function callback that removes the callback.
//
// A callback can be registered only once, callback with a filter type (not ANY) must be registered before the matching
// Exit callback.
func (pm *ProcessMonitor) SubscribeExec(callback ProcessCallback) func() {
	pm.m.Lock()
	defer pm.m.Unlock()

	pm.processExecCallbacks[&callback] = struct{}{}

	// UnSubscribe()
	return func() {
		pm.m.Lock()
		defer pm.m.Unlock()

		delete(pm.processExecCallbacks, &callback)
	}
}

// SubscribeExit register an exit callback and returns unsubscribe function callback that removes the callback.
func (pm *ProcessMonitor) SubscribeExit(callback ProcessCallback) func() {
	pm.m.Lock()
	defer pm.m.Unlock()

	pm.processExitCallbacks[&callback] = struct{}{}

	// UnSubscribe()
	return func() {
		pm.m.Lock()
		defer pm.m.Unlock()

		delete(pm.processExitCallbacks, &callback)
	}
}

func (pm *ProcessMonitor) stopNetLink() {
	close(pm.done)
	pm.wgNetLink.Wait()
}

func (pm *ProcessMonitor) Stop() {
	pm.m.Lock()
	if pm.refcount.Load() == 0 {
		pm.m.Unlock()
		return
	}

	pm.refcount.Add(-1)
	if pm.refcount.Load() > 0 {
		pm.m.Unlock()
		return
	}

	pm.isInitialized = false
	pm.m.Unlock()

	pm.isClosing.Store(true)

	pm.stopNetLink()

	close(pm.callbackRunner)
	pm.wgCBRunners.Wait()
}

// FindDeletedProcesses returns the terminated PIDs from the given map.
func FindDeletedProcesses[V any](pids map[uint32]V) map[uint32]struct{} {
	existingPids := make(map[uint32]struct{}, len(pids))

	procIter := func(pid int) error {
		if _, exists := pids[uint32(pid)]; exists {
			existingPids[uint32(pid)] = struct{}{}
		}
		return nil
	}
	// Scanning already running processes
	if err := kernel.WithAllProcs(kernel.ProcFSRoot(), procIter); err != nil {
		return nil
	}

	res := make(map[uint32]struct{}, len(pids)-len(existingPids))
	for pid := range pids {
		if _, exists := existingPids[pid]; exists {
			continue
		}
		res[pid] = struct{}{}
	}

	return res
}
