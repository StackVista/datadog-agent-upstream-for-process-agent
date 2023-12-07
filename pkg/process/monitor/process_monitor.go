// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package monitor

import (
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/process/util"
	"go.uber.org/atomic"

	"github.com/DataDog/gopsutil/process"
	"github.com/vishvananda/netlink"

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
	refcount int

	isInitialized bool

	// chan push done by vishvananda/netlink library
	events    chan netlink.ProcEvent
	done      chan struct{}
	isClosing *atomic.Bool
	wgNetLink sync.WaitGroup

	// callback registration and parallel execution management
	procEventCallbacks map[ProcessEventType][]*ProcessCallback
	runningPids        map[uint32]metadataName
	callbackRunner     chan func()
	wgCBRunners        sync.WaitGroup
}

type ProcessEventType int

const (
	EXEC ProcessEventType = iota
	EXIT
)

type ProcessMetadataField int

const (
	ANY ProcessMetadataField = iota
	NAME
)

type metadataName struct {
	Name string
}

type ProcessCallback struct {
	Event    ProcessEventType
	Metadata ProcessMetadataField
	Regex    *regexp.Regexp
	Callback func(pid uint32)
}

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
			isInitialized:      false,
			procEventCallbacks: make(map[ProcessEventType][]*ProcessCallback),
			runningPids:        make(map[uint32]metadataName),
		}
	})

	return processMonitor
}

// enqueueMatchingCallback is a best effort and would not return errors, but report them
func (p *ProcessMonitor) enqueueMatchingCallback(c *ProcessCallback, pid uint32, name metadataName) {
	if c.Metadata != NAME || c.Regex.MatchString(name.Name) {
		p.callbackRunner <- func() { c.Callback(pid) }
	}
}

// Initialize will scan all running processes and execute matching callbacks
// Once it's done all new events from netlink socket will be processed by the main async loop
func (pm *ProcessMonitor) Initialize() error {
	pm.m.Lock()
	defer pm.m.Unlock()

	pm.refcount++
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

func drainErrors(errors chan error) {
	// Reads from the errors channel, logging any errors
	for err := range errors {
		log.Errorf("Netlink process event monitor error: %v", err)
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

	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		// We receive the Exec event first and /proc could be slow to update
		end := time.Now().Add(10 * time.Millisecond)
		for end.After(time.Now()) {
			proc, err = process.NewProcess(int32(pid))
			if err == nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
	}
	if err != nil {
		// short living process can hit here (or later proc.Name() parsing)
		// as they already exited when we try to find them in /proc
		// so let's be quiet on the logs as there not much to do here
		return
	}

	pname, err := proc.Name()
	if err != nil {
		log.Debugf("process %d name parsing failed %s", pid, err)
		return
	}
	metadata := metadataName{Name: pname}
	pm.runningPids[pid] = metadata

	for _, c := range pm.procEventCallbacks[EXEC] {
		pm.enqueueMatchingCallback(c, pid, metadata)
	}
}

func (pm *ProcessMonitor) callExitCallbacks(pid uint32) {
	metadata, exists := pm.runningPids[pid]
	if !exists {
		return
	}

	for _, c := range pm.procEventCallbacks[EXIT] {
		pm.enqueueMatchingCallback(c, pid, metadata)
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
	go drainErrors(errors)

	err := util.WithRootNS(util.GetProcRoot(), func() error {
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

	if err := util.WithAllProcs(util.HostProc(), fn); err != nil {
		return fmt.Errorf("process monitor init, scanning all process failed %s", err)
	}

	// Remove the pids that were not observed.
	for notActive, _ := range notRunningPids {
		pm.callExitCallbacks(notActive)
	}

	return nil
}

// Subscribe register a callback and store it pm.procEventCallbacks[callback.Event] list
// this list is maintained out of order, and the return UnSubscribe function callback
// will remove the previously registered callback from the list
//
// By design : 1/ a callback object can be registered only once
//
//	2/ Exec callback with a Metadata (!=ANY) must be registred before the sibling Exit metadata,
//	   otherwise the Subscribe() will return an error as no metadata will be saved between Exec and Exit,
//	   please refer to GetProcessMonitor()
func (pm *ProcessMonitor) Subscribe(callback *ProcessCallback) (UnSubscribe func(), err error) {
	pm.m.Lock()
	defer pm.m.Unlock()

	for _, c := range pm.procEventCallbacks[callback.Event] {
		if c == callback {
			return nil, errors.New("same callback can't be registred twice")
		}
	}

	// check if the sibling Exec callback exist
	if callback.Event == EXIT && callback.Metadata != ANY {
		foundSibling := false
		for _, c := range pm.procEventCallbacks[EXEC] {
			if c.Metadata == callback.Metadata && c.Regex.String() == callback.Regex.String() {
				foundSibling = true
				break
			}
		}
		if !foundSibling {
			return nil, errors.New("no Exec callback has been found with the same Metadata and Regex, please Subscribe(Exec callback, Metadata) first")
		}
	}

	pm.procEventCallbacks[callback.Event] = append(pm.procEventCallbacks[callback.Event], callback)

	// UnSubscribe()
	return func() {
		pm.m.Lock()
		defer pm.m.Unlock()

		// we are scanning all callbacks remove the one we registered
		// and remove it from the pm.procEventCallbacks[callback.Event] list
		for i, c := range pm.procEventCallbacks[callback.Event] {
			if c == callback {
				l := len(pm.procEventCallbacks[callback.Event])
				pm.procEventCallbacks[callback.Event][i] = pm.procEventCallbacks[callback.Event][l-1]
				pm.procEventCallbacks[callback.Event] = pm.procEventCallbacks[callback.Event][:l-1]
				return
			}
		}
	}, nil
}

func (pm *ProcessMonitor) stopNetLink() {
	close(pm.done)
	pm.wgNetLink.Wait()
}

func (pm *ProcessMonitor) Stop() {
	pm.m.Lock()
	if pm.refcount == 0 {
		pm.m.Unlock()
		return
	}

	pm.refcount--
	if pm.refcount > 0 {
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
