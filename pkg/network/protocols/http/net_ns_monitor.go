// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package http

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/process/monitor"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/vishvananda/netns"
	"sync"
)

const (
	nsMonitorMaxEvents = 2048
)

type NetNs uint32

// NetNsMonitor will subscribe to a processMonitor to track changes to net namespaces being created/destroyed.
//
// In theory a process may switch between namespaces, however since we are only interested in all active namespaces for containers
// here, going with the initial namespace of a process should be fine, since containers do not change namespace.
//
// Looking at tools like lsns and the like, it seems going through the processes to find all network namespaces seems the preferred option.
type NetNsMonitor struct {
	m sync.Mutex

	// callback registration and parallel execution management
	config          *config.Config
	addNsCallback   AddNsCallback
	dropNsCallback  DropNsCallback
	pidToNs         map[pid]NetNs
	pidsForNs       map[NetNs]map[pid]bool
	UnSubscribeExit func()
	UnSubscribeExec func()

	// We run callbacks async, to avoid blocking upstream events.
	callbackRunner chan func()
	done           sync.WaitGroup
}

type AddNsCallback func(netNs NetNs, handle netns.NsHandle)
type DropNsCallback func(netNs NetNs)

// MakeNetNsMonitor create a monitor for network namespaces, registering to a processmonitor.
// Make sure to subscribe to the process monitor befor Initialize() is called, to make
// sure all pids are reported and processed.
func MakeNetNsMonitor(c *config.Config, mon *monitor.ProcessMonitor, addCallback AddNsCallback, dropCallback DropNsCallback) (*NetNsMonitor, error) {
	var err error

	m := &NetNsMonitor{
		config:         c,
		addNsCallback:  addCallback,
		dropNsCallback: dropCallback,
		pidToNs:        map[pid]NetNs{},
		pidsForNs:      map[NetNs]map[pid]bool{},
	}

	// Running callbacks
	m.callbackRunner = make(chan func(), nsMonitorMaxEvents)
	m.done.Add(1)
	go func() {
		defer m.done.Done()
		for call := range m.callbackRunner {
			if call != nil {
				call()
			} else {
				return
			}
		}
	}()

	m.UnSubscribeExit, err = mon.Subscribe(&monitor.ProcessCallback{
		Event:    monitor.EXIT,
		Metadata: monitor.ANY,
		Callback: m.callbackExit,
	})

	if err != nil {
		return nil, fmt.Errorf("error registering callback: %w", err)
	}

	m.UnSubscribeExec, err = mon.Subscribe(&monitor.ProcessCallback{
		Event:    monitor.EXEC,
		Metadata: monitor.ANY,
		Callback: m.callbackExec,
	})

	if err != nil {
		m.UnSubscribeExit()
		return nil, fmt.Errorf("error registering callback: %w", err)
	}

	return m, nil
}

func (n *NetNsMonitor) callbackExit(p pid) {
	n.m.Lock()
	defer n.m.Unlock()

	var netNs NetNs
	netNs, ok := n.pidToNs[p]
	if !ok {
		log.Debugf("Got exit for unknown pid: %d", p)
		return
	}

	var pids map[pid]bool
	pids, ok = n.pidsForNs[netNs]
	if !ok {
		log.Errorf("Could not find network namespace: %d", netNs)
	}

	delete(pids, p)
	delete(n.pidToNs, p)

	if len(pids) == 0 {
		n.callbackRunner <- func() {
			n.dropNsCallback(netNs)
		}
		delete(n.pidsForNs, netNs)
	}
}

func (n *NetNsMonitor) callbackExec(p pid) {
	n.m.Lock()
	defer n.m.Unlock()

	nsHandle, err := util.GetNetNamespaceFromPid(n.config.ProcRoot, int(p))
	if err != nil || nsHandle.Equal(netns.None()) {
		log.Debugf("Could not find namespace handle for: %d: %w", p, err)
		return
	}

	ino, err := util.GetInoForNs(nsHandle)
	if err != nil || ino == 0 {
		log.Debugf("Could not find net ns for: %d: %w", p, err)
		nsHandle.Close()
		return
	}

	netNs := NetNs(ino)

	if existing, ok := n.pidsForNs[netNs]; ok {
		existing[p] = true

		err = nsHandle.Close()

		if err != nil {
			log.Warnf("Error closing namespace handle: %d, %w. Possible resource leak.", netNs, nsHandle)
		}
	} else {
		n.pidsForNs[netNs] = map[pid]bool{p: true}

		// Scheduling a callback, transferring ownership of nsHandle
		n.callbackRunner <- func() {
			n.addNsCallback(netNs, nsHandle)
			err = nsHandle.Close()

			if err != nil {
				log.Warnf("Error closing namespace handle: %d, %w. Possible resource leak.", netNs, nsHandle)
			}
		}
	}

	n.pidToNs[p] = netNs
}

func (n *NetNsMonitor) Close() {
	n.m.Lock()
	n.UnSubscribeExit()
	n.UnSubscribeExec()
	n.m.Unlock()

	close(n.callbackRunner)
	n.done.Wait()
}
