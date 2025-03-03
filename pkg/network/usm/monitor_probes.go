// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package usm

import (
	"fmt"
	"strconv"
	"sync"

	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	manager "github.com/DataDog/ebpf-manager"
	"github.com/vishvananda/netns"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/filter"
	"github.com/DataDog/datadog-agent/pkg/process/monitor"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// MonitorProbes is responsible for:
// * Starting and stopping probes when namespaces are created and removed.
type MonitorProbes struct {
	cfg *config.Config

	ebpfProgram *ebpfProgram

	netNsMonitor *NetNsMonitor

	nsProbesM sync.Mutex
	nsProbes  map[NetNs]func()
}

// NewMonitorProbes returns a new MonitorProbes instance
func NewMonitorProbes(c *config.Config, processMonitor *monitor.ProcessMonitor, mgr *ebpfProgram) (m *MonitorProbes) {
	monitorProbes := &MonitorProbes{
		cfg:         c,
		ebpfProgram: mgr,
		nsProbes:    map[NetNs]func(){},
	}

	monitorProbes.netNsMonitor = MakeNetNsMonitor(monitorProbes.cfg, processMonitor, monitorProbes.nsAddedCallback, monitorProbes.nsDroppedCallback)

	return monitorProbes
}

// Start USM monitor.
func (m *MonitorProbes) Start() error {
	m.nsProbesM.Lock()
	defer m.nsProbesM.Unlock()

	// todo!: before the `Start` the processMonitor is not initialized so we don't receive netlink events... in which scenario do we have a nsProbes not empty?
	// var noActiveNs = make(map[NetNs]bool)

	// for netNS, _ := range m.nsProbes {
	// 	noActiveNs[netNS] = true
	// }

	err := kernel.ForAllNS(m.cfg.ProcRoot, func(handle netns.NsHandle) error {
		ino, err := kernel.GetInoForNs(handle)
		if err != nil {
			return fmt.Errorf("error getting ino for handle: %w", err)
		}
		netNs := NetNs(ino)

		// delete(noActiveNs, netNs)

		if _, ok := m.nsProbes[netNs]; !ok {
			f, err := m.loadProbeForNamespace(handle, netNs)
			if err != nil {
				return fmt.Errorf("error loading probe for namespace: %w", err)
			}
			m.nsProbes[netNs] = f
		}

		return nil
	})

	// Close the namespaces that were not observed.
	// for notActive := range noActiveNs {
	// 	if f, ok := m.nsProbes[notActive]; ok {
	// 		f()
	// 		delete(m.nsProbes, notActive)
	// 	}
	// }

	return err
}

func (m *MonitorProbes) nsAddedCallback(netNs NetNs, nsHandle netns.NsHandle) {
	m.nsProbesM.Lock()
	defer m.nsProbesM.Unlock()

	if _, ok := m.nsProbes[netNs]; ok {
		// we already have a probe for this namespace
		return
	}
	f, err := m.loadProbeForNamespace(nsHandle, netNs)
	if err != nil {
		log.Errorf("Error registering network namespace: %d, %s", netNs, err)
		return
	}
	m.nsProbes[netNs] = f
	log.Debugf("Successfully registered probe for: %d", netNs)
}

func (m *MonitorProbes) nsDroppedCallback(netNs NetNs) {
	m.nsProbesM.Lock()
	defer m.nsProbesM.Unlock()

	closeFD, ok := m.nsProbes[netNs]
	if !ok {
		log.Warnf("Got drop namespace for non-existing namespace: %d", netNs)
		return
	}

	defer func() {
		// in any case we want to close the file descriptor.
		closeFD()
		delete(m.nsProbes, netNs)
	}()

	// If we have an entry in the map we should have the probe in the manager. `DetachHook` should always call `Stop` under the hood since we should have always the socket filter in the root network namespace.
	if err := m.ebpfProgram.DetachHook(manager.ProbeIdentificationPair{EBPFFuncName: protocolDispatcherSocketFilterFunction, UID: probeUID + "_" + strconv.Itoa(int(netNs))}); err != nil {
		log.Errorf("Error stopping probe for namespace: %d, %s", netNs, err)
		return
	}
	log.Debugf("Successfully unregistered probe for: %d", netNs)
}

func (m *MonitorProbes) loadProbeForNamespace(ns netns.NsHandle, netNs NetNs) (func(), error) {
	log.Debugf("Attaching probe to namespace: %d", netNs)

	// See here for an example on how clone a program: https://github.com/DataDog/ebpf-manager/blob/c4014715554a80fea3aaedd19739db3168fdf67c/examples/clone_vs_add_hook/demo.go#L9
	filterForCurrentNS := manager.Probe{
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			UID:          probeUID + "_" + strconv.Itoa(int(netNs)), // New UID for our new filter
			EBPFFuncName: protocolDispatcherSocketFilterFunction,
		},
	}

	netnsEditor := []manager.ConstantEditor{
		{
			Name:          "netns",
			Value:         uint64(netNs),
			FailOnMissing: true,
		},
	}

	closeFn, err := filter.HeadlessSocketFilterFromNamespace(&filterForCurrentNS, ns)
	if err != nil {
		return nil, fmt.Errorf("couldn't create headless socket filter: %w", err)
	}

	// As a uid we need to provide the uid of the probe we want to clone.
	if err := m.ebpfProgram.CloneProgram(probeUID, &filterForCurrentNS, netnsEditor, nil); err != nil {
		return nil, fmt.Errorf("couldn't clone %s: %w", filterForCurrentNS.ProbeIdentificationPair.UID, err)
	}

	return closeFn, nil
}

// Stop the MonitorProbes. This method should be called after the manager detaches and unloads all ebpf programs.
func (m *MonitorProbes) Stop() {
	m.netNsMonitor.Close()
	m.nsProbesM.Lock()
	defer m.nsProbesM.Unlock()
	// We just need to close the file descriptors, the manager should have already detached everything.
	for _, closeFD := range m.nsProbes {
		closeFD()
	}
	m.nsProbes = map[NetNs]func(){}
}
