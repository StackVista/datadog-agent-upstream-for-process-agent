// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package usm

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	manager "github.com/DataDog/ebpf-manager"
	"github.com/vishvananda/netns"
	"strconv"
	"sync"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	filterpkg "github.com/DataDog/datadog-agent/pkg/network/filter"
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
	nsProbes  map[NetNs]*NsProbe
}

// NewMonitorProbes returns a new MonitorProbes instance
func NewMonitorProbes(c *config.Config, processMonitor *monitor.ProcessMonitor, mgr *ebpfProgram) (m *MonitorProbes) {
	monitorProbes := &MonitorProbes{
		cfg:         c,
		ebpfProgram: mgr,
		nsProbes:    map[NetNs]*NsProbe{},
	}

	monitorProbes.netNsMonitor = MakeNetNsMonitor(monitorProbes.cfg, processMonitor, monitorProbes.nsAddedCallback, monitorProbes.nsDroppedCallback)

	return monitorProbes
}

// Start USM monitor.
func (m *MonitorProbes) Start() error {

	return m.updateAllNsProbes()
}

/** Update the active namespaces in one go. Only used for initialization. */
func (m *MonitorProbes) updateAllNsProbes() error {
	m.nsProbesM.Lock()
	defer m.nsProbesM.Unlock()

	var noActiveNs = make(map[NetNs]bool)

	for netNS, _ := range m.nsProbes {
		noActiveNs[netNS] = true
	}

	err := kernel.ForAllNS(m.cfg.ProcRoot, func(handle netns.NsHandle) error {
		ino, err := kernel.GetInoForNs(handle)
		if err != nil {
			return fmt.Errorf("error getting ino for handle: %w", err)
		}
		netNs := NetNs(ino)

		delete(noActiveNs, netNs)

		if _, ok := m.nsProbes[netNs]; !ok {
			nsM, err := m.loadProbeForNamespace(handle, netNs)
			if err != nil {
				return fmt.Errorf("error loading probe for namespace: %w", err)
			}
			m.nsProbes[netNs] = nsM
		}

		return nil
	})

	// Close the namespaces that were not observed.
	for notActive, _ := range noActiveNs {
		if probe, ok := m.nsProbes[notActive]; ok {
			probe.Close()
			delete(m.nsProbes, notActive)
		}
	}

	return err
}

func (m *MonitorProbes) nsAddedCallback(netNs NetNs, nsHandle netns.NsHandle) {
	m.nsProbesM.Lock()
	defer m.nsProbesM.Unlock()

	if _, ok := m.nsProbes[netNs]; !ok {
		nsM, err := m.loadProbeForNamespace(nsHandle, netNs)
		if err != nil {
			log.Errorf("Error registering network namespace: %d, %w", netNs, err)
			return
		}
		m.nsProbes[netNs] = nsM
		log.Debugf("Successfully registered probe for: %d", netNs)
	}
}

func (m *MonitorProbes) nsDroppedCallback(netNs NetNs) {
	m.nsProbesM.Lock()
	defer m.nsProbesM.Unlock()

	if nsProbe, ok := m.nsProbes[netNs]; ok {
		log.Debugf("Successfully unregistered probe for: %d", netNs)
		nsProbe.Close()
		delete(m.nsProbes, netNs)
	} else {
		log.Errorf("Got drop namespace for non-existing namespace: %d", netNs)
	}
}

func (m *MonitorProbes) loadProbeForNamespace(ns netns.NsHandle, netNs NetNs) (*NsProbe, error) {
	log.Debugf("Attaching probe to namespace: %d", netNs)

	probeTemplate, _ := m.ebpfProgram.GetProbe(manager.ProbeIdentificationPair{EBPFFuncName: protocolDispatcherSocketFilterFunction, UID: probeUID})
	if probeTemplate == nil {
		return nil, fmt.Errorf("error retrieving socket filter")
	}

	newProbe := probeTemplate.Copy()
	newProbe.CopyProgram = true
	newProbe.UID = probeUID + "_" + strconv.Itoa(int(netNs))
	newProbe.KeepProgramSpec = false

	var packetSrc *filterpkg.AFPacketSource

	err := kernel.WithNS(ns, func() error {
		var srcErr error
		packetSrc, srcErr = filterpkg.NewPacketSource(newProbe, nil)
		return srcErr
	})

	if err != nil {
		return nil, err
	}

	netnsEditor := []manager.ConstantEditor{
		{
			Name:          "netns",
			Value:         uint64(netNs),
			FailOnMissing: true,
		},
	}

	if err := m.ebpfProgram.CloneProgram(probeUID, newProbe, netnsEditor, nil); err != nil {
		if packetSrc != nil {
			packetSrc.Close()
		}
		return nil, fmt.Errorf("couldn't clone %s: %w", probeUID, err)
	}

	return &NsProbe{
		probe:       newProbe,
		packetSrc:   packetSrc,
		ebpfProgram: m.ebpfProgram,
	}, nil
}

// Stop HTTP monitoring
func (m *MonitorProbes) Stop() {
	m.netNsMonitor.Close()

	m.nsProbesM.Lock()
	defer m.nsProbesM.Unlock()
	for _, n := range m.nsProbes {
		n.Close()
	}
}
