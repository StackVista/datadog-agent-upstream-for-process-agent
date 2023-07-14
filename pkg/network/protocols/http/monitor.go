// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package http

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/vishvananda/netns"
	"strconv"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"

	manager "github.com/DataDog/ebpf-manager"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	filterpkg "github.com/DataDog/datadog-agent/pkg/network/filter"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/events"
	errtelemetry "github.com/DataDog/datadog-agent/pkg/network/telemetry"
	"github.com/DataDog/datadog-agent/pkg/process/monitor"
)

// Monitor is responsible for:
// * Creating a raw socket and attaching an eBPF filter to it;
// * Consuming HTTP transaction "events" that are sent from Kernel space;
// * Aggregating and emitting metrics based on the received HTTP transactions;
type Monitor struct {
	consumer       *events.Consumer
	ebpfProgram    *ebpfProgram
	telemetry      *telemetry
	statkeeper     *httpStatKeeper
	processMonitor *monitor.ProcessMonitor
	netNsMonitor   *NetNsMonitor
	config         *config.Config

	nsProbesM sync.Mutex
	nsProbes  map[NetNs]*NsProbe
}

type NsProbe struct {
	ebpfProgram *ebpfProgram
	probe       *manager.Probe
	packetSrc   *filterpkg.AFPacketSource
}

func (n *NsProbe) Close() {
	program := n.probe.Program()
	err := n.ebpfProgram.DetachHook(n.probe.ProbeIdentificationPair)
	if err != nil {
		log.Errorf("Error detaching hook %v : %s", n.probe.ProbeIdentificationPair, err)
	}
	if program != nil {
		err = program.Close()
		if err != nil {
			log.Errorf("Error closing program %v : %s", n.probe.ProbeIdentificationPair, err)
		}
	}

	n.packetSrc.Close()
}

// NewMonitor returns a new Monitor instance
func NewMonitor(c *config.Config, offsets []manager.ConstantEditor, sockFD *ebpf.Map, bpfTelemetry *errtelemetry.EBPFTelemetry) (*Monitor, error) {
	mgr, err := newEBPFProgram(c, offsets, sockFD, bpfTelemetry)
	if err != nil {
		return nil, fmt.Errorf("error setting up http ebpf program: %w", err)
	}

	if err := mgr.Init(); err != nil {
		return nil, fmt.Errorf("error initializing http ebpf program: %w", err)
	}

	telemetry, err := newTelemetry()
	if err != nil {
		return nil, err
	}

	statkeeper := newHTTPStatkeeper(c, telemetry)
	processMonitor := monitor.GetProcessMonitor()

	m := &Monitor{
		ebpfProgram:    mgr,
		telemetry:      telemetry,
		statkeeper:     statkeeper,
		processMonitor: processMonitor,
		config:         c,
		nsProbes:       map[NetNs]*NsProbe{},
	}

	m.netNsMonitor, err = MakeNetNsMonitor(m.config, m.processMonitor, m.nsAddedCallback, m.nsDroppedCallback)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// Start consuming HTTP events
func (m *Monitor) Start() error {
	if m == nil {
		return nil
	}

	var err error
	m.consumer, err = events.NewConsumer(
		"http",
		m.ebpfProgram.Manager.Manager,
		m.process,
	)
	if err != nil {
		return err
	}
	m.consumer.Start()

	if err := m.ebpfProgram.Start(); err != nil {
		m.consumer.Stop()
		return err
	}

	// Starting with updateAllNsProbes.
	// We run this synchronously here instead of waiting for the NsNetMonitor to be sure all probes are started after this function
	// returns
	err = m.updateAllNsProbes()

	if err != nil {
		m.consumer.Stop()
		m.ebpfProgram.Close()
		return err
	}

	return m.processMonitor.Initialize()
}

// GetHTTPStats returns a map of HTTP stats stored in the following format:
// [source, dest tuple, request path] -> RequestStats object
func (m *Monitor) GetHTTPStats() (map[Key]*RequestStats, []TransactionObservation) {
	if m == nil {
		return nil, nil
	}

	m.consumer.Sync()
	m.telemetry.log()
	return m.statkeeper.GetAndResetAllStats()
}

/** Update the active namespaces in one go. Only used for initialization. */
func (m *Monitor) updateAllNsProbes() error {
	m.nsProbesM.Lock()
	defer m.nsProbesM.Unlock()

	var noActiveNs map[NetNs]bool = make(map[NetNs]bool)

	for netNS, _ := range m.nsProbes {
		noActiveNs[netNS] = true
	}

	err := util.ForAllNS(m.config.ProcRoot, func(handle netns.NsHandle) error {
		ino, err := util.GetInoForNs(handle)
		if err != nil {
			return err
		}
		netNs := NetNs(ino)

		delete(noActiveNs, netNs)

		if _, ok := m.nsProbes[netNs]; !ok {
			nsM, err := m.loadProbeForNamespace(handle, netNs)
			if err != nil {
				return err
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

func (m *Monitor) nsAddedCallback(netNs NetNs, nsHandle netns.NsHandle) {
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

func (m *Monitor) nsDroppedCallback(netNs NetNs) {
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

func (m *Monitor) loadProbeForNamespace(ns netns.NsHandle, netNs NetNs) (*NsProbe, error) {
	log.Debugf("Attaching probe to namespace: %d", netNs)

	probeTemplate, _ := m.ebpfProgram.GetProbe(manager.ProbeIdentificationPair{EBPFSection: protocolDispatcherSocketFilterSection, EBPFFuncName: protocolDispatcherSocketFilterFunction, UID: probeUID})
	if probeTemplate == nil {
		return nil, fmt.Errorf("error retrieving socket filter")
	}

	newProbe := probeTemplate.Copy()
	newProbe.CopyProgram = true
	newProbe.UID = probeUID + "_" + strconv.Itoa(int(netNs))
	newProbe.KeepProgramSpec = false

	var packetSrc *filterpkg.AFPacketSource

	err := util.WithNS(ns, func() error {
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
func (m *Monitor) Stop() {
	if m == nil {
		return
	}

	m.processMonitor.Stop()
	m.netNsMonitor.Close()

	m.nsProbesM.Lock()
	defer m.nsProbesM.Unlock()
	for _, n := range m.nsProbes {
		n.Close()
	}
	m.ebpfProgram.Close()
	m.consumer.Stop()
}

func (m *Monitor) process(data []byte) {
	tx := (*ebpfHttpTx)(unsafe.Pointer(&data[0]))
	m.telemetry.count(tx)
	m.statkeeper.Process(tx)
}

// DumpMaps dumps the maps associated with the monitor
func (m *Monitor) DumpMaps(maps ...string) (string, error) {
	return m.ebpfProgram.DumpMaps(maps...)
}
