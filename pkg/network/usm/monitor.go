// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package usm

import (
	"errors"
	"fmt"
	"io"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/atomic"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/ebpf/probe/ebpfcheck"
	ebpftelemetry "github.com/DataDog/datadog-agent/pkg/ebpf/telemetry"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/protocols"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/telemetry"
	"github.com/DataDog/datadog-agent/pkg/process/monitor"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type monitorState = string

const (
	disabled   monitorState = "disabled"
	running    monitorState = "running"
	notRunning monitorState = "Not running"
)

var (
	state        = disabled
	startupError error
)

// Monitor is responsible for:
// * Creating a raw socket and attaching an eBPF filter to it;
// * Consuming HTTP transaction "events" that are sent from Kernel space;
// * Aggregating and emitting metrics based on the received HTTP transactions;
type Monitor struct {
	cfg *config.Config

	ebpfProgram *ebpfProgram

	processMonitor *monitor.ProcessMonitor

	probes *MonitorProbes

	lastUpdateTime *atomic.Int64
}

// NewMonitor returns a new Monitor instance
func NewMonitor(c *config.Config, connectionProtocolMap *ebpf.Map, bpfTelemetry *ebpftelemetry.EBPFTelemetry) (m *Monitor, err error) {
	defer func() {
		// capture error and wrap it
		if err != nil {
			state = notRunning
			err = fmt.Errorf("could not initialize USM: %w", err)
			startupError = err
		}
	}()

	mgr, err := newEBPFProgram(c, connectionProtocolMap, bpfTelemetry)
	if err != nil {
		return nil, fmt.Errorf("error setting up ebpf program: %w", err)
	}

	if len(mgr.enabledProtocols) == 0 {
		state = disabled
		log.Debug("not enabling USM as no protocols monitoring were enabled.")
		return nil, nil
	}

	if err := mgr.Init(); err != nil {
		return nil, fmt.Errorf("error initializing ebpf program: %w", err)
	}

	ebpfcheck.AddNameMappings(mgr.Manager.Manager, "usm_monitor")

	processMonitor := monitor.GetProcessMonitor()

	probes := NewMonitorProbes(c, processMonitor, mgr)

	state = Running

	usmMonitor := &Monitor{
		cfg:              c,
		enabledProtocols: enabledProtocols,
		ebpfProgram:      mgr,
		processMonitor:   processMonitor,
		probes:           probes,
	}

	usmMonitor.lastUpdateTime = atomic.NewInt64(time.Now().Unix())

	return usmMonitor, nil
}

// Start USM monitor.
func (m *Monitor) Start() error {
	if m == nil {
		return nil
	}

	var err error

	defer func() {
		if err != nil {
			if errors.Is(err, syscall.ENOMEM) {
				err = fmt.Errorf("could not enable usm monitoring: not enough memory to attach http ebpf socket filter. please consider raising the limit via sysctl -w net.core.optmem_max=<LIMIT>")
			} else {
				err = fmt.Errorf("could not enable USM: %s", err)
			}

			m.Stop()

			startupError = err
		}
	}()

	err = m.ebpfProgram.Start()
	if err != nil {
		return fmt.Errorf("error starting ebpf program for usm: %w", err)
	}

	enabledProtocolsTmp = m.enabledProtocols[:0]
	for _, protocol := range m.enabledProtocols {
		startErr := protocol.PostStart(m.ebpfProgram.Manager.Manager)
		if startErr != nil {
			// Cleanup the protocol. Note that at this point we can't unload the
			// ebpf programs of a specific protocol without shutting down the
			// entire manager.
			protocol.Stop(m.ebpfProgram.Manager.Manager)

			// Log and reset the error value
			log.Errorf("could not complete post-start phase of %s monitoring: %s", protocol.Name(), startErr)
			continue
		}
		enabledProtocolsTmp = append(enabledProtocolsTmp, protocol)
	}
	m.enabledProtocols = enabledProtocolsTmp

	// We check again if there are protocols that could be enabled, and abort if
	// it is not the case.
	if len(m.enabledProtocols) == 0 {
		err = m.ebpfProgram.Close()
		if err != nil {
			log.Errorf("error during USM shutdown: %s", err)
		}

		return errNoProtocols
	}

	// Starting with updateAllNsProbes.
	// We run this synchronously here instead of waiting for the NsNetMonitor to be sure all probes are started after this function
	// returns
	err = m.probes.Start()

	if err != nil {
		for _, protocol := range m.enabledProtocols {
			protocol.Stop(m.ebpfProgram.Manager.Manager)
		}

		m.ebpfProgram.Close()
		return err
	}

	// Need to explicitly save the error in `err` so the defer function could save the startup error.
	if m.cfg.EnableNativeTLSMonitoring || m.cfg.EnableGoTLSSupport || m.cfg.EnableJavaTLSSupport || m.cfg.EnableIstioMonitoring {
		err = m.processMonitor.Initialize()
	}

	for _, protocolName := range m.enabledProtocols {
		log.Infof("enabled USM protocol: %s", protocolName.Name())
	}

	// TODO: check whether we should close the probes and program here.
	return err
}

// GetUSMStats returns the current state of the USM monitor
func (m *Monitor) GetUSMStats() map[string]interface{} {
	response := map[string]interface{}{
		"state": state,
	}

	if startupError != nil {
		response["error"] = startupError.Error()
	}

	if m != nil {
		response["last_check"] = m.lastUpdateTime
	}
	return response
}

// GetProtocolStats returns the current stats for all protocols
func (m *Monitor) GetProtocolStats() map[protocols.ProtocolType]interface{} {
	if m == nil {
		return nil
	}

	defer func() {
		// Update update time
		now := time.Now().Unix()
		m.lastUpdateTime.Swap(now)
		telemetry.ReportPrometheus()
	}()

	return m.ebpfProgram.getProtocolStats()
}

// Stop HTTP monitoring
func (m *Monitor) Stop() {
	if m == nil {
		return
	}

	m.processMonitor.Stop()
	m.probes.Stop()

	ebpfcheck.RemoveNameMappings(m.ebpfProgram.Manager.Manager)

	for _, protocol := range m.enabledProtocols {
		protocol.Stop(m.ebpfProgram.Manager.Manager)
	}

	m.ebpfProgram.Close()
}

// DumpMaps dumps the maps associated with the monitor
func (m *Monitor) DumpMaps(w io.Writer, maps ...string) error {
	return m.ebpfProgram.DumpMaps(w, maps...)
}
