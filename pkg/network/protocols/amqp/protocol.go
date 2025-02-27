// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package amqp

import (
	"io"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/protocols"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/events"
	"github.com/DataDog/datadog-agent/pkg/network/usm/buildmode"
	"github.com/DataDog/datadog-agent/pkg/network/usm/utils"
)

type protocol struct {
	cfg            *config.Config
	telemetry      *Telemetry
	statkeeper     *StatKeeper
	eventsConsumer *events.Consumer[EbpfTx]
}

const (
	protocolName       = "AMQP"
	eventStreamName    = "amqp"
	processTailCall    = "socket__amqp_process"
	tlsProcessTailCall = "uprobe__amqp_process"
	amqpHeapMap        = "amqp_heap"
)

var Spec = &protocols.ProtocolSpec{
	Factory: newAMQPProtocol,
	Maps: []*manager.Map{
		{
			Name: amqpHeapMap,
		},
	},
	TailCalls: []manager.TailCallRoute{
		{
			ProgArrayName: protocols.ProtocolDispatcherProgramsMap,
			Key:           uint32(protocols.ProgramAMQP),
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: processTailCall,
			},
		},
		{
			ProgArrayName: protocols.TLSDispatcherProgramsMap,
			Key:           uint32(protocols.ProgramAMQP),
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: tlsProcessTailCall,
			},
		},
	},
}

func newAMQPProtocol(cfg *config.Config) (protocols.Protocol, error) {
	if !cfg.EnableAMQPMonitoring {
		return nil, nil
	}

	return &protocol{
		cfg:       cfg,
		telemetry: NewTelemetry(),
	}, nil
}

func (p *protocol) Name() string {
	return protocolName
}

// ConfigureOptions add the necessary options for the AMQP monitoring to work,
// to be used by the manager.
func (p *protocol) ConfigureOptions(mgr *manager.Manager, opts *manager.Options) {
	utils.EnableOption(opts, "amqp_monitoring_enabled")
	events.Configure(p.cfg, eventStreamName, mgr, opts)
}

func (p *protocol) PreStart(mgr *manager.Manager) error {
	var err error
	p.eventsConsumer, err = events.NewConsumer(
		eventStreamName,
		mgr,
		p.processAMQPTransactionData,
	)
	if err != nil {
		return err
	}

	// todo!: shouldn't we move this into `newAMQPProtocol`? the telemetry should be external and not included inside the StatKeeper
	p.statkeeper = NewStatkeeper(p.cfg, p.telemetry)
	p.eventsConsumer.Start()

	return nil
}

func (p *protocol) PostStart(_ *manager.Manager) error {
	return nil
}

func (p *protocol) Stop(_ *manager.Manager) {
	if p.eventsConsumer != nil {
		p.eventsConsumer.Stop()
	}
}

func (p *protocol) DumpMaps(_ io.Writer, _ string, _ *ebpf.Map) {}

func (p *protocol) processAMQPTransactionData(events []EbpfTx) {
	for i := range events {
		tx := &events[i]
		p.telemetry.Count(tx)
		p.statkeeper.Process(tx)
	}
}

// GetStats returns a map of AMQP stats stored in the following format:
// [source, dest tuple, request path] -> RequestStats object
func (p *protocol) GetStats() *protocols.ProtocolStats {
	p.eventsConsumer.Sync()
	p.telemetry.Log()
	return &protocols.ProtocolStats{
		Type:  protocols.AMQP,
		Stats: p.statkeeper.GetAndResetAllStats(),
	}
}

// IsBuildModeSupported returns always true, as amqp module is supported by all modes.
func (*protocol) IsBuildModeSupported(buildmode.Type) bool {
	return true
}
