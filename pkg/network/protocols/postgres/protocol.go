// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package postgres

import (
	"strings"
	"unsafe"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/protocols"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/events"
	"github.com/DataDog/datadog-agent/pkg/network/usm/utils"
)

type protocol struct {
	cfg            *config.Config
	eventsConsumer *events.Consumer
}

const (
	eventStreamName    = "postgres"
	processTailCall    = "socket__postgres_process"
	tlsProcessTailCall = "uprobe__postgres_process"
)

var Spec = &protocols.ProtocolSpec{
	Factory: newPostgresProtocol,
	Maps:    []*manager.Map{},
	TailCalls: []manager.TailCallRoute{
		{
			ProgArrayName: protocols.ProtocolDispatcherProgramsMap,
			Key:           uint32(protocols.ProgramPostgres),
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: processTailCall,
			},
		},
		{
			ProgArrayName: protocols.TLSDispatcherProgramsMap,
			Key:           uint32(protocols.ProgramTLSPostgresProcess),
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: tlsProcessTailCall,
			},
		},
	},
}

func newPostgresProtocol(cfg *config.Config) (protocols.Protocol, error) {
	// Always enable for now
	/*
		if !cfg.EnablePostgresMonitoring {
			return nil, nil
		}
	*/

	return &protocol{
		cfg:       cfg,
		telemetry: NewTelemetry(),
	}, nil
}

func (p *protocol) Name() string {
	return "Postgres"
}

// ConfigureOptions add the necessary options for the Postgres monitoring to work,
// to be used by the manager.
// We also configure the AMQP event stream with the manager and its options.
func (p *protocol) ConfigureOptions(mgr *manager.Manager, opts *manager.Options) {
	events.Configure(eventStreamName, mgr, opts)
	utils.EnableOption(opts, "postgres_monitoring_enabled")
}

func (p *protocol) PreStart(mgr *manager.Manager) error {
	var err error
	p.eventsConsumer, err = events.NewConsumer(
		eventStreamName,
		mgr,
		p.processPostgresTransactionData,
	)
	if err != nil {
		return err
	}

	/*
		p.statkeeper = NewStatkeeper(p.cfg, p.telemetry)
	*/
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

func (p *protocol) DumpMaps(_ *strings.Builder, _ string, _ *ebpf.Map) {}

func (p *protocol) processPostgresTransactionData(data []byte) {
	tx := (*EbpfTx)(unsafe.Pointer(&data[0]))

	/*
		p.telemetry.Count(tx)
		p.statkeeper.Process(tx)
	*/
}

// GetStats returns a map of Postgres stats stored in the following format:
// [source, dest tuple, request path] -> RequestStats object
func (p *protocol) GetStats() *protocols.ProtocolStats {
	p.eventsConsumer.Sync()
	p.telemetry.Log()
	return &protocols.ProtocolStats{
		Type:  protocols.AMQP,
		Stats: p.statkeeper.GetAndResetAllStats(),
	}
}
