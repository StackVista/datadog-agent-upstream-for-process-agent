// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package mongo

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
	telemetry      *Telemetry
	statkeeper     *StatKeeper
	eventsConsumer *events.Consumer
}

const (
	eventStreamName    = "mongo"
	filterTailCall     = "socket__mongo_filter"
	tlsProcessTailCall = "uprobe__mongo_process"
)

var Spec = &protocols.ProtocolSpec{
	Factory: newMongoProtocol,
	Maps:    []*manager.Map{},
	TailCalls: []manager.TailCallRoute{
		{
			ProgArrayName: protocols.ProtocolDispatcherProgramsMap,
			Key:           uint32(protocols.ProgramMongo),
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: filterTailCall,
			},
		},
		{
			ProgArrayName: protocols.TLSDispatcherProgramsMap,
			Key:           uint32(protocols.ProgramTLSMongoProcess),
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: tlsProcessTailCall,
			},
		},
	},
}

func newMongoProtocol(cfg *config.Config) (protocols.Protocol, error) {
	if !cfg.EnableMongoMonitoring {
		return nil, nil
	}

	return &protocol{
		cfg:       cfg,
		telemetry: NewTelemetry(),
	}, nil
}

func (p *protocol) Name() string {
	return "Mongo"
}

// ConfigureOptions add the necessary options for the mongo monitoring to work,
// to be used by the manager. These are:
// - Set the `kafka_last_tcp_seq_per_connection` map size to the value of the `max_tracked_connection` configuration variable.
//
// We also configure the kafka event stream with the manager and its options.
func (p *protocol) ConfigureOptions(mgr *manager.Manager, opts *manager.Options) {
	events.Configure(eventStreamName, mgr, opts)
	utils.EnableOption(opts, "mongo_monitoring_enabled")
}

func (p *protocol) PreStart(mgr *manager.Manager) error {
	var err error
	p.eventsConsumer, err = events.NewConsumer(
		eventStreamName,
		mgr,
		p.processMongo,
	)
	if err != nil {
		return err
	}

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

func (p *protocol) DumpMaps(_ *strings.Builder, _ string, _ *ebpf.Map) {}

func (p *protocol) processMongo(data []byte) {
	tx := (*EbpfTx)(unsafe.Pointer(&data[0]))
	p.telemetry.Count(tx)
	p.statkeeper.Process(tx)
}

// GetStats returns a map of Mongo stats stored in the following format:
// [source, dest tuple, request path] -> RequestStats object
func (p *protocol) GetStats() *protocols.ProtocolStats {
	p.eventsConsumer.Sync()
	p.telemetry.Log()
	return &protocols.ProtocolStats{
		Type:  protocols.Mongo,
		Stats: p.statkeeper.GetAndResetAllStats(),
	}
}
