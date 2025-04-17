// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package main - single file executable
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config/model"
	"github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/ebpf"
	tracerConfig "github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/tracer"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
)

var (
	ebpfDir = flag.String("dir", "/ebpf_artifacts", "Directory containing the eBPF programs (.o files)")
	// Enable extended verifier logs increase the time needed to run this program
	verifierVerbose = flag.Bool("verbose", false, "Enable verbose verifier debug logs")
)

func getTracerConfig() *tracerConfig.Config {
	// Defaults taken from datadog
	const defaultUDPTimeoutSeconds = 30
	const defaultUDPStreamTimeoutSeconds = 120
	const defaultOffsetThreshold = 400
	const maxTrackedConnections = 1000

	return &tracerConfig.Config{
		Config: ebpf.Config{
			BPFDebug:                 false,
			BPFDir:                   *ebpfDir,
			ExcludedBPFLinuxVersions: []string{},
			EnableTracepoints:        false,
			ProcRoot:                 kernel.ProcFSRoot(),

			EnableCORE:                   false,
			EnableRuntimeCompiler:        false,
			AllowRuntimeCompiledFallback: false,

			// Should be irrilevant for us since we disable CORE and runtime compiler.
			// Put it to `true` just to highlight that we want to fallback to the prebuilt mode.
			AllowPrebuiltFallback: true,

			BTFPath: "", // No btf support for now

			RuntimeCompilerOutputDir:         "",
			EnableKernelHeaderDownload:       false,
			KernelHeadersDirs:                []string{""},
			KernelHeadersDownloadDir:         "/tmp",
			AptConfigDir:                     "/etc/apt",
			YumReposDir:                      "/etc/yum.repos.d",
			ZypperReposDir:                   "/etc/zypp/repos.d",
			AttachKprobesWithKprobeEventsABI: false,
		},

		NPMEnabled:               true,
		ServiceMonitoringEnabled: true,

		CollectTCPv4Conns: true,
		TCPConnTimeout:    2 * time.Minute,

		CollectUDPv4Conns: false,
		UDPConnTimeout:    defaultUDPTimeoutSeconds * time.Second,
		UDPStreamTimeout:  defaultUDPStreamTimeoutSeconds * time.Second,

		CollectTCPv6Conns:              true,
		OffsetGuessThreshold:           defaultOffsetThreshold,
		ExcludedSourceConnections:      map[string][]string{},
		ExcludedDestinationConnections: map[string][]string{},

		MaxTrackedConnections:          uint32(maxTrackedConnections),
		MaxClosedConnectionsBuffered:   uint32(maxTrackedConnections),
		ClosedConnectionFlushThreshold: 0,
		ClosedChannelSize:              500,
		MaxConnectionsStateBuffered:    75000,
		ClientStateExpiry:              2 * time.Minute,

		DNSInspection:       false,
		CollectDNSStats:     false,
		CollectLocalDNS:     false,
		CollectDNSDomains:   false,
		MaxDNSStats:         20000,
		MaxDNSStatsBuffered: 75000,
		DNSTimeout:          15 * time.Second,

		// Enable everything related to eBPF loading, so that if we have a failure we face it immediately
		ProtocolClassificationEnabled: true,
		EnableHTTPMonitoring:          true,
		EnableHTTP2Monitoring:         true,
		EnableKafkaMonitoring:         true,
		EnableMongoMonitoring:         true,
		EnableAMQPMonitoring:          true,
		EnablePostgresMonitoring:      true,
		EnableNativeTLSMonitoring:     true,
		EnableHTTPTracing:             true,

		ProbeDebugLog: *verifierVerbose,

		EnableConntrack:       true,
		EnableEbpfConntracker: true,

		// today we don't support it
		EnableIstioMonitoring: false,
		EnableGoTLSSupport:    false,

		MaxMongoStatsBuffered:       100000,
		MaxAMQPStatsBuffered:        100000,
		MaxPostgresStatsBuffered:    100000,
		MaxPostgresTelemetryBuffer:  160,
		MaxHTTPStatsBuffered:        100000,
		MaxHTTPObservationsBuffered: 100000,

		MaxTrackedHTTPConnections: 1024,
		MaxUSMConcurrentRequests:  1024,
		HTTPNotificationThreshold: 512,
		HTTPMaxRequestFragment:    160,

		// At the moment we disable it by default, this is a new feature from the 7.62.2 sync.
		// Let's see if we need it in the future.
		EnableCiliumLBConntracker:    false,
		ConntrackMaxStateSize:        131072,
		ConntrackRateLimit:           500,
		ConntrackRateLimitInterval:   3 * time.Second,
		EnableConntrackAllNamespaces: true,
		IgnoreConntrackInitFailure:   false,
		ConntrackInitTimeout:         120 * time.Second,

		EnableGatewayLookup: false,

		EnableMonotonicCount: false,

		RecordedQueryTypes: []string{},

		EnableRootNetNs: true,

		HTTP2DynamicTableMapCleanerInterval: 300 * time.Second,

		HTTPMapCleanerInterval: 300 * time.Second,
		HTTPIdleConnectionTTL:  30 * time.Second,
	}
}

func main() {
	// Parse the flags
	flag.Parse()

	// If we don't intialize a config datadog will panic
	// Workaround to use only env var for the config
	// https://github.com/DataDog/datadog-agent/blob/e7235cf59393e06a187005695e489d63217cab3e/pkg/config/setup/config.go#L2054
	os.Setenv("AWS_LAMBDA_FUNCTION_NAME", "DummyValue")

	// The real reason why we are loading the config here is to detect the container runtimes (see DetectFeatures method inside `LoadWithoutSecret`)
	config := model.NewConfig("sts", "DD", strings.NewReplacer(".", "_"))
	setup.InitConfig(config)
	if _, err := setup.LoadWithoutSecret(config, nil); err != nil {
		fmt.Fprintf(os.Stderr, "unable to load datadog config: %v\n", err)
		os.Exit(1)
	}

	c := getTracerConfig()

	fmt.Printf("Injecting our ebpf instrumentation...\n")
	_, err := tracer.NewTracer(c, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("No verifier errors :)\n")
	os.Exit(0)
}
