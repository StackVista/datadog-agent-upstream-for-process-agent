// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package main - single file executable
package main

import (
	"embed"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config/model"
	"github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/ebpf"
	tracerConfig "github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/tracer"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/cihub/seelog"
	ciliumEbpf "github.com/cilium/ebpf"
)

//go:embed ebpf/*
var ebpfFS embed.FS

// this is paired with the embed FS tag
const ebpfEmbedFSFolder = "ebpf"

var (
	// Enable extended verifier logs increase the time needed to run this program
	verifierLogLevel  = flag.Int("ebpf-verbose", int(ciliumEbpf.LogLevelStats), "Verifier log level. 4 -> stats (the least verbose), 2 -> instructions (the most verbose), 1 -> branch.")
	longRunning       = flag.Bool("long-run", false, "Used to debug ebpf programs, if set the program will run for 30 minutes")
	userspaceLogLevel = flag.String("verbose", "warn", "Userspace vebosity. Possible values (debug, info, warn, error, critical, off).")
)

func getTracerConfig(ebpfDir string) *tracerConfig.Config {
	// Defaults taken from datadog
	const defaultUDPTimeoutSeconds = 30
	const defaultUDPStreamTimeoutSeconds = 120
	const defaultOffsetThreshold = 400
	const maxTrackedConnections = 1000

	// Validation on the log level.
	logLevel := ciliumEbpf.LogLevel(*verifierLogLevel & 7)
	if logLevel == 0 {
		log.Errorf("Invalid verifier log level %d, must be between 1 and 7", *verifierLogLevel)
		os.Exit(1)
	}
	log.Warnf("Using verifier log level %d", logLevel)

	return &tracerConfig.Config{
		Config: ebpf.Config{
			BPFDebug:                 false,
			BPFDir:                   ebpfDir,
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

		// Here we want to manually control the level of logging not using `ProbeDebugLog`
		EBPFLogLevelUSM: logLevel,
		ProbeDebugLog:   false,

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

func dumpEBPF() (string, error) {
	// Create a temp dir, unpack all the .o files there
	tmp := filepath.Join(os.TempDir(), "nettop-ebpf")
	if err := os.MkdirAll(tmp, 0755); err != nil {
		return "", err
	}
	entries, err := ebpfFS.ReadDir(ebpfEmbedFSFolder)
	if err != nil {
		return "", log.Errorf("reading embedded dir %q: %w", ebpfEmbedFSFolder, err)
	}
	for _, e := range entries {
		filePath := filepath.Join(ebpfEmbedFSFolder, e.Name())
		data, err := ebpfFS.ReadFile(filePath)
		if err != nil {
			return "", log.Errorf("reading embedded file %q: %w", filePath, err)
		}
		if err := os.WriteFile(filepath.Join(tmp, e.Name()), data, 0644); err != nil {
			return "", err
		}
		// we need this because because we check the permissions of the files `root:root 0022`
		if err := os.Chown(filepath.Join(tmp, e.Name()), 0, 0); err != nil {
			return "", err
		}
	}
	return tmp, nil
}

func run() int {
	log.SetupLogger(seelog.Default, *userspaceLogLevel)
	// Critical so that it will be always printed
	log.Criticalf("Using userspace verbosity level %s\n", *userspaceLogLevel)
	defer log.Flush()

	ebpfDir, err := dumpEBPF()
	if err != nil {
		log.Errorf("unable to embedded FS: %v\n", err)
		return 1
	}

	// If we don't intialize a config datadog will panic
	// Workaround to use only env var for the config
	// https://github.com/DataDog/datadog-agent/blob/e7235cf59393e06a187005695e489d63217cab3e/pkg/config/setup/config.go#L2054
	os.Setenv("AWS_LAMBDA_FUNCTION_NAME", "DummyValue")

	// The real reason why we are loading the config here is to detect the container runtimes (see DetectFeatures method inside `LoadWithoutSecret`)
	config := model.NewConfig("sts", "DD", strings.NewReplacer(".", "_"))
	setup.InitConfig(config)
	if _, err := setup.LoadWithoutSecret(config, nil); err != nil {
		log.Errorf("unable to load datadog config: %v\n", err)
		return 1
	}

	c := getTracerConfig(ebpfDir)

	log.Warn("Injecting our ebpf instrumentation...\n")
	_, err = tracer.NewTracer(c, nil)
	if err != nil {
		log.Errorf("%v\n", err)
		return 1
	}
	log.Warn("No verifier errors :)\n")

	if *longRunning {
		log.Warn("Running for 30 minutes...\n")
		time.Sleep(30 * time.Minute)
	}
	return 0
}

func main() {
	// Parse the flags
	flag.Parse()
	os.Exit(run())
}
