// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package main - single file executable
package main

import (
	"embed"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config/model"
	"github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network"
	tracerConfig "github.com/DataDog/datadog-agent/pkg/network/config"
	httpdebugging "github.com/DataDog/datadog-agent/pkg/network/protocols/http/debugging"
	postgresdebugging "github.com/DataDog/datadog-agent/pkg/network/protocols/postgres/debugging"
	"github.com/DataDog/datadog-agent/pkg/network/tracer"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/cihub/seelog"
	ciliumEbpf "github.com/cilium/ebpf"
)

const (
	postgresProtocol = "postgres"
	amqpProtocol     = "amqp"
	httpProtocol     = "http"
	proto            = "proto"
	connections      = "conns"
	allProtocols     = "all"
)

const (
	postgresCode = 1 << iota
	httpCode
	connectionsCode
	amqpCode
)

//go:embed ebpf/*
var ebpfFS embed.FS

// this is paired with the embed FS tag
const ebpfEmbedFSFolder = "ebpf"

var (
	// Enable extended verifier logs increase the time needed to run this program
	verifierLogLevel = flag.Int("ebpf-verbose", int(ciliumEbpf.LogLevelStats), "Verifier log level. 4 -> stats (the least verbose), 2 -> instructions (the most verbose), 1 -> branch.")
	longRunning      = flag.Bool("long-run", false, "Used to debug ebpf programs, if set the program will run for 30 minutes")
	// we use warn as default verbosity level to avoid polluting the logs in case we just want to see a verifer error.
	userspaceLogLevel = flag.String("verbose", "warn", "Userspace vebosity. Possible values (trace, debug, info, warn, error, critical, off).")
	printProtocols    = flag.String(
		"proto",
		"all", "print active connections or/and protocol metrics. Possible values (all, conns, proto, http, postgres, amqp). 'all' means active connections + all supported protocols")
	enableHTTP = flag.Bool("enable-http", true, "Enable HTTP and HTTP2 monitoring (sets EnableHTTPMonitoring and EnableHTTP2Monitoring to true).")
	testUprobe = flag.Bool("test-uprobe", false, "Test if uprobes are supported on the system by trying to access the uprobe_events tracefs file.")
)

func validatePrintProtocols() uint64 {
	defer log.Warnf("Print: %s\n", *printProtocols)
	switch *printProtocols {
	case connections:
		return connectionsCode
	case httpProtocol:
		return httpCode
	case postgresProtocol:
		return postgresCode
	case amqpProtocol:
		return amqpCode
	case proto:
		return httpCode | postgresCode | amqpCode
	default:
		return httpCode | postgresCode | connectionsCode | amqpCode
	}
}

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
		EnableHTTPMonitoring:          *enableHTTP,
		EnableHTTP2Monitoring:         *enableHTTP,
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

// runUprobeTest checks whether uprobes are supported on the current system by
// attempting to open and write to the kernel's uprobe_events tracefs file, then
// immediately removing the test entry.  This does not require an eBPF program.
func runUprobeTest() error {
	const testEventName = "nettop_uprobe_test"

	// uprobe_events may live under debugfs or directly under tracefs.
	tracefsPaths := []string{
		"/sys/kernel/debug/tracing",
		"/sys/kernel/tracing",
	}

	var uprobeEventsPath string
	for _, base := range tracefsPaths {
		p := base + "/uprobe_events"
		if _, err := os.Stat(p); err == nil {
			uprobeEventsPath = p
			break
		}
	}
	if uprobeEventsPath == "" {
		return fmt.Errorf("uprobe_events file not found; tracefs may not be mounted or uprobes are not supported")
	}
	log.Warnf("uprobe probe path found: %s\n", uprobeEventsPath)

	// Resolve the path of the current executable to attach the test probe to.
	self, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return fmt.Errorf("cannot resolve /proc/self/exe: %w", err)
	}

	f, err := os.OpenFile(uprobeEventsPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("cannot open %s (are you root?): %w", uprobeEventsPath, err)
	}
	defer f.Close()

	// Add a test uprobe at offset 0x0 of the current binary.
	addEntry := fmt.Sprintf("p:uprobes/%s %s:0x0\n", testEventName, self)
	if _, err := fmt.Fprint(f, addEntry); err != nil {
		return fmt.Errorf("cannot register test uprobe: %w", err)
	}

	// Remove the test uprobe immediately.
	removeEntry := fmt.Sprintf("-:uprobes/%s\n", testEventName)
	if _, err := fmt.Fprint(f, removeEntry); err != nil {
		// Non-fatal: we registered it but couldn't clean it up.
		log.Warnf("test-uprobe: could not remove test uprobe entry: %v", err)
	}

	return nil
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

	if *testUprobe {
		if err := runUprobeTest(); err != nil {
			log.Warnf("test-uprobe: FAILED – uprobes do not appear to be supported: %v\n", err)
			return 1
		}
		log.Warnf("test-uprobe: OK – uprobes are supported on this system\n")
	}

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
	tr, err := tracer.NewTracer(c, nil)
	if err != nil {
		log.Errorf("%v\n", err)
		return 1
	}
	log.Warn("No verifier errors :)\n")
	// If we are not in long running mode, we just exit
	if !*longRunning {
		return 0
	}

	protocols := validatePrintProtocols()

	log.Warn("Running until CTRL+C...\n")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	printConns := func(now time.Time) {
		cs, err := tr.GetActiveConnections(fmt.Sprintf("%d", os.Getpid()))
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("-- %s --\n", now)
		switch {
		case protocols&connectionsCode != 0:
			fmt.Printf("\n\n------ Connection summary\n\n")
			for _, c := range cs.Conns {
				fmt.Println(network.ConnectionSummary(&c, cs.DNS))
			}
		case protocols&postgresCode != 0:
			stats := postgresdebugging.Postgres(cs.Postgres)
			fmt.Printf("\n\n------ Postgres stats (%d)\n\n", len(stats))
			for _, c := range stats {
				fmt.Println(c)
			}
		case protocols&amqpCode != 0:
			fmt.Printf("\n\n------ AMQP stats (%d)\n\n", len(cs.AMQP))
			for key, v := range cs.AMQP {
				fmt.Printf("tuple: '%v', queue: '%v', exchange: '%v', published: '%d', delivered: '%d'\n", key.ConnectionKey.String(), key.QueueName, key.ExchangeName, v.MessagesPublished, v.MessagesDelivered)
			}
		case protocols&httpCode != 0:
			stats := httpdebugging.HTTP(cs.HTTP, cs.DNS)
			fmt.Printf("\n\n------ HTTP stats (%d)\n\n", len(stats))
			for _, c := range stats {
				fmt.Println(c)
			}
			fmt.Printf("\n\n------ HTTP observations (%d)\n\n", len(cs.HTTPObservations))
			for _, obs := range cs.HTTPObservations {
				fmt.Println(obs)
			}
			stats = httpdebugging.HTTP(cs.HTTP2, cs.DNS)
			fmt.Printf("\n\n------ HTTP2 stats (%d)\n\n", len(stats))
			for _, c := range stats {
				fmt.Println(c)
			}
		}
	}

	stopChan := make(chan struct{})
	go func() {
		// Print active connections immediately, and then again every 5 seconds
		tick := time.NewTicker(5 * time.Second)
		printConns(time.Now())
		for {
			select {
			case now := <-tick.C:
				printConns(now)
			case <-stopChan:
				tick.Stop()
				return
			}
		}
	}()

	<-sig
	stopChan <- struct{}{}

	tr.Stop()
	return 0
}

func main() {
	// Parse the flags
	flag.Parse()
	os.Exit(run())
}
