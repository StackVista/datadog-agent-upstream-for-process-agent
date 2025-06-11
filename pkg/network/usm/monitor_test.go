// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package usm

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	nethttp "net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/DataDog/datadog-agent/pkg/ebpf/ebpftest"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	netlink "github.com/DataDog/datadog-agent/pkg/network/netlink/testutil"
	"github.com/DataDog/datadog-agent/pkg/network/protocols"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/http"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/http/testutil"
	libtelemetry "github.com/DataDog/datadog-agent/pkg/network/protocols/telemetry"
	"github.com/DataDog/datadog-agent/pkg/network/types"
	usmconfig "github.com/DataDog/datadog-agent/pkg/network/usm/config"
	"github.com/DataDog/datadog-agent/pkg/network/usm/utils"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	stsutil "github.com/DataDog/datadog-agent/pkg/util/testutil"
)

func TestMain(m *testing.M) {
	logLevel := os.Getenv("DD_LOG_LEVEL")
	if logLevel == "" {
		logLevel = "warn"
	}
	log.SetupLogger(log.Default(), logLevel)
	os.Exit(m.Run())
}

const (
	kb = 1024
	mb = 1024 * kb
)

var (
	emptyBody = []byte(nil)
	kv        = kernel.MustHostVersion()
)

func TestMonitorProtocolFail(t *testing.T) {
	failingStartupMock := func(_ *manager.Manager) error {
		return fmt.Errorf("mock error")
	}

	testCases := []struct {
		name string
		spec protocolMockSpec
	}{
		{name: "PreStart fails", spec: protocolMockSpec{preStartFn: failingStartupMock}},
		{name: "PostStart fails", spec: protocolMockSpec{postStartFn: failingStartupMock}},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// Replace the HTTP protocol with a Mock
			patchProtocolMock(t, tt.spec)

			cfg := utils.NewUSMEmptyConfig()
			cfg.EnableHTTPMonitoring = true

			monitor, err := NewMonitor(cfg, nil)
			skipIfNotSupported(t, err)
			require.NoError(t, err)
			t.Cleanup(monitor.Stop)

			err = monitor.Start()
			require.ErrorIs(t, err, errNoProtocols)
		})
	}
}

type HTTPTestSuite struct {
	suite.Suite
}

func TestHTTP(t *testing.T) {
	if kv < usmconfig.MinimumKernelVersion {
		t.Skipf("USM is not supported on %v", kv)
	}
	ebpftest.TestBuildModes(t, stsutil.OnlyPrebuiltModeIfSelected(), "", func(t *testing.T) {
		suite.Run(t, new(HTTPTestSuite))
	})
}

func (s *HTTPTestSuite) TestHTTPStats() {
	t := s.T()

	// Start an HTTP server on localhost:8080
	serverAddr := "127.0.0.1:8080"
	srvDoneFn := testutil.HTTPServer(t, serverAddr, testutil.Options{
		EnableKeepAlive: true,
	})
	t.Cleanup(srvDoneFn)

	monitor := newHTTPMonitorWithCfg(t, utils.NewUSMEmptyConfig())

	resp, err := nethttp.Get(fmt.Sprintf("http://%s/%d/test", serverAddr, nethttp.StatusNoContent))
	require.NoError(t, err)
	_ = resp.Body.Close()
	srvDoneFn()

	// Iterate through active connections until we find connection created above
	require.Eventuallyf(t, func() bool {
		stats := getHTTPLikeProtocolStats(monitor, protocols.HTTP)

		for key, reqStats := range stats {
			if key.Method == http.MethodGet && strings.HasSuffix(key.Path.Content.Get(), "/test") && (key.SrcPort == 8080 || key.DstPort == 8080) {
				currentStats := reqStats.Data[200]
				if currentStats != nil && currentStats.Count == 1 {
					return true
				}
			}
		}

		return false
	}, 3*time.Second, 100*time.Millisecond, "couldn't find http connection matching: %s", serverAddr)
}

// TestHTTPMonitorLoadWithIncompleteBuffers sends thousands of requests without getting responses for them, in parallel
// we send another request. We expect to capture the another request but not the incomplete requests.
func (s *HTTPTestSuite) TestHTTPMonitorLoadWithIncompleteBuffers() {
	t := s.T()

	slowServerAddr := "localhost:8080"
	fastServerAddr := "localhost:8081"

	monitor := newHTTPMonitorWithCfg(t, utils.NewUSMEmptyConfig())
	slowSrvDoneFn := testutil.HTTPServer(t, slowServerAddr, testutil.Options{
		SlowResponse: time.Millisecond * 500, // Half a second.
		WriteTimeout: time.Millisecond * 200,
		ReadTimeout:  time.Millisecond * 200,
	})

	fastSrvDoneFn := testutil.HTTPServer(t, fastServerAddr, testutil.Options{})
	abortedRequestFn := requestGenerator(t, fmt.Sprintf("%s/ignore", slowServerAddr), "", emptyBody)
	wg := sync.WaitGroup{}
	abortedRequests := make(chan *nethttp.Request, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := abortedRequestFn()
			abortedRequests <- req
		}()
	}
	fastReq := requestGenerator(t, fastServerAddr, "", emptyBody)()
	wg.Wait()
	close(abortedRequests)
	slowSrvDoneFn()
	fastSrvDoneFn()

	foundFastReq := false
	// We are iterating for a couple of iterations and making sure the aborted requests will never be found.
	// Since the every call for monitor.GetHTTPStats will delete the pop all entries, and we want to find fastReq
	// then we are using a variable to check if "we ever found it" among the iterations.
	for i := 0; i < 10; i++ {
		time.Sleep(10 * time.Millisecond)
		stats := getHTTPLikeProtocolStats(monitor, protocols.HTTP)
		for req := range abortedRequests {
			checkRequestIncluded(t, stats, req, false)
		}

		included, err := isRequestIncludedOnce(stats, fastReq)
		require.NoError(t, err)
		foundFastReq = foundFastReq || included
	}

	require.True(t, foundFastReq)
}

func (s *HTTPTestSuite) TestHTTPWebSockets() {
	t := s.T()

	var upgrader = websocket.Upgrader{
		// CheckOrigin: in production, validate the Origin header
		CheckOrigin: func(r *nethttp.Request) bool {
			// Allow all origins (for example purposes only)
			return true
		},
	}

	handler := func(w nethttp.ResponseWriter, r *nethttp.Request) {
		// Upgrade the HTTP connection to WebSocket
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Log("Upgrade error:", err)
			return
		}
		defer conn.Close()
		t.Log("New WebSocket connection from", r.RemoteAddr)

		// We exchange a message on the websocket just to be sure it is ignored by HTTP stats
		msgType, msg, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				t.Log("Unexpected close error:", err)
			}
			return
		}
		t.Log("Send message back to the client")

		if err := conn.WriteMessage(msgType, []byte(string(msg))); err != nil {
			t.Log("Write message error:", err)
			return
		}
		t.Log("Message sent back to the client")
	}

	// We start our monitor
	monitor := newHTTPMonitorWithCfg(t, utils.NewUSMEmptyConfig())

	// We start Http server
	addr := ":8080"
	url := "ws://" + addr + "/ws"
	srv := &nethttp.Server{
		Addr:         addr,
		Handler:      nethttp.HandlerFunc(handler),
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != nethttp.ErrServerClosed {
			t.Fatal("cannot start the server:", err)
		}
	}()
	defer srv.Shutdown(context.Background())

	var conn types.ConnectionKey

	// new scope to defer the connection close
	{
		// We try to contact the server
		var c *websocket.Conn
		assert.Eventually(t, func() bool {
			var err error
			c, _, err = websocket.DefaultDialer.Dial(url, nil)
			if err != nil {
				t.Log("Dial error:", err)
				return false
			}
			return true
		}, 3*time.Second, time.Millisecond*100, "cannot open connection with the server")
		defer c.Close()

		// We know have a connection, and our monitor should already have a request in the HTTP stats.
		// the http transaction should be sent when the server answers with the upgrade.
		stats := getHTTPLikeProtocolStats(monitor, protocols.HTTP)
		for k, v := range stats {
			t.Logf("Stats for %s: %v", k, v)
			if k.Method == http.MethodGet && strings.HasSuffix(k.Path.Content.Get(), "/ws") {
				// We expect to have a single request with 101 status code
				require.Len(t, v.Data, 1)
				// Please note that we should have 101 as status code but we normalize it here to 100
				s, ok := v.Data[100]
				require.True(t, ok, "expected status code 100 but got %v", v.Data)
				require.Equal(t, 1, s.Count)
				// we store the connection because we will need it later to assert we have no other stats from this connection
				// we use also this to understand if we have found the websocket transaction
				conn = k.ConnectionKey
				break
			}
		}

		// if we didn't find the websocket transaction the src and dst ports will be 0
		if conn.SrcPort == 0 && conn.DstPort == 0 {
			t.Fatal("cannot find WebSocket transaction in HTTP stats")
		}

		// No we send the message from the client and we shouldn't see other HTTP transaction for this connection
		if err := c.WriteMessage(websocket.TextMessage, []byte("Hello!")); err != nil {
			t.Fatal("Write message error:", err)
		}
		_, _, err := c.ReadMessage()
		if err != nil {
			t.Fatal("Read message error:", err)
		}
	}

	// We assert again the stats and we should find the connection
	stats := getHTTPLikeProtocolStats(monitor, protocols.HTTP)
	for k, v := range stats {
		t.Logf("Stats for %s: %v", k, v)
		if k.ConnectionKey == conn {
			t.Fatal("found WebSocket request in HTTP stats after the connection was closed, this is unexpected")
		}
	}
}

// TestHTTPMonitorInstructionCounts should fail everytime we touch an ebpf program. We want to be aware of the amount of
// instructions we add to the verifier with our changes to not hit the limit too quickly.
func (s *HTTPTestSuite) TestHTTPMonitorInstructionCounts() {
	t := s.T()
	// This is the exact number of instruction we obtain compiling with clang-12 in our docker build image.
	// To generate them again is enough to use the for loop above, disabling the assertions.
	instrCounts := map[string]int{
		"istio_uretprobe__SSL_read":                                4809,
		"istio_uretprobe__SSL_write":                               4854,
		"kprobe__sockfd_lookup_light":                              22,
		"kprobe__tcp_close":                                        779,
		"kprobe__tcp_sendmsg":                                      593,
		"kretprobe__sockfd_lookup_light":                           651,
		"nodejs_uretprobe__SSL_read":                               4809,
		"nodejs_uretprobe__SSL_read_ex":                            4824,
		"nodejs_uretprobe__SSL_write":                              4854,
		"nodejs_uretprobe__SSL_write_ex":                           4826,
		"socket__amqp_process":                                     290144,
		"socket__http2_dynamic_table_cleaner":                      3968,
		"socket__http2_eos_parser":                                 79818,
		"socket__http2_filter":                                     125275,
		"socket__http2_handle_first_frame":                         1116,
		"socket__http2_headers_parser":                             779373,
		"socket__http_filter":                                      77026,
		"socket__kafka_fetch_response_partition_parser_v0":         7483,
		"socket__kafka_fetch_response_partition_parser_v12":        4862,
		"socket__kafka_fetch_response_record_batch_parser_v0":      3754,
		"socket__kafka_fetch_response_record_batch_parser_v12":     3754,
		"socket__kafka_filter":                                     6932,
		"socket__kafka_produce_response_partition_parser_v0":       1123,
		"socket__kafka_produce_response_partition_parser_v9":       1211,
		"socket__mongo_filter":                                     397,
		"socket__postgres_handle":                                  3045,
		"socket__protocol_dispatcher":                              17051,
		"socket__protocol_dispatcher_kafka":                        18984,
		"socket__redis_process":                                    2,
		"tracepoint__net__netif_receive_skb":                       2189,
		"uprobe__BIO_new_socket":                                   14,
		"uprobe__SSL_connect":                                      14,
		"uprobe__SSL_do_handshake":                                 14,
		"uprobe__SSL_read":                                         73,
		"uprobe__SSL_read_ex":                                      75,
		"uprobe__SSL_set_bio":                                      35,
		"uprobe__SSL_set_fd":                                       22,
		"uprobe__SSL_shutdown":                                     358,
		"uprobe__SSL_write":                                        16,
		"uprobe__SSL_write_ex":                                     18,
		"uprobe__amqp_process":                                     295698,
		"uprobe__gnutls_bye":                                       358,
		"uprobe__gnutls_deinit":                                    358,
		"uprobe__gnutls_handshake":                                 14,
		"uprobe__gnutls_record_recv":                               16,
		"uprobe__gnutls_record_send":                               16,
		"uprobe__gnutls_transport_set_int2":                        22,
		"uprobe__gnutls_transport_set_ptr":                         22,
		"uprobe__gnutls_transport_set_ptr2":                        22,
		"uprobe__http2_dynamic_table_cleaner":                      3964,
		"uprobe__http2_tls_eos_parser":                             79815,
		"uprobe__http2_tls_filter":                                 67862,
		"uprobe__http2_tls_handle_first_frame":                     955,
		"uprobe__http2_tls_headers_parser":                         800877,
		"uprobe__http2_tls_termination":                            107,
		"uprobe__http_process":                                     101822,
		"uprobe__http_termination":                                 612,
		"uprobe__kafka_tls_fetch_response_partition_parser_v0":     8889,
		"uprobe__kafka_tls_fetch_response_partition_parser_v12":    5531,
		"uprobe__kafka_tls_fetch_response_record_batch_parser_v0":  3970,
		"uprobe__kafka_tls_fetch_response_record_batch_parser_v12": 3970,
		"uprobe__kafka_tls_filter":                                 6542,
		"uprobe__kafka_tls_produce_response_partition_parser_v0":   1193,
		"uprobe__kafka_tls_produce_response_partition_parser_v9":   1297,
		"uprobe__kafka_tls_termination":                            43,
		"uprobe__mongo_process":                                    417,
		"uprobe__postgres_tls_handle":                              2796,
		"uprobe__postgres_tls_termination":                         109,
		"uprobe__redis_tls_process":                                2,
		"uprobe__redis_tls_termination":                            2,
		"uprobe__tls_protocol_dispatcher_kafka":                    31785,
		"uretprobe__BIO_new_socket":                                29,
		"uretprobe__SSL_connect":                                   9,
		"uretprobe__SSL_do_handshake":                              9,
		"uretprobe__SSL_read":                                      4809,
		"uretprobe__SSL_read_ex":                                   4824,
		"uretprobe__SSL_write":                                     4854,
		"uretprobe__SSL_write_ex":                                  4826,
		"uretprobe__gnutls_handshake":                              9,
		"uretprobe__gnutls_record_recv":                            4802,
		"uretprobe__gnutls_record_send":                            4847,
	}

	cfg := utils.NewUSMEmptyConfig()
	cfg.EnableNativeTLSMonitoring = true
	cfg.EnableHTTPMonitoring = true
	cfg.EnableHTTP2Monitoring = true
	cfg.EnableKafkaMonitoring = true
	cfg.EnablePostgresMonitoring = true
	cfg.EnableRedisMonitoring = true
	cfg.EnableMongoMonitoring = true
	cfg.EnableAMQPMonitoring = true
	monitor := newHTTPMonitorWithCfg(t, cfg)

	programs, err := monitor.ebpfProgram.GetPrograms()
	require.NoError(t, err)
	r, err := regexp.Compile("processed ([0-9]+) insns")
	require.NoError(t, err)

	mismatchMap := make(map[string]int)
	mismatch := false

	for name, p := range programs {
		count, ok := instrCounts[name]
		require.True(t, ok, fmt.Sprintf("instruction count for %s is missing", name))
		match := r.FindStringSubmatch(p.VerifierLog)
		insns, err := strconv.Atoi(match[1])
		require.NoError(t, err)
		if insns != count {
			mismatchMap[name] = insns
			mismatch = true
		}
	}

	if mismatch {
		/////////////////////
		// Dump the diff so we can check what is changed
		/////////////////////
		for name, instr := range mismatchMap {
			msg := "++"
			// `--` less instruction than before
			if instr < instrCounts[name] {
				msg = "--"
			}
			t.Logf("- [%s] mismatch for prog %q: expected %d != actual %d\n", msg, name, instrCounts[name], instr)
			// Update to the new value so that at the end of the test we can create the new table to copy and paste
			instrCounts[name] = instr
		}

		/////////////////////
		// Dump the new table so we can copy and paste it
		/////////////////////

		// sort it by name
		keys := make([]string, 0, len(instrCounts))
		for k := range instrCounts {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			fmt.Printf("%q: %d,\n", k, instrCounts[k])
		}

		t.Errorf("instruction count mismatch")
	}
}

func (s *HTTPTestSuite) TestHTTPMonitorIntegrationWithResponseBody() {
	t := s.T()
	stsutil.SkipIfStackState(t, "[todo] still not clear why it is flaky")
	serverAddr := "localhost:8080"

	tests := []struct {
		name            string
		requestBodySize int
	}{
		{
			name:            "no body",
			requestBodySize: 0,
		},
		{
			name:            "1kb body",
			requestBodySize: 1 * kb,
		},
		{
			name:            "10kb body",
			requestBodySize: 10 * kb,
		},
		{
			name:            "500kb body",
			requestBodySize: 500 * kb,
		},
		{
			name:            "10mb body",
			requestBodySize: 10 * mb,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			monitor := newHTTPMonitorWithCfg(t, utils.NewUSMEmptyConfig())
			srvDoneFn := testutil.HTTPServer(t, serverAddr, testutil.Options{
				EnableKeepAlive: true,
			})
			t.Cleanup(srvDoneFn)

			requestFn := requestGenerator(t, serverAddr, "", bytes.Repeat([]byte("a"), tt.requestBodySize))
			var requests []*nethttp.Request
			for i := 0; i < 100; i++ {
				requests = append(requests, requestFn())
			}
			srvDoneFn()

			assertAllRequestsExists(t, monitor, requests)
		})
	}
}

// TestHTTPMonitorIntegrationSlowResponse sends a request and getting a slow response.
// The test checks multiple scenarios regarding USM's internal timeouts and cleaning intervals, and based on the values
// we check if we captured a request (and if we should have), or we didn't capture (and if we shouldn't have).
func (s *HTTPTestSuite) TestHTTPMonitorIntegrationSlowResponse() {
	t := s.T()
	serverAddr := "localhost:8080"

	tests := []struct {
		name                         string
		mapCleanerIntervalSeconds    int
		httpIdleConnectionTTLSeconds int
		slowResponseTime             int
		shouldCapture                bool
		skipReason                   string
	}{
		{
			name:                         "response reaching after cleanup",
			mapCleanerIntervalSeconds:    1,
			httpIdleConnectionTTLSeconds: 1,
			slowResponseTime:             3,
			shouldCapture:                false,
		},
		{
			skipReason:                   "[todo] still not clear why it fails",
			name:                         "response reaching before cleanup",
			mapCleanerIntervalSeconds:    1,
			httpIdleConnectionTTLSeconds: 3,
			slowResponseTime:             1,
			shouldCapture:                true,
		},
		{
			skipReason:                   "[todo] still not clear why it fails",
			name:                         "slow response reaching after ttl but cleaner not running",
			mapCleanerIntervalSeconds:    5, // bumped to let the test pass
			httpIdleConnectionTTLSeconds: 1,
			slowResponseTime:             2,
			shouldCapture:                true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipReason != "" {
				stsutil.SkipIfStackState(t, tt.skipReason)
			}
			cfg := utils.NewUSMEmptyConfig()
			cfg.HTTPMapCleanerInterval = time.Duration(tt.mapCleanerIntervalSeconds) * time.Second
			cfg.HTTPIdleConnectionTTL = time.Duration(tt.httpIdleConnectionTTLSeconds) * time.Second
			monitor := newHTTPMonitorWithCfg(t, cfg)

			slowResponseTimeout := time.Duration(tt.slowResponseTime) * time.Second
			serverTimeout := slowResponseTimeout + time.Second
			srvDoneFn := testutil.HTTPServer(t, serverAddr, testutil.Options{
				WriteTimeout: serverTimeout,
				ReadTimeout:  serverTimeout,
				SlowResponse: slowResponseTimeout,
			})
			t.Cleanup(srvDoneFn)

			// Create a request generator `requestGenerator(t, serverAddr, emptyBody)`, and runs it once. We save
			// the request for a later comparison.
			req := requestGenerator(t, serverAddr, "", emptyBody)()
			srvDoneFn()

			// Ensure all captured transactions get sent to user-space
			time.Sleep(10 * time.Millisecond)
			checkRequestIncluded(t, getHTTPLikeProtocolStats(monitor, protocols.HTTP), req, tt.shouldCapture)
		})
	}
}

func testNameHelper(optionTrue, optionFalse string, value bool) string {
	if value {
		return optionTrue
	}
	return optionFalse
}

// TestSanity checks that USM capture a random generated 100 requests send to a local HTTP server under the following
// conditions:
// 1. Server and client support keep alive, and there is no NAT.
// 2. Server and client do not support keep alive, and there is no NAT.
// 3. Server and client support keep alive, and there is DNAT.
// 4. Server and client do not support keep alive, and there is DNAT.
func (s *HTTPTestSuite) TestSanity() {
	t := s.T()
	stsutil.SkipIfIpPackagesRequired(t)

	serverAddrWithoutNAT := "localhost:8080"
	targetAddrWithNAT := "2.2.2.2:8080"
	serverAddrWithNAT := "1.1.1.1:8080"
	// SetupDNAT sets up a NAT translation from 2.2.2.2 to 1.1.1.1
	netlink.SetupDNAT(t)

	testCases := []struct {
		name          string
		serverAddress string
		targetAddress string
	}{
		{
			name:          "with dnat",
			serverAddress: serverAddrWithNAT,
			targetAddress: targetAddrWithNAT,
		},
		{
			name:          "without dnat",
			serverAddress: serverAddrWithoutNAT,
			targetAddress: serverAddrWithoutNAT,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			for _, keepAliveEnabled := range []bool{true, false} {
				t.Run(testNameHelper("with keep alive", "without keep alive", keepAliveEnabled), func(t *testing.T) {
					monitor := newHTTPMonitorWithCfg(t, utils.NewUSMEmptyConfig())

					srvDoneFn := testutil.HTTPServer(t, tt.serverAddress, testutil.Options{EnableKeepAlive: keepAliveEnabled})
					t.Cleanup(srvDoneFn)

					// Create a request generator that will be used to randomly generate requests and send them to the server.
					requestFn := requestGenerator(t, tt.targetAddress, "", emptyBody)
					var requests []*nethttp.Request
					for i := 0; i < 100; i++ {
						// Send a request to the server and save it for later comparison.
						requests = append(requests, requestFn())
					}
					srvDoneFn()

					// Ensure USM captured all requests.
					assertAllRequestsExists(t, monitor, requests)
				})
			}
		})
	}
}

func runHTTPMonitor(t *testing.T, serverAddr string, numReqs int, o testutil.Options, cfg *config.Config) (*Monitor, []*nethttp.Request) {
	monitor := newHTTPMonitorWithCfg(t, cfg)
	srvDoneFn := testutil.HTTPServer(t, serverAddr, o)

	// Perform a number of random requests
	requestFn := requestGenerator(t, serverAddr, o.RequestTraceId, emptyBody)
	var requests []*nethttp.Request
	for i := 0; i < numReqs; i++ {
		requests = append(requests, requestFn())
	}
	srvDoneFn()

	return monitor, requests
}

func (s *HTTPTestSuite) TestHTTPTraceId() {
	t := s.T()
	cfg := utils.NewUSMEmptyConfig()
	cfg.EnableHTTPTracing = true
	serverAddr := "localhost:8080"

	tests := []struct {
		name       string
		keep_alive bool
		options    testutil.Options
		expected   http.TransactionTraceId
	}{
		{
			name: "request_with_keep_alives",
			options: testutil.Options{
				// Use a different traceID for each request to easily identify them BPF side
				RequestTraceId:  "request0-keep-4206-8da1-d8c11c80585c",
				EnableKeepAlive: true,
			},
			expected: http.TransactionTraceId{
				Type: http.TraceIdRequest,
				Id:   "request0-keep-4206-8da1-d8c11c80585c",
			},
		},
		{
			name: "request_without_keep_alives",
			options: testutil.Options{
				RequestTraceId:  "request1-noke-4206-8da1-d8c11c80585c",
				EnableKeepAlive: false,
			},
			expected: http.TransactionTraceId{
				Type: http.TraceIdRequest,
				Id:   "request1-noke-4206-8da1-d8c11c80585c",
			},
		},
		{
			name: "response",
			options: testutil.Options{
				RequestTraceId:  "",
				ResponseTraceId: "response-noke-4206-8da1-d8c11c80585c",
				EnableKeepAlive: false,
			},
			expected: http.TransactionTraceId{
				Type: http.TraceIdResponse,
				Id:   "response-noke-4206-8da1-d8c11c80585c",
			},
		},
		{
			name: "ambigous",
			options: testutil.Options{
				RequestTraceId:  "request3-ambg-4206-8da1-d8c11c80585c",
				ResponseTraceId: "response-ambg-4206-8da1-d8c11c80585c",
				EnableKeepAlive: false,
			},
			expected: http.TransactionTraceId{
				Type: http.TraceIdAmbiguous,
				Id:   "",
			},
		},
		{
			name: "both",
			options: testutil.Options{
				RequestTraceId:  "both3435-4r2t-4206-8da1-d8c11c80585c",
				ResponseTraceId: "both3435-4r2t-4206-8da1-d8c11c80585c",
				EnableKeepAlive: false,
			},
			expected: http.TransactionTraceId{
				Type: http.TraceIdBoth,
				Id:   "both3435-4r2t-4206-8da1-d8c11c80585c",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			monitor, _ := runHTTPMonitor(t, serverAddr, 1, tt.options, cfg)
			stats, observations := getHTTPLikeProtocolStatsObservations(monitor, protocols.HTTP)
			t.Logf("Stats: %v", stats)
			require.Equal(t, 0, len(stats))
			t.Logf("Observations: %v", observations)
			// todo!: Change this test when will fix the race condition.
			// Due to a race condition issue we could have more than one observation, but at least we should have one.
			require.GreaterOrEqual(t, len(observations), 1, "expected at least 1 observation")
			// Even if we have 2 observations, they are identical because we are pushing the same twice. Just assert the first one.
			require.Equal(t, tt.expected, observations[0].TraceId, "unexpected a different trace ID")

			if t.Failed() {
				ebpftest.DumpMapsTestHelper(t, monitor.DumpMaps, "http_in_flight")
			}
		})
	}
}

// TestRSTPacketRegression checks that USM captures a request that was forcefully terminated by a RST packet.
func (s *HTTPTestSuite) TestRSTPacketRegression() {
	t := s.T()
	stsutil.SkipIfStackState(t, "[todo] still not clear why it fails")

	monitor := newHTTPMonitorWithCfg(t, utils.NewUSMEmptyConfig())

	serverAddr := "127.0.0.1:8080"
	srvDoneFn := testutil.HTTPServer(t, serverAddr, testutil.Options{
		EnableKeepAlive: true,
	})
	t.Cleanup(srvDoneFn)

	// Create a "raw" TCP socket that will serve as our HTTP client
	// We do this in order to configure the socket option SO_LINGER
	// so we can force a RST packet to be sent during termination
	c, err := net.DialTimeout("tcp", serverAddr, 5*time.Second)
	require.NoError(t, err)

	// Issue HTTP request
	c.Write([]byte("GET /200/foobar HTTP/1.1\nHost: 127.0.0.1:8080\n\n"))
	io.Copy(io.Discard, c)

	// Configure SO_LINGER to 0 so that triggers an RST when the socket is terminated
	require.NoError(t, c.(*net.TCPConn).SetLinger(0))
	c.Close()
	time.Sleep(100 * time.Millisecond)

	// Assert that the HTTP request was correctly handled despite its forceful termination
	stats := getHTTPLikeProtocolStats(monitor, protocols.HTTP)
	url, err := url.Parse("http://127.0.0.1:8080/200/foobar")
	require.NoError(t, err)
	checkRequestIncluded(t, stats, &nethttp.Request{URL: url, Method: nethttp.MethodGet}, true)
}

// TestKeepAliveWithIncompleteResponseRegression checks that USM captures a request, although we initially saw a
// response and then a request with its response.
func (s *HTTPTestSuite) TestKeepAliveWithIncompleteResponseRegression() {
	t := s.T()

	monitor := newHTTPMonitorWithCfg(t, utils.NewUSMEmptyConfig())

	const req = "GET /200/foobar HTTP/1.1\n"
	const rsp = "HTTP/1.1 200 OK\n"
	const serverAddr = "127.0.0.1:8080"

	srvFn := func(c net.Conn) {
		// emulates a half-transaction (beginning with a response)
		n, err := c.Write([]byte(rsp))
		require.NoError(t, err)
		require.Equal(t, len(rsp), n)

		// now we read the request from the client on the same connection
		b := make([]byte, len(req))
		n, err = c.Read(b)
		require.NoError(t, err)
		require.Equal(t, len(req), n)
		require.Equal(t, string(b), req)

		// and finally send the response completing a full HTTP transaction
		n, err = c.Write([]byte(rsp))
		require.NoError(t, err)
		require.Equal(t, len(rsp), n)
		c.Close()
	}
	srv := testutil.NewTCPServer(serverAddr, srvFn, false)
	done := make(chan struct{})
	srv.Run(done)
	t.Cleanup(func() { close(done) })

	c, err := net.DialTimeout("tcp", serverAddr, 5*time.Second)
	require.NoError(t, err)

	// ensure we're beginning the connection with a "headless" response from the
	// server. this emulates the case where system-probe started in the middle of
	// request/response cycle
	b := make([]byte, len(rsp))
	n, err := c.Read(b)
	require.NoError(t, err)
	require.Equal(t, len(rsp), n)
	require.Equal(t, string(b), rsp)

	// now perform a request
	n, err = c.Write([]byte(req))
	require.NoError(t, err)
	require.Equal(t, len(req), n)

	// and read the response completing a full transaction
	n, err = c.Read(b)
	require.NoError(t, err)
	require.Equal(t, len(rsp), n)
	require.Equal(t, string(b), rsp)

	// after this response, request, response cycle we should ensure that
	// we got a full HTTP transaction
	url, err := url.Parse("http://127.0.0.1:8080/200/foobar")
	require.NoError(t, err)
	assertAllRequestsExists(t, monitor, []*nethttp.Request{{URL: url, Method: "GET"}})
}

// TestEmptyConfig checks the test helper indeed returns a config with no
// protocols enable, by checking it prevents USM from running.
// If this test fails after enabling a protocol by default, you MUST NOT change
// this test, and instead update `NewUSMEmptyConfig` to make sure it disables the
// new protocol.
func TestEmptyConfig(t *testing.T) {
	cfg := utils.NewUSMEmptyConfig()
	require.True(t, cfg.ServiceMonitoringEnabled)

	// The monitor should not start, and not return an error when no protocols
	// are enabled.
	monitor, err := NewMonitor(cfg, nil)
	require.Nil(t, monitor)
	require.NoError(t, err)
}

func assertAllRequestsExists(t *testing.T, monitor *Monitor, requests []*nethttp.Request) {
	requestsExist := make([]bool, len(requests))

	assert.Eventually(t, func() bool {
		stats, obs := getHTTPLikeProtocolStatsObservations(monitor, protocols.HTTP)
		require.Equal(t, 0, len(obs))

		if len(stats) == 0 {
			return false
		}

		for reqIndex, req := range requests {
			if !requestsExist[reqIndex] {
				exists, err := isRequestIncludedOnce(stats, req)
				require.NoError(t, err)
				requestsExist[reqIndex] = exists
			}
		}

		// Slight optimization here, if one is missing, then go into another cycle of checking the new connections.
		// otherwise, if all present, abort.
		for _, exists := range requestsExist {
			if !exists {
				return false
			}
		}

		return true
	}, 3*time.Second, time.Millisecond*100, "connection not found")

	if t.Failed() {
		ebpftest.DumpMapsTestHelper(t, monitor.DumpMaps, "http_in_flight")

		for reqIndex, exists := range requestsExist {
			if !exists {
				// reqIndex is 0 based, while the number is requests[reqIndex] is 1 based.
				t.Logf("request %d was not found (req %v)", reqIndex+1, requests[reqIndex])
			}
		}
	}
}

func assertAllObservationsExists(t *testing.T, monitor *Monitor, requests []*nethttp.Request) {
	requestsExist := make([]bool, len(requests))

	assert.Eventually(t, func() bool {
		stats, obs := getHTTPLikeProtocolStatsObservations(monitor, protocols.HTTP)
		require.Equal(t, 0, len(stats))

		if len(obs) == 0 {
			return false
		}

		for reqIndex, req := range requests {
			if !requestsExist[reqIndex] {
				exists, err := isObservationIncludedOnce(obs, req)
				require.NoError(t, err)
				requestsExist[reqIndex] = exists
			}
		}

		// Slight optimization here, if one is missing, then go into another cycle of checking the new connections.
		// otherwise, if all present, abort.
		for _, exists := range requestsExist {
			if !exists {
				return false
			}
		}

		return true
	}, 3*time.Second, time.Millisecond*100, "connection not found")

	if t.Failed() {
		ebpftest.DumpMapsTestHelper(t, monitor.DumpMaps, "http_in_flight")

		for reqIndex, exists := range requestsExist {
			if !exists {
				// reqIndex is 0 based, while the number is requests[reqIndex] is 1 based.
				t.Logf("request %d was not found (req %v)", reqIndex+1, requests[reqIndex])
			}
		}
	}
}

var (
	// todo!: re-enable the TRACE method when we have the support for it eBPF side.
	httpMethods         = []string{nethttp.MethodGet, nethttp.MethodHead, nethttp.MethodPost, nethttp.MethodPut, nethttp.MethodPatch, nethttp.MethodDelete, nethttp.MethodOptions /*nethttp.MethodTrace*/}
	httpMethodsWithBody = []string{nethttp.MethodPost, nethttp.MethodPut, nethttp.MethodPatch, nethttp.MethodDelete}
	statusCodes         = []int{nethttp.StatusOK, nethttp.StatusMultipleChoices, nethttp.StatusBadRequest, nethttp.StatusInternalServerError}
)

func requestGenerator(t *testing.T, targetAddr string, requestId string, reqBody []byte) func() *nethttp.Request {
	var (
		random  = rand.New(rand.NewSource(time.Now().Unix()))
		idx     = 0
		client  = new(nethttp.Client)
		reqBuf  = make([]byte, 0, len(reqBody))
		respBuf = make([]byte, 512)
	)

	// Disabling http2
	tr := nethttp.DefaultTransport.(*nethttp.Transport).Clone()
	tr.ForceAttemptHTTP2 = false
	tr.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) nethttp.RoundTripper)

	client.Transport = tr

	return func() *nethttp.Request {
		idx++
		var method string
		var body io.Reader
		var finalBody []byte
		if len(reqBody) > 0 {
			finalBody = reqBuf[:0]
			finalBody = append(finalBody, []byte(strings.Repeat(" ", idx))...)
			finalBody = append(finalBody, reqBody...)
			body = bytes.NewReader(finalBody)

			// save resized-buffer
			reqBuf = finalBody

			method = httpMethodsWithBody[random.Intn(len(httpMethodsWithBody))]
		} else {
			method = httpMethods[random.Intn(len(httpMethods))]
		}
		status := statusCodes[random.Intn(len(statusCodes))]
		url := fmt.Sprintf("http://%s/%d/request-%d", targetAddr, status, idx)
		req, err := nethttp.NewRequest(method, url, body)
		if requestId != "" {
			if requestId == "random" {
				req.Header.Set("x-request-id", uuid.New().String())
			} else {
				req.Header.Set("x-request-id", requestId)
			}
		}
		require.NoError(t, err)

		resp, err := client.Do(req)
		if strings.Contains(targetAddr, "ignore") {
			return req
		}
		require.NoError(t, err)
		defer resp.Body.Close()
		if len(reqBody) > 0 {
			for {
				n, err := resp.Body.Read(respBuf)
				require.True(t, n <= len(finalBody))
				require.Equal(t, respBuf[:n], finalBody[:n])
				if err != nil {
					assert.Equal(t, io.EOF, err)
					break
				}
				finalBody = finalBody[n:]
			}
		}
		return req
	}
}

func checkRequestIncluded(t *testing.T, allStats map[http.Key]*http.RequestStats, req *nethttp.Request, expectedToBeIncluded bool) {
	included, err := isRequestIncludedOnce(allStats, req)
	require.NoError(t, err)
	if included != expectedToBeIncluded {
		t.Errorf(
			"%s not find HTTP transaction matching the following criteria:\n path=%s method=%s status=%d",
			testNameHelper("could", "should", expectedToBeIncluded),
			req.URL.Path,
			req.Method,
			testutil.StatusFromPath(req.URL.Path),
		)
	}
}

func isRequestIncludedOnce(allStats map[http.Key]*http.RequestStats, req *nethttp.Request) (bool, error) {
	occurrences := countRequestOccurrences(allStats, req)

	if occurrences == 1 {
		return true, nil
	} else if occurrences == 0 {
		return false, nil
	}
	return false, fmt.Errorf("expected to find 1 occurrence of %v, but found %d instead", req, occurrences)
}

func countRequestOccurrences(allStats map[http.Key]*http.RequestStats, req *nethttp.Request) int {
	expectedStatus := testutil.StatusFromPath(req.URL.Path)
	occurrences := 0
	for key, stats := range allStats {
		if key.Method.String() != req.Method {
			continue
		}
		if key.Path.Content.Get() != req.URL.Path {
			continue
		}
		if requests, exists := stats.Data[expectedStatus]; exists && requests.Count > 0 {
			occurrences++
		}
	}

	return occurrences
}

func newHTTPMonitorWithCfg(t *testing.T, cfg *config.Config) *Monitor {
	cfg.EnableHTTPMonitoring = true

	monitor, err := NewMonitor(cfg, nil)
	// skipIfNotSupported(t, err) keep it like it was before the sync
	require.NoError(t, err)

	// at this stage the test can be legitimately skipped due to missing BTF information
	// in the context of CO-RE
	require.NoError(t, monitor.Start())

	t.Cleanup(func() {
		monitor.Stop()
		libtelemetry.Clear()
	})
	return monitor
}

func skipIfNotSupported(t *testing.T, err error) {
	notSupported := new(errNotSupported)
	if errors.As(err, &notSupported) {
		t.Skipf("skipping test because this kernel is not supported: %s", notSupported)
	}
}

var (
	mapTypesToZero = map[ebpf.MapType]struct{}{
		ebpf.PerCPUArray: {},
		ebpf.Array:       {},
		ebpf.PerCPUHash:  {},
	}
)

func cleanProtocolMaps(t *testing.T, protocolName string, manager *manager.Manager) {
	// Getting all maps loaded into the manager
	maps, err := manager.GetMaps()
	if err != nil {
		t.Logf("failed to get maps: %v", err)
		return
	}
	for mapName, mapInstance := range maps {
		// We only want to clean postgres maps
		if !strings.Contains(mapName, protocolName) {
			continue
		}
		// Special case for batches, as the values is never "empty", but contain the CPU number.
		if strings.HasSuffix(mapName, fmt.Sprintf("%s_batches", protocolName)) {
			continue
		}
		_, shouldOnlyZero := mapTypesToZero[mapInstance.Type()]

		key := make([]byte, mapInstance.KeySize())
		value := make([]byte, mapInstance.ValueSize())
		mapEntries := mapInstance.Iterate()
		var keys [][]byte
		for mapEntries.Next(&key, &value) {
			keys = append(keys, key)
		}

		if shouldOnlyZero {
			emptyValue := make([]byte, mapInstance.ValueSize())
			for _, key := range keys {
				if err := mapInstance.Put(&key, &emptyValue); err != nil {
					t.Log("failed zeroing map entry; error: ", err)
				}
			}
		} else {
			for _, key := range keys {
				if err := mapInstance.Delete(&key); err != nil {
					t.Log("failed deleting map entry; error: ", err)
				}
			}
		}
	}
}

func isObservationIncludedOnce(allObservations []http.TransactionObservation, req *nethttp.Request) (bool, error) {
	occurrences := countObservationOccurrences(allObservations, req)

	if occurrences == 1 {
		return true, nil
	} else if occurrences == 0 {
		return false, nil
	}
	return false, fmt.Errorf("expected to find 1 occurrence of %v, but found %d instead", req, occurrences)
}

func countObservationOccurrences(allObservations []http.TransactionObservation, req *nethttp.Request) int {
	expectedStatus := testutil.StatusFromPath(req.URL.Path)
	occurrences := 0
	netNs, err := kernel.GetCurrentIno()
	if err != nil {
		return 0
	}

	for _, observation := range allObservations {
		if observation.Key.NetNs == netNs && observation.Key.Path.Content.Get() == req.URL.Path && observation.Status == expectedStatus && req.Header.Get("X-Request-ID") == observation.TraceId.Id && observation.TraceId.Type == http.TraceIdRequest {
			occurrences++
		}
	}

	return occurrences
}
