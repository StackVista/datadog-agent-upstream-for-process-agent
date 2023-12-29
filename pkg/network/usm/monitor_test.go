// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package usm

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/google/uuid"
	"io"
	"math/rand"
	"net"
	nethttp "net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cihub/seelog"
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
	"github.com/DataDog/datadog-agent/pkg/network/tracer/testutil/grpc"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	testutil2 "github.com/DataDog/datadog-agent/pkg/util/testutil"
)

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

			cfg := config.New()
			cfg.EnableHTTPMonitoring = true
			monitor, err := NewMonitor(cfg, nil, nil)
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
	ebpftest.TestBuildModes(t, []ebpftest.BuildMode{ebpftest.Prebuilt, ebpftest.RuntimeCompiled /* STS edit:, ebpftest.CORE */}, "", func(t *testing.T) {
		suite.Run(t, new(HTTPTestSuite))
	})
}

func (s *HTTPTestSuite) TestHTTPStats() {
	t := s.T()

	testCases := []struct {
		name                  string
		aggregateByStatusCode bool
	}{
		{name: "without TCP timestamp option", value: false},
		{name: "with TCP timestamp option", value: true},
	} {
		t.Run(TCPTimestamp.name, func(t *testing.T) {

			monitor := newHTTPMonitor(t, testutil.Options{})

			serverAddr := "localhost:8081"
			srvDoneFn := testutil.HTTPServer(t, serverAddr, testutil.Options{
				EnableKeepAlive: true,
			})
			t.Cleanup(srvDoneFn)

			cfg := config.New()
			cfg.EnableHTTPStatsByStatusCode = tt.aggregateByStatusCode
			monitor := newHTTPMonitorWithCfg(t, cfg)

			resp, err := nethttp.Get(fmt.Sprintf("http://%s/%d/test", serverAddr, nethttp.StatusNoContent))
			require.NoError(t, err)

			expectedOccurrences := 10
			for i := 0; i < expectedOccurrences; i++ {
				resp, err := client.Do(req)
				require.NoError(t, err)
				// Have to read the response body to ensure the client will be able to properly close the connection.
				io.ReadAll(resp.Body)
				resp.Body.Close()
			}
			srvDoneFn()

			occurrences := 0
			require.Eventually(t, func() bool {
				stats := getHttpStats(t, monitor)
				occurrences += countRequestOccurrences(stats, req)
				return occurrences == expectedOccurrences
			}, time.Second*3, time.Millisecond*100, "Expected to find a request %d times, instead captured %d", occurrences, expectedOccurrences)
		})
	}
}

// TestHTTPMonitorLoadWithIncompleteBuffers sends thousands of requests without getting responses for them, in parallel
// we send another request. We expect to capture the another request but not the incomplete requests.
func (s *HTTPTestSuite) TestHTTPMonitorLoadWithIncompleteBuffers() {
	t := s.T()

	slowServerAddr := "localhost:8080"
	fastServerAddr := "localhost:8081"

	monitor := newHTTPMonitor(t, testutil.Options{})
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

// TestHTTPMonitorInstructionCounts puts a cap on the amount of instructions for the ebpf probe
// We want to be aware of the amount of instructions we add to the verifier with our changes to
// not hit the limit too quickly.
func (s *HTTPTestSuite) TestHTTPMonitorInstructionCounts() {
	t := s.T()

	monitor := newHTTPMonitor(t, testutil.Options{})

	programs, err := monitor.ebpfProgram.GetPrograms()
	require.NoError(t, err)

	maxCounts := map[string]int{
		"uprobe__SSL_write":                     15,
		"uprobe__SSL_set_bio":                   34,
		"uprobe__crypto_tls_Conn_Close":         1767,
		"uretprobe__gnutls_record_recv":         1485,
		"uretprobe__SSL_write_ex":               1503,
		"socket__http_filter":                   250000,
		"uprobe__SSL_set_fd":                    21,
		"uprobe__SSL_do_handshake":              14,
		"uretprobe__gnutls_handshake":           8,
		"uprobe__http_process":                  104448,
		"uprobe__crypto_tls_Conn_Read":          628,
		"uretprobe__SSL_connect":                8,
		"uprobe__gnutls_transport_set_ptr2":     21,
		"uprobe__crypto_tls_Conn_Write":         765,
		"uprobe__gnutls_handshake":              14,
		"uprobe__BIO_new_socket":                14,
		"uprobe__http_termination":              460,
		"uprobe__SSL_read":                      15,
		"uprobe__SSL_shutdown":                  1189,
		"kprobe__tcp_sendmsg":                   1027,
		"uretprobe__SSL_write":                  1489,
		"uprobe__SSL_read_ex":                   17,
		"uprobe__gnutls_deinit":                 1189,
		"uprobe__SSL_write_ex":                  17,
		"uprobe__gnutls_transport_set_ptr":      21,
		"uprobe__crypto_tls_Conn_Write__return": 2072,
		"uprobe__gnutls_bye":                    1189,
		"uretprobe__gnutls_record_send":         1485,
		"tracepoint__net__netif_receive_skb":    255,
		"uretprobe__SSL_do_handshake":           8,
		"uretprobe__SSL_read":                   1489,
		"socket__protocol_dispatcher":           2267,
		"socket__http2_frames_parser":           92402,
		"uprobe__gnutls_record_recv":            15,
		"uprobe__gnutls_record_send":            15,
		"uprobe__SSL_connect":                   14,
		"uprobe__crypto_tls_Conn_Read__return":  1982,
		"uretprobe__SSL_read_ex":                1503,
		"uprobe__gnutls_transport_set_int2":     21,
		"socket__http2_filter":                  698269,
		"uretprobe__BIO_new_socket":             29,
	}

	for name, p := range programs {
		limit, ok := maxCounts[name]
		require.True(t, ok, fmt.Sprintf("Max instruction entry for %s is missing", name))
		r, err := regexp.Compile("processed ([0-9]+) insns")
		require.NoError(t, err)
		match := r.FindStringSubmatch(p.VerifierLog)
		insns, err := strconv.Atoi(match[1])
		require.NoError(t, err)
		require.LessOrEqual(t, insns, limit, name)
	}
}

func (s *HTTPTestSuite) TestHTTPMonitorIntegrationWithResponseBody() {
	t := s.T()
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
			monitor := newHTTPMonitor(t, testutil.Options{})
			srvDoneFn := testutil.HTTPServer(t, serverAddr, testutil.Options{
				EnableKeepAlive: true,
			})
			t.Cleanup(srvDoneFn)

			requestFn := requestGenerator(t, targetAddr, "", bytes.Repeat([]byte("a"), tt.requestBodySize))
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
	}{
		{
			name:                         "response reaching after cleanup",
			mapCleanerIntervalSeconds:    1,
			httpIdleConnectionTTLSeconds: 1,
			slowResponseTime:             3,
			shouldCapture:                false,
		},
		{
			name:                         "response reaching before cleanup",
			mapCleanerIntervalSeconds:    1,
			httpIdleConnectionTTLSeconds: 3,
			slowResponseTime:             1,
			shouldCapture:                true,
		},
		{
			name:                         "slow response reaching after ttl but cleaner not running",
			mapCleanerIntervalSeconds:    3,
			httpIdleConnectionTTLSeconds: 1,
			slowResponseTime:             2,
			shouldCapture:                true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config.ResetSystemProbeConfig(t)
			t.Setenv("DD_SERVICE_MONITORING_CONFIG_HTTP_MAP_CLEANER_INTERVAL_IN_S", strconv.Itoa(tt.mapCleanerIntervalSeconds))
			t.Setenv("DD_SERVICE_MONITORING_CONFIG_HTTP_IDLE_CONNECTION_TTL_IN_S", strconv.Itoa(tt.httpIdleConnectionTTLSeconds))
			monitor := newHTTPMonitor(t, testutil.Options{})

			slowResponseTimeout := time.Duration(tt.slowResponseTime) * time.Second
			serverTimeout := slowResponseTimeout + time.Second
			srvDoneFn := testutil.HTTPServer(t, serverAddr, testutil.Options{
				WriteTimeout: serverTimeout,
				ReadTimeout:  serverTimeout,
				SlowResponse: slowResponseTimeout,
			})
			t.Cleanup(srvDoneFn)

			// Perform a number of random requests
			req := requestGenerator(t, targetAddr, "", emptyBody)()
			srvDoneFn()

			// Ensure all captured transactions get sent to user-space
			time.Sleep(10 * time.Millisecond)
			stats := getHttpStats(t, monitor)

			if tt.shouldCapture {
				includesRequest(t, stats, req)
			} else {
				requestNotIncluded(t, stats, req)
			}
		})
	}
}

func (s *HTTPTestSuite) TestHTTPMonitorIntegration() {
	t := s.T()
	targetAddr := "localhost:8080"
	serverAddr := "localhost:8080"

	t.Run("with keep-alives", func(t *testing.T) {
		testHTTPMonitor(t, targetAddr, serverAddr, 100, testutil.Options{
			EnableKeepAlive: true,
		})
	})
	t.Run("without keep-alives", func(t *testing.T) {
		testHTTPMonitor(t, targetAddr, serverAddr, 100, testutil.Options{
			EnableKeepAlive: false,
		})
	})
}

func (s *HTTPTestSuite) TestHTTPMonitorRequestId() {
	t := s.T()

	targetAddr := "localhost:8080"
	serverAddr := "localhost:8080"

	t.Run("with keep-alives", func(t *testing.T) {
		testHTTPMonitor(t, targetAddr, serverAddr, 1, testutil.Options{
			EnableHttpTracing: true,
			RequestTraceId:    "random",
			EnableKeepAlive:   true,
		})
	})
	t.Run("without keep-alives", func(t *testing.T) {
		testHTTPMonitor(t, targetAddr, serverAddr, 1, testutil.Options{
			EnableHttpTracing: true,
			RequestTraceId:    "random",
			EnableKeepAlive:   false,
		})
	})
}

func (s *HTTPTestSuite) TestHTTPMonitorResponseId() {
	t := s.T()
	targetAddr := "localhost:8080"
	serverAddr := "localhost:8080"
	traceId := "672aef67-566f-4206-8da1-d8c11c80585c"

	monitor, _ := runHTTPMonitor(t, targetAddr, serverAddr, 1, testutil.Options{
		EnableHttpTracing: true,
		RequestTraceId:    "",
		ResponseTraceId:   traceId,
		EnableKeepAlive:   false,
	})

	stats, observations := getAllStats(t, monitor)
	require.Equal(t, 0, len(stats))
	require.Equal(t, 1, len(observations))

	require.Equal(t, http.TransactionTraceId{
		Type: http.TraceIdResponse,
		Id:   traceId,
	}, observations[0].TraceId)
}

func (s *HTTPTestSuite) TestHTTPMonitorBothId() {
	t := s.T()
	targetAddr := "localhost:8080"
	serverAddr := "localhost:8080"
	traceId := "672aef67-566f-4206-8da1-d8c11c80585c"

	monitor, _ := runHTTPMonitor(t, targetAddr, serverAddr, 1, testutil.Options{
		EnableHttpTracing: true,
		RequestTraceId:    traceId,
		ResponseTraceId:   traceId,
		EnableKeepAlive:   false,
	})

	stats, observations := getAllStats(t, monitor)
	require.Equal(t, 0, len(stats))
	require.Equal(t, 1, len(observations))

	require.Equal(t, http.TransactionTraceId{
		Type: http.TraceIdBoth,
		Id:   traceId,
	}, observations[0].TraceId)
}

func (s *HTTPTestSuite) TestHTTPMonitorAmbiguousId() {
	t := s.T()
	targetAddr := "localhost:8080"
	serverAddr := "localhost:8080"
	traceId := "672aef67-566f-4206-8da1-d8c11c80585c"

	monitor, _ := runHTTPMonitor(t, targetAddr, serverAddr, 1, testutil.Options{
		EnableHttpTracing: true,
		RequestTraceId:    "random",
		ResponseTraceId:   traceId,
		EnableKeepAlive:   false,
	})

	stats, observations := getAllStats(t, monitor)
	require.Equal(t, 0, len(stats))
	require.Equal(t, 1, len(observations))

	require.Equal(t, http.TransactionTraceId{
		Type: http.TraceIdAmbiguous,
		Id:   "",
	}, observations[0].TraceId)
}

func (s *HTTPTestSuite) TestHTTPMonitorIntegrationWithNAT() {
	t := s.T()
	testutil2.SkipIfStackState(t, "Not running dnat test where iptables cannot be ran")

	// SetupDNAT sets up a NAT translation from 2.2.2.2 to 1.1.1.1
	netlink.SetupDNAT(t)

	targetAddr := "2.2.2.2:8080"
	serverAddr := "1.1.1.1:8080"

	t.Run("with keep-alives", func(t *testing.T) {
		testHTTPMonitor(t, targetAddr, serverAddr, 100, testutil.Options{
			EnableKeepAlive: true,
		})
	})
	t.Run("without keep-alives", func(t *testing.T) {
		testHTTPMonitor(t, targetAddr, serverAddr, 100, testutil.Options{
			EnableKeepAlive: false,
		})
	})
}

func (s *HTTPTestSuite) TestUnknownMethodRegression() {
	t := s.T()
	testutil2.SkipIfStackState(t, "Not running dnat test where iptables cannot be ran")

	// SetupDNAT sets up a NAT translation from 2.2.2.2 to 1.1.1.1
	netlink.SetupDNAT(t)

	monitor := newHTTPMonitor(t, testutil.Options{})
	targetAddr := "2.2.2.2:8080"
	serverAddr := "1.1.1.1:8080"
	serverAddrIP := util.AddressFromString("1.1.1.1")
	srvDoneFn := testutil.HTTPServer(t, serverAddr, testutil.Options{
		EnableTLS:       false,
		EnableKeepAlive: true,
	})
	t.Cleanup(srvDoneFn)

	requestFn := requestGenerator(t, targetAddr, "", emptyBody)
	for i := 0; i < 100; i++ {
		requestFn()
	}

	time.Sleep(5 * time.Second)
	stats := getHttpStats(t, monitor)
	tel := telemetry.ReportPayloadTelemetry("1")
	requestsSum := 0

	for key := range stats {
		if key.Method == http.MethodUnknown {
			t.Error("detected HTTP request with method unknown")
		}
		// we just want our requests
		if strings.Contains(key.Path.Content.Get(), "/request-") &&
			key.DstPort == 8080 &&
			util.FromLowHigh(key.DstIPLow, key.DstIPHigh) == serverAddrIP {
			requestsSum++
		}
	}

	require.Equal(t, int64(0), tel["usm.http.dropped"])
	require.Equal(t, int64(0), tel["usm.http.rejected"])
	require.Equal(t, int64(0), tel["usm.http.malformed"])
	// requestGenerator() doesn't query 100 responses
	require.Equal(t, int64(0), tel["usm.http.hits1XX"])

	require.Equal(t, int(100), requestsSum)
}

func (s *HTTPTestSuite) TestRSTPacketRegression() {
	t := s.T()

	monitor := newHTTPMonitor(t, testutil.Options{})

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
	checkRequestIncluded(t, stats, &nethttp.Request{URL: url}, true)
}

// TestKeepAliveWithIncompleteResponseRegression checks that USM captures a request, although we initially saw a
// response and then a request with its response.
func (s *HTTPTestSuite) TestKeepAliveWithIncompleteResponseRegression() {
	t := s.T()

	monitor := newHTTPMonitor(t, testutil.Options{})

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

func assertAllRequestsExists(t *testing.T, monitor *Monitor, requests []*nethttp.Request) {
	requestsExist := make([]bool, len(requests))

	assert.Eventually(t, func() bool {
		stats := getHTTPLikeProtocolStats(monitor, protocols.HTTP)

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
				}, time.Second*5, time.Millisecond*100, "%v != %v", res, tt.expectedEndpoints)
			})
		}
	}
}

func getClientsArray(t *testing.T, size int, options grpc.Options) []*nethttp.Client {
	t.Helper()

	res := make([]*nethttp.Client, size)
	for i := 0; i < size; i++ {
		res[i] = newH2CClient(t)
	}

	return res
}

func startH2CServer(t *testing.T) {
	t.Helper()

	srv := &nethttp.Server{
		Addr: http2SrvPortStr,
		Handler: h2c.NewHandler(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.WriteHeader(200)
			w.Write([]byte("test"))
		}), &http2.Server{}),
		IdleTimeout: 2 * time.Second,
	}

	err := http2.ConfigureServer(srv, nil)
	require.NoError(t, err)

	l, err := net.Listen("tcp", http2SrvPortStr)
	require.NoError(t, err, "could not create listening socket")

	go func() {
		srv.Serve(l)
		require.NoErrorf(t, err, "could not start HTTP2 server")
	}()

	t.Cleanup(func() { srv.Close() })
}

func newH2CClient(t *testing.T) *nethttp.Client {
	t.Helper()

	client := &nethttp.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		},
	}

	return client
}

func getClientsIndex(index, totalCount int) int {
	return index % totalCount
}

func assertAllRequestsExists(t *testing.T, monitor *Monitor, requests []*nethttp.Request) {
	requestsExist := make([]bool, len(requests))
	for i := 0; i < 10; i++ {
		time.Sleep(10 * time.Millisecond)
		stats, observations := getAllStats(t, monitor)
		require.Equal(t, 0, len(observations))
		for reqIndex, req := range requests {
			included, err := isRequestIncludedOnce(stats, req)
			require.NoError(t, err)
			requestsExist[reqIndex] = requestsExist[reqIndex] || included
		}
		if allTrue(requestsExist) {
			return
		}
	}

	for reqIndex, exists := range requestsExist {
		require.Truef(t, exists, "request %d was not found (req %v)", reqIndex, requests[reqIndex])
	}
}

func assertAllObservationsExists(t *testing.T, monitor *Monitor, requests []*nethttp.Request) {
	requestsExist := make([]bool, len(requests))
	for i := 0; i < 10; i++ {
		time.Sleep(10 * time.Millisecond)
		stats, observations := getAllStats(t, monitor)
		require.Equal(t, 0, len(stats))
		for reqIndex, req := range requests {
			included, err := isObservationIncludedOnce(observations, req)
			require.NoError(t, err)
			requestsExist[reqIndex] = requestsExist[reqIndex] || included
		}
	}

	for reqIndex, exists := range requestsExist {
		require.Truef(t, exists, "request %d was not found (req %v)", reqIndex, requests[reqIndex])
	}
}

func allTrue(x []bool) bool {
	for _, v := range x {
		if !v {
			return false
		}
	}
	return true
}

func testHTTPMonitor(t *testing.T, targetAddr, serverAddr string, numReqs int, o testutil.Options) {
	monitor, requests := runHTTPMonitor(t, targetAddr, serverAddr, numReqs, o)

	// Ensure all captured transactions get sent to user-space
	if o.EnableHttpTracing {
		assertAllObservationsExists(t, monitor, requests)
	} else {
		assertAllRequestsExists(t, monitor, requests)
	}
}

func runHTTPMonitor(t *testing.T, targetAddr, serverAddr string, numReqs int, o testutil.Options) (*Monitor, []*nethttp.Request) {
	monitor := newHTTPMonitor(t, o)
	srvDoneFn := testutil.HTTPServer(t, serverAddr, o)

	// Perform a number of random requests
	requestFn := requestGenerator(t, targetAddr, o.RequestTraceId, emptyBody)
	var requests []*nethttp.Request
	for i := 0; i < numReqs; i++ {
		requests = append(requests, requestFn())
	}
	srvDoneFn()

	return monitor, requests
}

var (
	httpMethods         = []string{nethttp.MethodGet, nethttp.MethodHead, nethttp.MethodPost, nethttp.MethodPut, nethttp.MethodPatch, nethttp.MethodDelete, nethttp.MethodOptions}
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

func getAllStats(t *testing.T, mon *Monitor) (map[http.Key]*http.RequestStats, []http.TransactionObservation) {
	t.Helper()

	allStats := mon.GetProtocolStats()
	require.NotNil(t, allStats)

	httpStats, ok := allStats[protocols.HTTP]
	require.True(t, ok)

	allHttpStats := httpStats.(http.AllHttpStats)
	return allHttpStats.RequestStats, allHttpStats.Observations
}

func getHttpStats(t *testing.T, mon *Monitor) map[http.Key]*http.RequestStats {
	t.Helper()

	allStats := mon.GetProtocolStats()
	require.NotNil(t, allStats)

	httpStats, ok := allStats[protocols.HTTP]
	require.True(t, ok)

	return httpStats.(http.AllHttpStats).RequestStats
}

func getHttpObservations(t *testing.T, mon *Monitor) []http.TransactionObservation {
	t.Helper()

	allStats := mon.GetProtocolStats()
	require.NotNil(t, allStats)

	httpStats, ok := allStats[protocols.HTTP]
	require.True(t, ok)

	return httpStats.(http.AllHttpStats).Observations
}

func countRequestOccurrences(allStats map[http.Key]*http.RequestStats, req *nethttp.Request) int {
	expectedStatus := testutil.StatusFromPath(req.URL.Path)
	occurrences := 0
	for key, stats := range allStats {
		if key.Path.Content.Get() != req.URL.Path {
			continue
		}
		if requests, exists := stats.Data[expectedStatus]; exists && requests.Count > 0 {
			occurrences++
		}
	}

	return occurrences
}

func newHTTPMonitor(t *testing.T, o testutil.Options) *Monitor {
	cfg := networkconfig.New()
	cfg.EnableHTTPMonitoring = true
	cfg.EnableHTTPTracing = o.EnableHttpTracing

	monitor, err := NewMonitor(cfg, nil, nil, nil)
	require.NoError(t, err)

	// at this stage the test can be legitimately skipped due to missing BTF information
	// in the context of CO-RE
	err = monitor.Start()
	require.NoError(t, err)

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
