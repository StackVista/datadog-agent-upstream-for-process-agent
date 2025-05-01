// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package usm

import (
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/DataDog/datadog-agent/pkg/ebpf/ebpftest"
	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/protocols"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/http/testutil"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/postgres"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/postgres/ebpf"
	protocolsUtils "github.com/DataDog/datadog-agent/pkg/network/protocols/testutil"
	gotlstestutil "github.com/DataDog/datadog-agent/pkg/network/protocols/tls/gotls/testutil"
	"github.com/DataDog/datadog-agent/pkg/network/usm/consts"
	"github.com/DataDog/datadog-agent/pkg/network/usm/utils"
	stsutil "github.com/DataDog/datadog-agent/pkg/util/testutil"
)

const (
	postgresPort             = "5432"
	createTableQuery         = "CREATE TABLE dummy (id SERIAL PRIMARY KEY, foo TEXT)"
	updateSingleValueQuery   = "UPDATE dummy SET foo = 'updated' WHERE id = 1"
	selectAllQuery           = "SELECT * FROM dummy"
	selectParameterizedQuery = "SELECT * FROM dummy WHERE foo = $1"
	dropTableQuery           = "DROP TABLE IF EXISTS dummy"
	deleteTableQuery         = "DELETE FROM dummy WHERE id = 1"
	alterTableQuery          = "ALTER TABLE dummy ADD test VARCHAR(255);"
	truncateTableQuery       = "TRUNCATE TABLE dummy"
	showQuery                = "SHOW search_path"
)

var (
	longCreateQuery = fmt.Sprintf("CREATE TABLE %s (id SERIAL PRIMARY KEY, foo TEXT)", strings.Repeat("a", ebpf.BufferSize))
	longDropQuery   = fmt.Sprintf("DROP TABLE IF EXISTS %s", strings.Repeat("a", ebpf.BufferSize))
)

func createInsertQuery(values ...string) string {
	return fmt.Sprintf("INSERT INTO dummy (foo) VALUES ('%s')", strings.Join(values, "'), ('"))
}

func generateTestValues(startingIndex, count int) []string {
	values := make([]string, count)
	for i := 0; i < count; i++ {
		values[i] = fmt.Sprintf("value-%d", startingIndex+i)
	}
	return values
}

func generateSelectLimitQuery(limit int) string {
	return fmt.Sprintf("SELECT * FROM dummy limit %d", limit)
}

// pgTestContext shares the context of a given test.
// It contains common variable used by all tests, and allows extending the context dynamically by setting more
// attributes to the `extras` map.
type pgTestContext struct {
	// The address of the server to listen on.
	serverAddress string
	// The port to listen on.
	serverPort string
	// The address for the client to communicate with.
	targetAddress string
	// A dynamic map that allows extending the context easily between phases of the test.
	extras map[string]interface{}
}

// postgresParsingTestAttributes holds all attributes a single postgres parsing test should have.
type postgresParsingTestAttributes struct {
	// The name of the test.
	name string
	// Specific test context, allows to share states among different phases of the test.
	context pgTestContext
	// Allows to do any preparation without traffic being captured by the monitor.
	preMonitorSetup func(t *testing.T, ctx pgTestContext)
	// All traffic here will be captured by the monitor.
	postMonitorSetup func(t *testing.T, ctx pgTestContext)
	// A validation method ensure the test succeeded.
	validation func(t *testing.T, ctx pgTestContext, tr *Monitor)
	// Reason to skip the test
	skipReason string
}

type postgresProtocolParsingSuite struct {
	suite.Suite
}

func TestPostgresMonitoring(t *testing.T) {
	skipTestIfKernelNotSupported(t)
	ebpftest.TestBuildModes(t, stsutil.OnlyPrebuiltModeIfSelected(), "", func(t *testing.T) {
		suite.Run(t, new(postgresProtocolParsingSuite))
	})
}

func (s *postgresProtocolParsingSuite) TestLoadPostgresBinary() {
	t := s.T()
	for name, debug := range map[string]bool{"enabled": true, "disabled": false} {
		t.Run(name, func(t *testing.T) {
			cfg := getPostgresDefaultTestConfiguration(protocolsUtils.TLSDisabled)
			cfg.BPFDebug = debug
			setupUSMTLSMonitor(t, cfg)
		})
	}
}

func (s *postgresProtocolParsingSuite) TestDecoding() {
	t := s.T()

	tests := []struct {
		name  string
		isTLS bool
	}{
		{
			name:  "with TLS",
			isTLS: true,
		},
		{
			name:  "without TLS",
			isTLS: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.isTLS && !gotlstestutil.GoTLSSupported(t, utils.NewUSMEmptyConfig()) {
				t.Skip("GoTLS not supported for this setup")
			}
			testDecoding(t, tt.isTLS)
		})
	}
}

// Please note that the "ping" usage in the pgx library. This is not a postgres thing.
// "if it is elapsed more than 1 sec from the last postgres message on the connection the library pings the server before doing the real query"
// A ping is equivalent to an empty SQL query with body "-- ping".
// 127.0.0.1|>Q|127.0.0.1|12|-- ping
// 127.0.0.1|<I/Z|127.0.0.1|4,5|
func (s *postgresProtocolParsingSuite) TestPostgresPlaintextQuery() {
	t := s.T()

	isTLS := false
	serverHost := "127.0.0.1"
	serverAddress := net.JoinHostPort(serverHost, postgresPort)

	// Create and Wait for the server
	require.NoError(t, postgres.RunServer(t, serverHost, postgresPort, isTLS))
	waitForPostgresServer(t, serverAddress, isTLS)

	// Create a new client and ping
	pg, err := postgres.NewPGXClient(postgres.ConnectionOptions{
		ServerAddress: serverAddress,
		EnableTLS:     isTLS,
	})
	require.NoError(t, err)

	// Start monitor
	monitor := setupUSMTLSMonitor(t, getPostgresDefaultTestConfiguration(isTLS))

	// We create a table with a simple query.
	// tshark output:
	//
	// 127.0.0.1|>Q|127.0.0.1|57|CREATE TABLE dummy (id SERIAL PRIMARY KEY, foo TEXT)
	// 127.0.0.1|<C/Z|127.0.0.1|17,5|
	//
	// Our instrumentation:
	//
	// [POSTGRES]: Query: ifx 1, type 4, tcp_seq 901465898, netns 4026531840, sport 57790, dport 5432
	// [POSTGRES]: Store transaction: tcp_seq 901465898, netns 4026531840, query: CREATE TABLE dummy (id SERIAL PRIMARY KEY, foo TEXT)
	// [POSTGRES]: Query: ifx 204, type 4, tcp_seq 1639342837, netns 4026531840, sport 53678, dport 5432
	// [POSTGRES]: Store transaction: tcp_seq 1639342837, netns 4026531840, query: CREATE TABLE dummy (id SERIAL PRIMARY KEY, foo TEXT)
	// [POSTGRES]: Query: ifx 2, type 0, tcp_seq 1639342837, netns 4026533550, sport 53678, dport 5432
	// [POSTGRES]: Store transaction: tcp_seq 1639342837, netns 4026533550, query: CREATE TABLE dummy (id SERIAL PRIMARY KEY, foo TEXT)
	// [POSTGRES]: Not Q/P: ifx 2, type 4, tcp_seq 4186652565, netns 4026533550, sport 5432, dport 53678
	// [POSTGRES]: Complete: tcp_seq 4186652565, netns 4026533550, sport 53678, dport 5432
	// [POSTGRES]: Not Q/P: ifx 205, type 3, tcp_seq 4186652565, netns 4026531840, sport 5432, dport 53678
	// [POSTGRES]: Complete: tcp_seq 4186652565, netns 4026531840, sport 53678, dport 5432
	// [POSTGRES]: Not Q/P: ifx 1, type 4, tcp_seq 1490311863, netns 4026531840, sport 5432, dport 57790
	// [POSTGRES]: Complete: tcp_seq 1490311863, netns 4026531840, sport 57790, dport 5432
	require.NoError(t, pg.RunSimpleQuery(createTableQuery))
	require.NoError(t, monitor.Pause())

	validatePostgres(t, monitor, map[string]map[postgres.Operation]int{
		"dummy": {
			// As you can see we store the same SQL query under 3 different views.
			// 1. From the client (our docker running in the root ns) to the docker-proxy through the loopback interface (ifx 1)
			// 2. From the docker-proxy to the postgres server through the docker-br interface (ifx 204). Always in the root ns.
			// 3. From the docker-proxy to the postgres server through the veth interface (ifx 205) inside the docker network ns.
			// At the same way we see 3 different view of the same response and so we send 3 transactions for the same query in userspace.
			postgres.CreateTableOP: 3,
		},
	}, isTLS)
}

func (s *postgresProtocolParsingSuite) TestPostgresPlaintextExtendedQuery() {
	t := s.T()

	isTLS := false
	serverHost := "127.0.0.1"
	serverAddress := net.JoinHostPort(serverHost, postgresPort)

	// Create and Wait for the server
	require.NoError(t, postgres.RunServer(t, serverHost, postgresPort, isTLS))
	waitForPostgresServer(t, serverAddress, isTLS)

	// Create a new client and ping it
	pg, err := postgres.NewPGXClient(postgres.ConnectionOptions{
		ServerAddress: serverAddress,
		EnableTLS:     isTLS,
	})
	require.NoError(t, err)

	// Under the hood the pgx client uses the extended query protocol.
	// So with this CREATE we first send a parse (P) and then a bind (B).
	// tshark output:
	//
	// This is a ping the library does under the hood to check if the server is still here.
	// 127.0.0.1 → 127.0.0.1    PGSQL 79 >Q
	// 127.0.0.1 → 127.0.0.1    PGSQL 77 <I/Z
	//
	// This is the CREATE query we are sending.
	// 127.0.0.1 → 127.0.0.1    PGSQL 255 >P/D/S
	// 127.0.0.1 → 127.0.0.1    PGSQL 89 <1/t/n/Z
	// 127.0.0.1 → 127.0.0.1    PGSQL 159 >B/D/E/S
	// 127.0.0.1 → 127.0.0.1    PGSQL 100 <2/n/C/Z
	require.NoError(t, pg.RunQuery(createTableQuery))

	// Now we do the same for the SELECT query.
	// We want to send the prepared statement here so that when we start the monitor we will see just the bind (B) and the execute (E).
	// tshark output:
	// 127.0.0.1 → 127.0.0.1    PGSQL 224 >P/D/S
	// 127.0.0.1 → 127.0.0.1    PGSQL 136 <1/t/T/Z
	// 127.0.0.1 → 127.0.0.1    PGSQL 165 >B/D/E/S
	// 127.0.0.1 → 127.0.0.1    PGSQL 143 <2/T/C/Z
	require.NoError(t, pg.RunQuery(selectAllQuery))

	// Start monitor
	monitor := setupUSMTLSMonitor(t, getPostgresDefaultTestConfiguration(isTLS))

	// We just started the monitor so we are still not aware of the postgres connection.
	// We send a first select that is equivalent to:
	//
	//  127.0.0.1 → 127.0.0.1    PGSQL 163 >B/D/E/S
	//  127.0.0.1 → 127.0.0.1    PGSQL 141 <2/T/C/Z
	//
	// in this way our ebpf instrumentation will see the bind complete `2` and
	// will associate this connection with the postgres protocol but we won't see the
	// transaction because we recognize the postgres protocol too late. We will
	// just see the bind complete but we are not able to associate it with any query.
	//
	// [POSTGRES]: Not Q/P: ifx 2, type 4, tcp_seq 2615490508, netns 4026534129, sport 5432, dport 59846
	// [POSTGRES]: Not Q/P: ifx 53, type 3, tcp_seq 2615490508, netns 4026531840, sport 5432, dport 59846
	// [POSTGRES]: Not Q/P: ifx 1, type 4, tcp_seq 1135662846, netns 4026531840, sport 5432, dport 35448
	require.NoError(t, pg.RunQuery(selectAllQuery))

	// Now we do it again and we should see the transaction this time.
	// tshark output:
	//
	//  127.0.0.1 → 127.0.0.1    PGSQL 163 >B/D/E/S
	//  127.0.0.1 → 127.0.0.1    PGSQL 141 <2/T/C/Z
	//
	// Our ebpf instrumentation output:
	//
	// [POSTGRES]: Bind: ifx 1, type 4, tcp_seq 772238126, netns 4026531840, sport 33604, dport 5432
	// [POSTGRES]: Bind: ifx 52, type 4, tcp_seq 2702627933, netns 4026531840, sport 41926, dport 5432
	// [POSTGRES]: Bind: ifx 2, type 0, tcp_seq 2702627933, netns 4026534129, sport 41926, dport 5432
	// [POSTGRES]: Not Q/P: ifx 2, type 4, tcp_seq 3076461883, netns 4026534129, sport 5432, dport 41926
	// [POSTGRES]: Complete: tcp_seq 3076461883, netns 4026534129, sport 41926, dport 5432
	// [POSTGRES]: Not Q/P: ifx 53, type 3, tcp_seq 3076461883, netns 4026531840, sport 5432, dport 41926
	// [POSTGRES]: Complete: tcp_seq 3076461883, netns 4026531840, sport 41926, dport 5432
	// [POSTGRES]: Not Q/P: ifx 1, type 4, tcp_seq 2260673675, netns 4026531840, sport 5432, dport 33604
	// [POSTGRES]: Complete: tcp_seq 2260673675, netns 4026531840, sport 33604, dport 5432
	require.NoError(t, pg.RunQuery(selectAllQuery))

	// We send a second select that is equivalent and this time we should correctly recognize the postgres transaction:
	require.NoError(t, monitor.Pause())

	// We cannot recover the operation and the table name from the ebpf instrumentation because we don't see the initial parse
	validatePostgres(t, monitor, map[string]map[postgres.Operation]int{
		"": {
			postgres.UnknownOP: 3,
		},
	}, isTLS)
}

func (s *postgresProtocolParsingSuite) TestPostgresDatabaseName() {
	t := s.T()

	isTLS := false
	serverHost := "127.0.0.1"
	serverAddress := net.JoinHostPort(serverHost, postgresPort)

	// Create and Wait for the server
	require.NoError(t, postgres.RunServer(t, serverHost, postgresPort, isTLS))
	waitForPostgresServer(t, serverAddress, isTLS)

	// Start monitor
	monitor := setupUSMTLSMonitor(t, getPostgresDefaultTestConfiguration(isTLS))

	// Create a new client and ping it, so we start a postgres connection
	pg, err := postgres.NewPGXClient(postgres.ConnectionOptions{
		ServerAddress: serverAddress,
		EnableTLS:     isTLS,
	})
	require.NoError(t, err)

	require.NoError(t, pg.RunSimpleQuery(createTableQuery))

	// Call getstats so that we clear all the batches and we should process the startup message with the database name
	monitor.GetProtocolStats()

	// Call a simple SELECT query and check if the database name is here.
	require.NoError(t, pg.RunSimpleQuery(selectAllQuery))

	var postgresProtocolStats interface{}
	require.Eventually(t, func() bool {
		var exists bool
		postgresProtocolStats, exists = monitor.GetProtocolStats()[protocols.Postgres]
		if !exists {
			return false
		}
		return len(postgresProtocolStats.(map[postgres.Key]*postgres.RequestStat)) != 0
	}, time.Second*5, time.Millisecond*100, "cannot collect postgres stats")

	currentStats := postgresProtocolStats.(map[postgres.Key]*postgres.RequestStat)
	for key := range currentStats {
		t.Log(key)
		if key.Operation == postgres.SelectOP {
			if key.DatabaseName == "testdb" {
				// In the auth message we could have:
				// Parameter name: user
				// Parameter value: admin
				// Parameter name: database
				// Parameter value: testdb
				// or:
				// Parameter name: database
				// Parameter value: testdb
				// Parameter name: user
				// Parameter value: admin
				//
				// we shouldn't have other combinations, so we should be able
				// to always find the database name.
				return
			} else {
				t.Fatalf("invalid database name %s", key.DatabaseName)
			}
		}
	}
	t.Fatal("Select operation not found")
}

// waitForPostgresServer verifies that the postgres server is up and running.
// It tries to connect to the server until it succeeds or the timeout is reached.
// We need that function (and cannot relay on the RunServer method) as the target regex is being logged a couple os
// milliseconds before the server is actually ready to accept connections.
func waitForPostgresServer(t *testing.T, serverAddress string, enableTLS bool) {
	pgClient, err := postgres.NewPGXClient(postgres.ConnectionOptions{
		ServerAddress: serverAddress,
		EnableTLS:     enableTLS,
	})
	require.NoError(t, err)
	defer pgClient.Close()
	require.Eventually(t, func() bool {
		return pgClient.Ping() == nil
	}, 5*time.Second, 100*time.Millisecond, "couldn't connect to postgres server")
}

// Best way to debug this is to use tshark and compare the output with our instrumentation.
// sudo tshark -i lo -f "port 5432" -Y "pgsql" -T fields -e ip.src -e _ws.col.Info -e ip.dst -e pgsql.length -e pgsql.query  -E separator='|'
func testDecoding(t *testing.T, isTLS bool) {
	serverHost := "127.0.0.1"

	serverAddress := net.JoinHostPort(serverHost, postgresPort)
	require.NoError(t, postgres.RunServer(t, serverHost, postgresPort, isTLS))
	// Verifies that the postgres server is up and running.
	// It tries to connect to the server until it succeeds or the timeout is reached.
	// We need that function (and cannot relay on the RunServer method) as the target regex is being logged a couple os
	// milliseconds before the server is actually ready to accept connections.
	waitForPostgresServer(t, serverAddress, isTLS)

	// With non-TLS, we need to triple the stats since we go through Docker proxy and the container network namespace.
	// See a concrete example in TestSimplePostGresPlaintextQuery.
	adjustCount := func(count int) int {
		if isTLS {
			return count
		}

		return count * 3
	}

	monitor := setupUSMTLSMonitor(t, getPostgresDefaultTestConfiguration(isTLS))
	if isTLS {
		utils.WaitForProgramsToBeTraced(t, consts.USMModuleName, GoTLSAttacherName, os.Getpid(), utils.ManualTracingFallbackEnabled)
	}

	tests := []postgresParsingTestAttributes{
		{
			name: "create table simple",
			preMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg, err := postgres.NewPGXClient(postgres.ConnectionOptions{
					ServerAddress: ctx.serverAddress,
					EnableTLS:     isTLS,
				})
				require.NoError(t, err)
				require.NoError(t, pg.Ping())
				ctx.extras["pg"] = pg
			},
			postMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg := ctx.extras["pg"].(*postgres.PGXClient)
				require.NoError(t, pg.RunSimpleQuery(createTableQuery))
			},
			validation: func(t *testing.T, _ pgTestContext, monitor *Monitor) {
				validatePostgres(t, monitor, map[string]map[postgres.Operation]int{
					"dummy": {
						postgres.CreateTableOP: adjustCount(1),
					},
				}, isTLS)
			},
		},
		{
			name: "insert rows in table simple",
			preMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg, err := postgres.NewPGXClient(postgres.ConnectionOptions{
					ServerAddress: ctx.serverAddress,
					EnableTLS:     isTLS,
				})
				require.NoError(t, err)
				require.NoError(t, pg.Ping())
				ctx.extras["pg"] = pg
				require.NoError(t, pg.RunQuery(createTableQuery))
			},
			postMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg := ctx.extras["pg"].(*postgres.PGXClient)
				// Sending 2 insert queries, each with 5 values.
				// We want to ensure we're capturing both requests.
				for i := 0; i < 2; i++ {
					require.NoError(t, pg.RunSimpleQuery(createInsertQuery(generateTestValues(5*i, 5*(1+i))...)))
				}
			},
			validation: func(t *testing.T, _ pgTestContext, monitor *Monitor) {
				validatePostgres(t, monitor, map[string]map[postgres.Operation]int{
					"dummy": {
						postgres.InsertOP: adjustCount(2),
					},
				}, isTLS)
			},
		},
		{
			name: "insert rows in table extended",
			preMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg, err := postgres.NewPGXClient(postgres.ConnectionOptions{
					ServerAddress: ctx.serverAddress,
					EnableTLS:     isTLS,
				})
				require.NoError(t, err)
				require.NoError(t, pg.Ping())
				ctx.extras["pg"] = pg
				require.NoError(t, pg.RunQuery(createTableQuery))
			},
			postMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				// tshark output:
				// 127.0.0.1|>Q|127.0.0.1|12|-- ping
				// 127.0.0.1|<I/Z|127.0.0.1|4,5|
				// 127.0.0.1|>P/D/S|127.0.0.1|160,64,4|INSERT INTO dummy (foo) VALUES ('value-0'), ..., ('value-4')
				// 127.0.0.1|<1/t/n/Z|127.0.0.1|4,6,4,5| <---- we recognize the postgres protocol here, thanks to `<1`
				// 127.0.0.1|>B/D/E/S|127.0.0.1|70,6,9,4|
				// 127.0.0.1|<2/n/C/Z|127.0.0.1|4,4,15,5|
				// 127.0.0.1|>P/D/S|127.0.0.1|230,64,4|INSERT INTO dummy (foo) VALUES ('value-5'), ..., ('value-14')
				// 127.0.0.1|<1/t/n/Z|127.0.0.1|4,6,4,5|
				// 127.0.0.1|>B/D/E/S|127.0.0.1|70,6,9,4|
				// 127.0.0.1|<2/n/C/Z|127.0.0.1|4,4,16,5|
				//
				// Our ebpf instrumentation output:
				// Bind 1
				// [POSTGRES]: Bind: ifx 1, type 4, tcp_seq 1043316547, netns 4026531840, sport 48384, dport 5432
				// [POSTGRES]: Bind: ifx 219, type 4, tcp_seq 2051224592, netns 4026531840, sport 54600, dport 5432
				// [POSTGRES]: Bind: ifx 2, type 0, tcp_seq 2051224592, netns 4026533550, sport 54600, dport 5432
				//
				// Bind complete 1
				// [POSTGRES]: Not Q/P: ifx 2, type 4, tcp_seq 830289304, netns 4026533550, sport 5432, dport 54600
				// [POSTGRES]: Complete: tcp_seq 830289304, netns 4026533550, sport 54600, dport 5432
				// [POSTGRES]: Not Q/P: ifx 220, type 3, tcp_seq 830289304, netns 4026531840, sport 5432, dport 54600
				// [POSTGRES]: Complete: tcp_seq 830289304, netns 4026531840, sport 54600, dport 5432
				// [POSTGRES]: Not Q/P: ifx 1, type 4, tcp_seq 3901940858, netns 4026531840, sport 5432, dport 48384
				// [POSTGRES]: Complete: tcp_seq 3901940858, netns 4026531840, sport 48384, dport 5432
				//
				// Parse 2
				// [POSTGRES]: Parse: ifx 1, type 4, tcp_seq 1043316246, netns 4026531840, sport 48384, dport 5432
				// [POSTGRES]: Parse: ifx 219, type 4, tcp_seq 2051224291, netns 4026531840, sport 54600, dport 5432
				// [POSTGRES]: Parse: ifx 2, type 0, tcp_seq 2051224291, netns 4026533550, sport 54600, dport 5432
				//
				// Bind 2
				// [POSTGRES]: Bind: ifx 1, type 4, tcp_seq 1043316547, netns 4026531840, sport 48384, dport 5432
				// [POSTGRES]: Bind: ifx 219, type 4, tcp_seq 2051224592, netns 4026531840, sport 54600, dport 5432
				// [POSTGRES]: Bind: ifx 2, type 0, tcp_seq 2051224592, netns 4026533550, sport 54600, dport 5432
				//
				// Bind complete 2
				// [POSTGRES]: Not Q/P: ifx 2, type 4, tcp_seq 830289304, netns 4026533550, sport 5432, dport 54600
				// [POSTGRES]: Complete: tcp_seq 830289304, netns 4026533550, sport 54600, dport 5432
				// [POSTGRES]: Not Q/P: ifx 220, type 3, tcp_seq 830289304, netns 4026531840, sport 5432, dport 54600
				// [POSTGRES]: Complete: tcp_seq 830289304, netns 4026531840, sport 54600, dport 5432
				// [POSTGRES]: Not Q/P: ifx 1, type 4, tcp_seq 3901940858, netns 4026531840, sport 5432, dport 48384
				// [POSTGRES]: Complete: tcp_seq 3901940858, netns 4026531840, sport 48384, dport 5432

				pg := ctx.extras["pg"].(*postgres.PGXClient)
				// Sending 2 insert queries, each with 5 values.
				// We want to ensure we're capturing both requests.
				for i := 0; i < 2; i++ {
					require.NoError(t, pg.RunQuery(createInsertQuery(generateTestValues(5*i, 5*(1+i))...)))
				}
			},
			validation: func(t *testing.T, _ pgTestContext, monitor *Monitor) {

				// Parse and Bind could arrive in any order. If they arrive out of order
				// we won't be able to extract the operation and the table name from the Bind. We check for unknown operation or the right operation but we don't know which one we wiil have. The only thing we know is that if we don't have unknown we should have the right operation and table name.
				require.Eventually(t, func() bool {
					postgresProtocolStats, exists := monitor.GetProtocolStats()[protocols.Postgres]
					if !exists {
						return false
					}
					currentStats := postgresProtocolStats.(map[postgres.Key]*postgres.RequestStat)

					for key := range currentStats {
						// We want just to check that if the operation is not unknown we can recover the right operation and the table name
						if key.Operation == postgres.UnknownOP {
							continue
						}

						if key.Operation != postgres.InsertOP || key.TableName != "dummy" {
							t.Logf("invalid operation '%v' or table name '%s'", key.Operation, key.TableName)
							return false
						}
					}
					return true
				}, time.Second*5, time.Millisecond*100, "cannot find required stats")
			},
		},
		{
			name: "update a row in a table simple",
			preMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg, err := postgres.NewPGXClient(postgres.ConnectionOptions{
					ServerAddress: ctx.serverAddress,
					EnableTLS:     isTLS,
				})
				require.NoError(t, err)
				require.NoError(t, pg.Ping())
				ctx.extras["pg"] = pg
				require.NoError(t, pg.RunQuery(createTableQuery))
				require.NoError(t, pg.RunQuery(createInsertQuery("value-1")))
			},
			postMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg := ctx.extras["pg"].(*postgres.PGXClient)
				require.NoError(t, pg.RunSimpleQuery(updateSingleValueQuery))
			},
			validation: func(t *testing.T, _ pgTestContext, monitor *Monitor) {
				validatePostgres(t, monitor, map[string]map[postgres.Operation]int{
					"dummy": {
						postgres.UpdateOP: adjustCount(1),
					},
				}, isTLS)
			},
		},
		{
			name: "select simple",
			preMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg, err := postgres.NewPGXClient(postgres.ConnectionOptions{
					ServerAddress: ctx.serverAddress,
					EnableTLS:     isTLS,
				})
				require.NoError(t, err)
				require.NoError(t, pg.Ping())
				ctx.extras["pg"] = pg
				require.NoError(t, pg.RunQuery(createTableQuery))
				require.NoError(t, pg.RunQuery(createInsertQuery("value-1")))
			},
			postMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg := ctx.extras["pg"].(*postgres.PGXClient)
				require.NoError(t, pg.RunSimpleQuery(selectAllQuery))
			},
			validation: func(t *testing.T, _ pgTestContext, monitor *Monitor) {
				validatePostgres(t, monitor, map[string]map[postgres.Operation]int{
					"dummy": {
						postgres.SelectOP: adjustCount(1),
					},
				}, isTLS)
			},
		},
		{
			name: "delete row from table simple",
			preMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg, err := postgres.NewPGXClient(postgres.ConnectionOptions{
					ServerAddress: ctx.serverAddress,
					EnableTLS:     isTLS,
				})
				require.NoError(t, err)
				require.NoError(t, pg.Ping())
				ctx.extras["pg"] = pg
				require.NoError(t, pg.RunQuery(createTableQuery))
			},
			postMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg := ctx.extras["pg"].(*postgres.PGXClient)
				require.NoError(t, pg.RunSimpleQuery(deleteTableQuery))
			},
			validation: func(t *testing.T, _ pgTestContext, monitor *Monitor) {
				validatePostgres(t, monitor, map[string]map[postgres.Operation]int{
					"dummy": {
						postgres.DeleteTableOP: adjustCount(1),
					},
				}, isTLS)
			},
		},
		{
			name: "alter command simple",
			preMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg, err := postgres.NewPGXClient(postgres.ConnectionOptions{
					ServerAddress: ctx.serverAddress,
					EnableTLS:     isTLS,
				})
				require.NoError(t, err)
				require.NoError(t, pg.Ping())
				ctx.extras["pg"] = pg
				require.NoError(t, pg.RunQuery(createTableQuery))
			},
			postMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg := ctx.extras["pg"].(*postgres.PGXClient)
				require.NoError(t, pg.RunSimpleQuery(alterTableQuery))
			},
			validation: func(t *testing.T, _ pgTestContext, monitor *Monitor) {
				validatePostgres(t, monitor, map[string]map[postgres.Operation]int{
					"dummy": {
						postgres.AlterTableOP: adjustCount(1),
					},
				}, isTLS)
			},
		},
		{
			name: "truncate operation simple",
			preMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg, err := postgres.NewPGXClient(postgres.ConnectionOptions{
					ServerAddress: ctx.serverAddress,
					EnableTLS:     isTLS,
				})
				require.NoError(t, err)
				require.NoError(t, pg.Ping())
				ctx.extras["pg"] = pg
				require.NoError(t, pg.RunQuery(createTableQuery))
			},
			postMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg := ctx.extras["pg"].(*postgres.PGXClient)
				// if TRUNCATE is the first message we see, we won't recognize the postgres	protocol for this reason we first need a SELECT
				require.NoError(t, pg.RunSimpleQuery(selectAllQuery))
				require.NoError(t, pg.RunSimpleQuery(truncateTableQuery))
			},
			validation: func(t *testing.T, _ pgTestContext, monitor *Monitor) {
				validatePostgres(t, monitor, map[string]map[postgres.Operation]int{
					"dummy": {
						postgres.SelectOP:        adjustCount(1),
						postgres.TruncateTableOP: adjustCount(1),
					},
				}, isTLS)
			},
		},
		{
			name: "drop table simple",
			preMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg, err := postgres.NewPGXClient(postgres.ConnectionOptions{
					ServerAddress: ctx.serverAddress,
					EnableTLS:     isTLS,
				})
				require.NoError(t, err)
				require.NoError(t, pg.Ping())
				ctx.extras["pg"] = pg
			},
			postMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg := ctx.extras["pg"].(*postgres.PGXClient)
				require.NoError(t, pg.RunSimpleQuery(dropTableQuery))
			},
			validation: func(t *testing.T, _ pgTestContext, monitor *Monitor) {
				validatePostgres(t, monitor, map[string]map[postgres.Operation]int{
					"dummy": {
						postgres.DropTableOP: adjustCount(1),
					},
				}, isTLS)
			},
		},
		{
			name: "combo - multiple operations should be captured simple",
			preMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg, err := postgres.NewPGXClient(postgres.ConnectionOptions{
					ServerAddress: ctx.serverAddress,
					EnableTLS:     isTLS,
				})
				require.NoError(t, err)
				require.NoError(t, pg.Ping())
				ctx.extras["pg"] = pg
			},
			postMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg := ctx.extras["pg"].(*postgres.PGXClient)
				ctx.extras["pg"] = pg
				require.NoError(t, pg.RunSimpleQuery(createTableQuery))
				for i := 0; i < 20; i++ {
					require.NoError(t, pg.RunSimpleQuery(createInsertQuery(generateTestValues(i*5, 5)...)))
				}
				require.NoError(t, pg.RunSimpleQuery(generateSelectLimitQuery(50)))
				require.NoError(t, pg.RunSimpleQuery(updateSingleValueQuery))
			},
			validation: func(t *testing.T, _ pgTestContext, monitor *Monitor) {
				validatePostgres(t, monitor, map[string]map[postgres.Operation]int{
					"dummy": {
						postgres.SelectOP:      adjustCount(1),
						postgres.UpdateOP:      adjustCount(1),
						postgres.InsertOP:      adjustCount(20),
						postgres.CreateTableOP: adjustCount(1),
					},
				}, isTLS)
			},
		},
		{
			name: "query is truncated simple",
			preMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg, err := postgres.NewPGXClient(postgres.ConnectionOptions{
					ServerAddress: ctx.serverAddress,
					EnableTLS:     isTLS,
				})
				require.NoError(t, err)
				require.NoError(t, pg.Ping())
				ctx.extras["pg"] = pg
			},
			postMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg := ctx.extras["pg"].(*postgres.PGXClient)
				require.NoError(t, pg.RunSimpleQuery(longCreateQuery))
				require.NoError(t, pg.RunSimpleQuery(longDropQuery))
			},
			validation: func(t *testing.T, _ pgTestContext, monitor *Monitor) {
				validatePostgres(t, monitor, map[string]map[postgres.Operation]int{
					// From ebpf we send 160 bytes. The first 5 bytes are `Q` tag + 4 bytes of len.
					// Then the next 13 bytes are the SQL query. So the name of the table should be in the remaining bytes:
					strings.Repeat("a", ebpf.BufferSize-5-13): {
						postgres.CreateTableOP: adjustCount(1),
					},
					strings.Repeat("a", ebpf.BufferSize-5-21): {
						postgres.DropTableOP: adjustCount(1),
					},
				}, isTLS)
			},
		},
		{
			name: "show command simple",
			preMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg, err := postgres.NewPGXClient(postgres.ConnectionOptions{
					ServerAddress: ctx.serverAddress,
					EnableTLS:     isTLS,
				})
				require.NoError(t, err)
				require.NoError(t, pg.Ping())
				ctx.extras["pg"] = pg
				require.NoError(t, pg.RunQuery(createTableQuery))
			},
			postMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg := ctx.extras["pg"].(*postgres.PGXClient)
				// if SHOW query is the first query we see, we won't recognize the postgres	protocol because we don't check against SHOW verb
				// for this reason we first need a SELECT
				require.NoError(t, pg.RunSimpleQuery(selectAllQuery))
				require.NoError(t, pg.RunSimpleQuery(showQuery))
			},
			validation: func(t *testing.T, _ pgTestContext, monitor *Monitor) {
				validatePostgres(t, monitor, map[string]map[postgres.Operation]int{
					"dummy": {
						postgres.SelectOP: adjustCount(1),
					},
					// show doesn't have a table name so we don't extract it
					"": {
						postgres.ShowOP: adjustCount(1),
					},
				}, isTLS)
			},
		},
		// This test validates that the sql transaction is not supported.
		{
			name: "transaction",
			preMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg, err := postgres.NewPGXClient(postgres.ConnectionOptions{
					ServerAddress: ctx.serverAddress,
					EnableTLS:     isTLS,
				})
				require.NoError(t, err)
				require.NoError(t, pg.Ping())
				ctx.extras["pg"] = pg

				tx, err := pg.Begin()
				require.NoError(t, err)
				require.NoError(t, pg.RunQuery(createTableQuery))
				require.NoError(t, pg.Commit(tx))
			},
			postMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg := ctx.extras["pg"].(*postgres.PGXClient)

				// tshark output:
				//
				// We don't recognize all the following
				// 127.0.0.1|>Q|127.0.0.1|12|-- ping
				// 127.0.0.1|<I/Z|127.0.0.1|4,5|
				// 127.0.0.1|>Q|127.0.0.1|10|begin
				// 127.0.0.1|<C/Z|127.0.0.1|10,5|
				// 127.0.0.1|>P/D/S|127.0.0.1|85,64,4|SELECT * FROM dummy
				// 127.0.0.1|<1/t/T/Z|127.0.0.1|4,6,49,5|
				//
				// We recognize the parse complete
				//
				// 127.0.0.1|>B/D/E/S|127.0.0.1|74,6,9,4|
				// 127.0.0.1|<2/T/C/Z|127.0.0.1|4,49,13,5|
				// 127.0.0.1|>Q|127.0.0.1|11|commit
				// 127.0.0.1|<C/Z|127.0.0.1|11,5|
				tx, err := pg.Begin()
				require.NoError(t, err)
				require.NoError(t, pg.RunQueryTX(tx, selectAllQuery))
				require.NoError(t, pg.Commit(tx))
			},
			validation: func(t *testing.T, _ pgTestContext, monitor *Monitor) {
				validatePostgres(t, monitor, map[string]map[postgres.Operation]int{
					"": {
						postgres.UnknownOP: adjustCount(2),
					},
				}, isTLS)
			},
		},
		{
			name:       "batched queries",
			skipReason: "this test is flaky because we don't know the order in which packet will be processed by userspace",
			preMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg, err := postgres.NewPGXClient(postgres.ConnectionOptions{
					ServerAddress: ctx.serverAddress,
					EnableTLS:     isTLS,
				})
				require.NoError(t, err)
				ctx.extras["pg"] = pg
			},
			postMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg := ctx.extras["pg"].(*postgres.PGXClient)

				// 127.0.0.1|>Q|127.0.0.1|57|CREATE TABLE dummy (id SERIAL PRIMARY KEY, foo TEXT)
				// 127.0.0.1|<C/Z|127.0.0.1|17,5|
				require.NoError(t, pg.RunSimpleQuery(createTableQuery))

				// We have 2 Parse in the same packet
				// 127.0.0.1|>P/D/P/D/S|127.0.0.1|108,64,85,64,4|INSERT INTO dummy (foo) VALUES ('value-1'),SELECT * FROM dummy
				// 127.0.0.1|<1/t/n/1/t/T/Z|127.0.0.1|4,6,4,4,6,49,5|
				//
				// We have 2 Bind in the same packet (we recognize it as one, we don't loop inside the packet to catch more than one)
				// 127.0.0.1|>B/D/E/B/D/E/S|127.0.0.1|70,6,9,74,6,9,4|
				// 127.0.0.1|<2/n/C/2/T/D/C/Z|127.0.0.1|4,4,15,4,49,25,13,5|

				// What we see from our instrumentation:
				// [POSTGRES]: Parse: ifx 1, type 4, tcp_seq 539562970, netns 4026531840, sport 50444, dport 5432
				// [POSTGRES]: Parse: ifx 231, type 4, tcp_seq 4188944133, netns 4026531840, sport 46162, dport 5432
				// [POSTGRES]: Parse: ifx 2, type 0, tcp_seq 4188944133, netns 4026533494, sport 46162, dport 5432
				//
				// We overwrite the previous parse since we don't find a Complete.
				//
				// [POSTGRES]: Bind: ifx 1, type 4, tcp_seq 539563300, netns 4026531840, sport 50444, dport 5432
				// [POSTGRES]: Bind: ifx 231, type 4, tcp_seq 4188944463, netns 4026531840, sport 46162, dport 5432
				// [POSTGRES]: Bind: ifx 2, type 0, tcp_seq 4188944463, netns 4026533494, sport 46162, dport 5432
				// [POSTGRES]: Not Q/P: ifx 2, type 4, tcp_seq 1773475585, netns 4026533494, sport 5432, dport 46162
				// [POSTGRES]: Complete: tcp_seq 1773475585, netns 4026533494, sport 46162, dport 5432
				// [POSTGRES]: Not Q/P: ifx 232, type 3, tcp_seq 1773475585, netns 4026531840, sport 5432, dport 46162
				// [POSTGRES]: Complete: tcp_seq 1773475585, netns 4026531840, sport 46162, dport 5432
				// [POSTGRES]: Not Q/P: ifx 1, type 4, tcp_seq 2609089898, netns 4026531840, sport 5432, dport 50444
				// [POSTGRES]: Complete: tcp_seq 2609089898, netns 4026531840, sport 50444, dport 5432
				require.NoError(t, pg.SendBatch(createInsertQuery("value-1"), selectAllQuery))
			},
			validation: func(t *testing.T, _ pgTestContext, monitor *Monitor) {
				validatePostgres(t, monitor, map[string]map[postgres.Operation]int{
					"dummy": {
						postgres.CreateTableOP: adjustCount(1),
						postgres.InsertOP:      adjustCount(1),
					},
				}, isTLS)
			},
		},
		{
			name: "long message",
			preMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg, err := postgres.NewPGXClient(postgres.ConnectionOptions{
					ServerAddress: ctx.serverAddress,
					EnableTLS:     isTLS,
				})
				require.NoError(t, err)
				require.NoError(t, pg.Ping())
				ctx.extras["pg"] = pg
			},
			postMonitorSetup: func(t *testing.T, ctx pgTestContext) {
				pg := ctx.extras["pg"].(*postgres.PGXClient)
				require.NoError(t, pg.Ping())
				ctx.extras["pg"] = pg
				require.NoError(t, pg.RunSimpleQuery(createTableQuery))
				// we generate 200 value to have a long SELECT response
				require.NoError(t, pg.RunSimpleQuery(createInsertQuery(generateTestValues(1, 200)...)))
				// we capture the `Z` at the end of the message so we don't care if the message is long.
				// The previous implemenation used the `C` message to identify the end of the message, that's why
				// it wasn't able to catch the SELECT transaction.
				require.NoError(t, pg.RunSimpleQuery(selectAllQuery))
			},
			validation: func(t *testing.T, _ pgTestContext, monitor *Monitor) {
				validatePostgres(t, monitor, map[string]map[postgres.Operation]int{
					"dummy": {
						postgres.InsertOP:      adjustCount(1),
						postgres.CreateTableOP: adjustCount(1),
						postgres.SelectOP:      adjustCount(1),
					},
				}, isTLS)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipReason != "" {
				t.Skip(tt.skipReason)
			}

			tt.context = pgTestContext{
				serverPort:    postgresPort,
				targetAddress: serverAddress,
				serverAddress: serverAddress,
				extras:        map[string]interface{}{},
			}
			t.Cleanup(func() {
				pgEntry, ok := tt.context.extras["pg"]
				if !ok {
					return
				}
				pg := pgEntry.(*postgres.PGXClient)
				defer pg.Close()
				_ = pg.RunQuery(dropTableQuery)
				cleanProtocolMaps(t, "postgres", monitor.ebpfProgram.Manager.Manager)
			})
			require.NoError(t, monitor.Pause())
			if tt.preMonitorSetup != nil {
				tt.preMonitorSetup(t, tt.context)
			}
			require.NoError(t, monitor.Resume())

			obj, ok := tt.context.extras["pg"]
			require.True(t, ok)
			pgClient := obj.(*postgres.PGXClient)
			// Since we cannot classify 'Parse' message, we need to send a harmless message that we know how
			// to classify to ensure the monitor is able to process the messages.
			// That's a workaround until we can classify the 'Parse' message.
			//
			// Please note that Ping() executes an SQL query with body  `-- ping` via the PostgreSQL simple query protocol. So in ebpf we will always see a simple query with `-- ping` body.
			require.NoError(t, pgClient.Ping())
			tt.postMonitorSetup(t, tt.context)
			require.NoError(t, monitor.Pause())
			tt.validation(t, tt.context, monitor)
		})
	}
}

// getTruncatedTableName returns the truncated table name by reducing the operation and extracting the remaining
// table name by the current max buffer size.
func getTruncatedTableName(query string, tableNameIndex int) string {
	return query[tableNameIndex:ebpf.BufferSize]
}

// getPostgresInFlightEntries returns the entries in the in-flight map.
func getPostgresInFlightEntries(t *testing.T, monitor *Monitor) map[ebpf.ConnTuple]ebpf.EbpfTx {
	postgresInFlightMap, _, err := monitor.ebpfProgram.GetMap(postgres.InFlightMap)
	require.NoError(t, err)

	var key ebpf.ConnTuple
	var value ebpf.EbpfTx
	entries := make(map[ebpf.ConnTuple]ebpf.EbpfTx)
	iter := postgresInFlightMap.Iterate()
	for iter.Next(&key, &value) {
		entries[key] = value
	}
	return entries
}

// TestCleanupEBPFEntriesOnTermination tests that the cleanup of the eBPF entries is done when the connection
// is closed. This is important to avoid leaking resources. The test creates a TCP server, which just reads the requests
// without sending any response. The test will send a postgres request (and obviously will fail), we will verify the
// request appear in the in_flight map and then we will close the connection and verify that the entry is removed.
func (s *postgresProtocolParsingSuite) TestCleanupEBPFEntriesOnTermination() {
	t := s.T()

	// Creating the monitor
	monitor := setupUSMTLSMonitor(t, getPostgresDefaultTestConfiguration(protocolsUtils.TLSDisabled))

	wg := sync.WaitGroup{}

	// Spinning the TCP server
	const serverAddress = "127.0.0.1:5433" // Using a different port than 5432 to avoid errors like "address already in use"
	srv := testutil.NewTCPServer(serverAddress, func(conn net.Conn) {
		defer conn.Close()
		defer wg.Done()
		_, _ = conn.Read(make([]byte, 1024))
		// Verifying the entry is present in the in-flight map
		entries := getPostgresInFlightEntries(t, monitor)
		require.Len(t, entries, 1)
	}, false)
	done := make(chan struct{})
	require.NoError(t, srv.Run(done))
	t.Cleanup(func() { close(done) })

	// Encoding a dummy query.
	output := make([]byte, 0)
	query := pgproto3.Query{String: "SELECT * FROM dummy"}
	var err error
	output, err = query.Encode(output)
	require.NoError(t, err)

	// Connecting to the server
	client, err := net.Dial("tcp", serverAddress)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	// Sending the query and waiting for the server to finish processing it
	wg.Add(1)
	_, err = client.Write(output)
	require.NoError(t, err)
	wg.Wait()

	// Closing the connection and verifying the entry is removed
	require.NoError(t, client.Close())
	entries := getPostgresInFlightEntries(t, monitor)
	require.Len(t, entries, 0)
}

func getPostgresDefaultTestConfiguration(enableTLS bool) *config.Config {
	cfg := utils.NewUSMEmptyConfig()
	cfg.EnablePostgresMonitoring = true
	cfg.MaxTrackedConnections = 1000
	cfg.EnableGoTLSSupport = enableTLS
	// If GO TLS is enabled, we need to allow self traffic to be captured.
	// If GO TLS is disabled, the value is irrelevant.
	cfg.GoTLSExcludeSelf = false
	cfg.BypassEnabled = true
	return cfg
}

func validatePostgres(t *testing.T, monitor *Monitor, expectedStats map[string]map[postgres.Operation]int, tls bool) {
	found := make(map[string]map[postgres.Operation]int)
	require.Eventually(t, func() bool {
		postgresProtocolStats, exists := monitor.GetProtocolStats()[protocols.Postgres]
		if !exists {
			return false
		}
		// We might not have postgres stats, and it might be the expected case (to capture 0).
		currentStats := postgresProtocolStats.(map[postgres.Key]*postgres.RequestStat)
		for key, stats := range currentStats {
			hasTLSTag := stats.StaticTags&network.ConnTagGo != 0
			if hasTLSTag != tls {
				continue
			}
			if _, ok := found[key.TableName]; !ok {
				found[key.TableName] = make(map[postgres.Operation]int)
			}
			found[key.TableName][key.Operation] += stats.Count
		}
		return reflect.DeepEqual(expectedStats, found)
	}, time.Second*5, time.Millisecond*100, "Expected to find a %v stats, instead captured %v", &expectedStats, &found)
}

func setupPGClient(t *testing.T, serverAddress string, isTLS bool) *postgres.PGXClient {
	pg, err := postgres.NewPGXClient(postgres.ConnectionOptions{
		ServerAddress: serverAddress,
		EnableTLS:     isTLS,
	})
	require.NoError(t, err)
	require.NoError(t, pg.Ping())
	return pg
}
