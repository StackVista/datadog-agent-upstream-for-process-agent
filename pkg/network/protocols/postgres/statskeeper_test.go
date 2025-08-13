// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package postgres

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/postgres/ebpf"
	libtelemetry "github.com/DataDog/datadog-agent/pkg/network/protocols/telemetry"
)

var defaultTuple = ebpf.ConnTuple{
	Saddr_h:  0x01020304,
	Saddr_l:  0x05060708,
	Daddr_h:  0x090a0b0c,
	Daddr_l:  0x0d0e0f10,
	Sport:    4576,
	Dport:    5432,
	Netns:    0,
	Metadata: 0,
}

const (
	databaseName   = "myDB"
	tableName1     = "table1"
	tableName2     = "table2"
	statementName1 = "statement1"
	statementName2 = "statement2"
)

func TestSimpleQueries(t *testing.T) {
	cfg := config.New()
	cfg.MaxPostgresStatsBuffered = 100
	s, err := NewStatkeeper(cfg, NewTelemetry())
	require.NoError(t, err)

	// we process 20 simple queries, we miss the startup so we don't have the database name
	for i := 0; i < 20; i++ {
		event := NewEventWrapper(&ebpf.EbpfEvent{
			Tx: ebpf.EbpfTx{
				Request_fragment:   createMessageFromString(QueryTag, "SELECT * FROM foo"),
				Request_started:    1,
				Response_last_seen: 10,
			},
		})
		s.Process(event)
	}

	// we shouldn't have stats because we didn't see the startup yet
	require.Equal(t, 0, len(s.stats))

	// we simulate a database startup later
	databaseName := "myDB"
	event := NewEventWrapper(&ebpf.EbpfEvent{
		Tx: ebpf.EbpfTx{
			Request_fragment: createMessageFromString(StartupTag,
				fmt.Sprintf("user\x00xx\x00database\x00%s\x00", databaseName)),
		},
	})
	s.Process(event)
	require.Equal(t, 1, len(s.stats))
	for k, stat := range s.stats {
		require.Equal(t, "foo", k.TableName)
		require.Equal(t, SelectOP, k.Operation)
		require.Equal(t, 20, stat.Count)
		require.Equal(t, float64(20), stat.Latencies.GetCount())
	}
}

func TestMissingDatabase(t *testing.T) {
	cfg := config.New()
	cfg.MaxPostgresStatsBuffered = 100
	s, err := NewStatkeeper(cfg, NewTelemetry())
	require.NoError(t, err)

	////////////
	// Simple query
	////////////

	e := NewEventWrapper(&ebpf.EbpfEvent{
		Tuple: defaultTuple,
		Tx: ebpf.EbpfTx{
			Request_fragment:   createMessageFromString(QueryTag, fmt.Sprintf("CREATE TABLE %s (id int)", tableName1)),
			Request_started:    1,
			Response_last_seen: 10,
		},
	})
	s.Process(e)
	// we are waiting for the startup message
	// but we will never receive it...
	require.Equal(t, 0, len(s.stats))

	stats := s.GetAndResetAllStats()
	require.Equal(t, 1, len(stats))
	req, ok := stats[Key{
		Operation:     CreateTableOP,
		TableName:     tableName1,
		ConnectionKey: e.ConnTuple(),
		DatabaseName:  UnobservedString,
	}]
	require.True(t, ok)
	require.Equal(t, req.Count, 1)
	require.Equal(t, s.telemetry.getTelemetryValues().missingDatabaseName, int64(1))
}

func TestFullFlow(t *testing.T) {
	cfg := config.New()
	cfg.MaxPostgresStatsBuffered = 100
	s, err := NewStatkeeper(cfg, NewTelemetry())
	require.NoError(t, err)

	// We want to check all the stages of a full flow

	////////////
	// Startup
	////////////
	e := NewEventWrapper(&ebpf.EbpfEvent{
		Tuple: defaultTuple,
		Tx: ebpf.EbpfTx{
			Request_fragment: createMessageFromString(StartupTag, fmt.Sprintf("user\x00xx\x00database\x00%s\x00", databaseName)),
		},
	})

	s.Process(e)
	require.Equal(t, 0, len(s.stats))

	////////////
	// Simple query
	////////////

	e = NewEventWrapper(&ebpf.EbpfEvent{
		Tuple: defaultTuple,
		Tx: ebpf.EbpfTx{
			Request_fragment:   createMessageFromString(QueryTag, fmt.Sprintf("CREATE TABLE %s (id int)", tableName1)),
			Request_started:    1,
			Response_last_seen: 10,
		},
	})
	s.Process(e)
	require.Equal(t, 1, len(s.stats))

	requestStats, ok := s.stats[Key{
		Operation:     CreateTableOP,
		TableName:     tableName1,
		ConnectionKey: e.ConnTuple(),
		DatabaseName:  databaseName,
	}]
	require.True(t, ok)
	require.Equal(t, requestStats.Count, 1)

	////////////
	// Parse a first statement
	////////////

	e = NewEventWrapper(&ebpf.EbpfEvent{
		Tuple: defaultTuple,
		Tx: ebpf.EbpfTx{
			Request_fragment: createMessageFromString(ParseTag, fmt.Sprintf("%s\x00INSERT INTO %s VALUES (1, 2, 3)", statementName1, tableName1)),
		},
	})
	s.Process(e)
	// no new stats
	require.Equal(t, 1, len(s.stats))

	qInfo, ok := s.statementsCache.Get(statementConnection{
		statementName: statementName1,
		conn:          e.ConnTuple(),
	})
	require.True(t, ok)
	require.Equal(t, queryInfo{tableName: tableName1, sqlCommand: InsertOP}, qInfo)

	////////////
	// Parse a second statement with the same name
	////////////

	// we have the same statement name but a different statement value
	e = NewEventWrapper(&ebpf.EbpfEvent{
		Tuple: defaultTuple,
		Tx: ebpf.EbpfTx{
			Request_fragment: createMessageFromString(ParseTag, fmt.Sprintf("%s\x00SELECT * FROM %s", statementName1, tableName2)),
		},
	})
	s.Process(e)

	qInfo, ok = s.statementsCache.Get(statementConnection{
		statementName: statementName1,
		conn:          e.ConnTuple(),
	})
	require.True(t, ok)
	// we check if the overwrite worked
	require.Equal(t, queryInfo{tableName: tableName2, sqlCommand: SelectOP}, qInfo)

	////////////
	// Parse a second statement
	////////////

	e = NewEventWrapper(&ebpf.EbpfEvent{
		Tuple: defaultTuple,
		Tx: ebpf.EbpfTx{
			Request_fragment: createMessageFromString(ParseTag, fmt.Sprintf("%s\x00UPDATE %s SET json_prefs = (json_prefs)s, modified = '2015-08-27 22:10:32.492912' WHERE user_id = (user_id)s AND url = (url)s", statementName2, tableName2)),
		},
	})
	s.Process(e)

	qInfo, ok = s.statementsCache.Get(statementConnection{
		statementName: statementName2,
		conn:          e.ConnTuple(),
	})
	require.True(t, ok)
	require.Equal(t, queryInfo{tableName: tableName2, sqlCommand: UpdateOP}, qInfo)

	////////////
	// Bind against the fist statement
	////////////

	e = NewEventWrapper(&ebpf.EbpfEvent{
		Tuple: defaultTuple,
		Tx: ebpf.EbpfTx{
			Request_fragment:   createMessageFromString(BindTag, fmt.Sprintf("PORTAL1\x00%s\x002342424242", statementName1)),
			Request_started:    1,
			Response_last_seen: 10,
		},
	})
	// we bind against statement one
	s.Process(e)

	// we have a new key so now we have 2 stats
	require.Equal(t, 2, len(s.stats))

	requestStats, ok = s.stats[Key{
		Operation:     SelectOP,
		TableName:     tableName2,
		ConnectionKey: e.ConnTuple(),
		DatabaseName:  databaseName,
	}]
	require.True(t, ok)
	require.Equal(t, requestStats.Count, 1)

	////////////
	// Bind against the second statement
	////////////

	e = NewEventWrapper(&ebpf.EbpfEvent{
		Tuple: defaultTuple,
		Tx: ebpf.EbpfTx{
			Request_fragment:   createMessageFromString(BindTag, fmt.Sprintf("PORTAL\x00%s\x002342424242", statementName2)),
			Request_started:    1,
			Response_last_seen: 10,
		},
	})
	// we bind against statement one
	s.Process(e)

	// we have a new key so now we have 2 stats
	require.Equal(t, 3, len(s.stats))

	requestStats, ok = s.stats[Key{
		Operation:     UpdateOP,
		TableName:     tableName2,
		ConnectionKey: e.ConnTuple(),
		DatabaseName:  databaseName,
	}]
	require.True(t, ok)
	require.Equal(t, requestStats.Count, 1)
}

func TestMisclassification(t *testing.T) {
	cfg := config.New()
	cfg.MaxPostgresStatsBuffered = 100

	tests := []struct {
		name            string
		requestFragment [160]byte
		payloadLen      int
	}{
		{
			name:            "startup not truncated",
			requestFragment: createMessageFromString(StartupTag, fmt.Sprintf("user\x00xx\x00database\x00dbdb\x00")),
			payloadLen:      23,
		},
		{
			name:            "startup truncated",
			requestFragment: createMessageFromString(StartupTag, strings.Repeat("A", 1023)),
			payloadLen:      152, // 160-8
		},
		{
			name:            "startup too small",
			requestFragment: createMessageFromString(StartupTag, "A"),
			payloadLen:      -1,
		},
		{
			name:            "startup too big",
			requestFragment: createMessageFromString(StartupTag, strings.Repeat("A", 30000)),
			payloadLen:      -1,
		},
		{
			name:            "generic not truncated",
			requestFragment: createMessageFromString(QueryTag, fmt.Sprintf("SELECT * FROM foo")),
			payloadLen:      18,
		},
		{
			name:            "generic truncated",
			requestFragment: createMessageFromString(QueryTag, strings.Repeat("A", 1023)),
			payloadLen:      155, // 160-5
		},
		{
			name:            "generic too small",
			requestFragment: createMessageFromString(QueryTag, ""),
			payloadLen:      -1,
		},
		{
			name:            "generic too big",
			requestFragment: createMessageFromString(QueryTag, strings.Repeat("A", 30000)),
			payloadLen:      -1,
		},
	}
	for _, tt := range tests {
		// test set payload
		t.Run(tt.name+" SetPayload", func(t *testing.T) {

			event := NewEventWrapper(&ebpf.EbpfEvent{
				Tx: ebpf.EbpfTx{
					Request_fragment: tt.requestFragment,
				},
			})

			if event.getTag() == StartupTag {
				if tt.payloadLen == -1 {
					require.False(t, event.setStartupPayload())
					return
				}
				require.True(t, event.setStartupPayload())
				require.Equal(t, tt.payloadLen, len(event.getPayload()))
				return
			}

			// All the other cases
			if tt.payloadLen == -1 {
				require.False(t, event.setPayload())
				return
			}
			require.True(t, event.setPayload())
			require.Equal(t, tt.payloadLen, len(event.getPayload()))
		})

		// test also the `Process` method in case of invalid payload
		if tt.payloadLen != -1 {
			continue
		}

		t.Run(tt.name+" Process", func(t *testing.T) {
			// Ensure telemetry counters don't accumulate across subtests since they are global
			libtelemetry.Clear()
			s, err := NewStatkeeper(cfg, NewTelemetry())
			require.NoError(t, err)
			e := NewEventWrapper(&ebpf.EbpfEvent{
				Tx: ebpf.EbpfTx{
					Request_fragment: tt.requestFragment,
				},
			})
			s.Process(e)
			require.Equal(t, 0, len(s.stats))
			require.Equal(t, int64(1), s.telemetry.getTelemetryValues().invalidMessage)
		})
	}
}
