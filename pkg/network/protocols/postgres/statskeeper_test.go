// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package postgres

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/postgres/ebpf"
)

func createMessageTagOnly(tag byte) [160]byte {
	var frag [160]byte
	frag[0] = tag

	length := uint32(4)
	binary.BigEndian.PutUint32(frag[1:5], length)
	return frag
}

func createMessageFromString(tag byte, query string) [160]byte {
	var frag [160]byte
	frag[0] = tag

	// 4 (int32) + len(query) + 1 (null terminator)
	length := uint32(4 + len(query) + 1)
	binary.BigEndian.PutUint32(frag[1:5], length)

	copy(frag[5:], query)
	frag[5+len(query)] = 0
	return frag
}

func createMessageFromBytes(tag byte, query []byte) [160]byte {
	var frag [160]byte
	frag[0] = tag

	// 4 (int32) + len(query)
	length := uint32(4 + len(query))
	binary.BigEndian.PutUint32(frag[1:5], length)

	copy(frag[5:], query)
	return frag
}

func TestSimpleQueries(t *testing.T) {
	t.Cleanup(cleanupCaches)
	cfg := config.New()
	cfg.MaxPostgresStatsBuffered = 100
	s, err := NewStatkeeper(cfg)
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
		require.Equal(t, UnobservedString, event.getDatabaseName())
		require.Equal(t, SelectOP, event.getSQLCommand())
		require.Equal(t, "foo", event.getTableName())
	}

	require.Equal(t, 1, len(s.stats))
	for k, stat := range s.stats {
		require.Equal(t, "foo", k.TableName)
		require.Equal(t, SelectOP, k.Operation)
		require.Equal(t, 20, stat.Count)
		require.Equal(t, float64(20), stat.Latencies.GetCount())
	}
}

func TestFullFlow(t *testing.T) {
	const (
		databaseName   = "myDB"
		tableName1     = "table1"
		tableName2     = "table2"
		statementName1 = "statement1"
		statementName2 = "statement2"
	)

	t.Cleanup(cleanupCaches)
	cfg := config.New()
	cfg.MaxPostgresStatsBuffered = 100
	s, err := NewStatkeeper(cfg)
	require.NoError(t, err)

	tup := ebpf.ConnTuple{
		Saddr_h:  0x01020304,
		Saddr_l:  0x05060708,
		Daddr_h:  0x090a0b0c,
		Daddr_l:  0x0d0e0f10,
		Sport:    4576,
		Dport:    5432,
		Netns:    0,
		Metadata: 0,
	}

	// We want to check all the stages of a full flow
	// This is the first message we should receive from ebpf side.

	////////////
	// Startup
	////////////
	e := NewEventWrapper(&ebpf.EbpfEvent{
		Tuple: tup,
		Tx: ebpf.EbpfTx{
			Request_fragment: createMessageFromString(StartupTag,
				fmt.Sprintf("user\x00xx\x00database\x00%s\x00\x00", databaseName)),
		},
	})

	s.Process(e)
	// we should have the database name in the table
	require.Equal(t, databaseName, e.getDatabaseName())
	require.Equal(t, UnknownOP, e.getSQLCommand())
	require.Equal(t, UnobservedString, e.getTableName())

	// we shouldn't have any stats yet
	require.Equal(t, 0, len(s.stats))

	////////////
	// Simple query
	////////////

	e = NewEventWrapper(&ebpf.EbpfEvent{
		Tuple: tup,
		Tx: ebpf.EbpfTx{
			Request_fragment:   createMessageFromString(QueryTag, fmt.Sprintf("CREATE TABLE %s (id int)", tableName1)),
			Request_started:    1,
			Response_last_seen: 10,
		},
	})
	s.Process(e)
	require.Equal(t, databaseName, e.getDatabaseName())
	require.Equal(t, CreateTableOP, e.getSQLCommand())
	require.Equal(t, tableName1, e.getTableName())
	require.Equal(t, 1, len(s.stats))

	key := Key{
		Operation:     e.getSQLCommand(),
		TableName:     e.getTableName(),
		ConnectionKey: e.ConnTuple(),
		DatabaseName:  e.getDatabaseName(),
	}

	requestStats, ok := s.stats[key]
	require.True(t, ok)
	require.Equal(t, requestStats.Count, 1)

	////////////
	// Parse a first statement
	////////////

	e = NewEventWrapper(&ebpf.EbpfEvent{
		Tuple: tup,
		Tx: ebpf.EbpfTx{
			Request_fragment: createMessageFromString(ParseTag, fmt.Sprintf("%s\x00INSERT INTO %s VALUES (1, 2, 3)", statementName1, tableName1)),
		},
	})
	s.Process(e)
	require.Equal(t, databaseName, e.getDatabaseName())
	// this is a parse message, we shouldn't have these values
	require.Equal(t, UnknownOP, e.getSQLCommand())
	require.Equal(t, UnobservedString, e.getTableName())
	// no new stats
	require.Equal(t, 1, len(s.stats))

	statCache, ok := statementsCache.Get(e.ConnTuple())
	require.True(t, ok)
	require.Equal(t, 1, statCache.Len())
	qInfo, ok := statCache.Get(statementName1)
	require.True(t, ok)
	require.Equal(t, queryInfo{tableName: tableName1, sqlCommand: InsertOP}, qInfo)

	////////////
	// Parse a second statement with the same name
	////////////

	// we have the same statement name but a different statement value
	e = NewEventWrapper(&ebpf.EbpfEvent{
		Tuple: tup,
		Tx: ebpf.EbpfTx{
			Request_fragment: createMessageFromString(ParseTag, fmt.Sprintf("%s\x00SELECT * FROM %s", statementName1, tableName2)),
		},
	})
	s.Process(e)
	require.Equal(t, databaseName, e.getDatabaseName())

	statCache, ok = statementsCache.Get(e.ConnTuple())
	require.True(t, ok)
	// always one value because we override the previous one
	require.Equal(t, 1, statCache.Len())

	qInfo, ok = statCache.Get(statementName1)
	require.True(t, ok)
	// we check if the overwrite worked
	require.Equal(t, queryInfo{tableName: tableName2, sqlCommand: SelectOP}, qInfo)

	////////////
	// Parse a second statement
	////////////

	e = NewEventWrapper(&ebpf.EbpfEvent{
		Tuple: tup,
		Tx: ebpf.EbpfTx{
			Request_fragment: createMessageFromString(ParseTag, fmt.Sprintf("%s\x00UPDATE %s SET json_prefs = (json_prefs)s, modified = '2015-08-27 22:10:32.492912' WHERE user_id = (user_id)s AND url = (url)s", statementName2, tableName2)),
		},
	})
	s.Process(e)

	statCache, ok = statementsCache.Get(e.ConnTuple())
	require.True(t, ok)
	require.Equal(t, 2, statCache.Len())

	// The old statement is still there untouched
	qInfo, ok = statCache.Get(statementName1)
	require.True(t, ok)
	require.Equal(t, queryInfo{tableName: tableName2, sqlCommand: SelectOP}, qInfo)

	qInfo, ok = statCache.Get(statementName2)
	require.True(t, ok)
	require.Equal(t, queryInfo{tableName: tableName2, sqlCommand: UpdateOP}, qInfo)

	////////////
	// Bind against the fist statement
	////////////

	e = NewEventWrapper(&ebpf.EbpfEvent{
		Tuple: tup,
		Tx: ebpf.EbpfTx{
			Request_fragment:   createMessageFromString(BindTag, fmt.Sprintf("PORTAL1\x00%s\x002342424242", statementName1)),
			Request_started:    1,
			Response_last_seen: 10,
		},
	})
	// we bind against statement one
	s.Process(e)

	require.Equal(t, databaseName, e.getDatabaseName())
	// These are the values of the statement 1
	require.Equal(t, SelectOP, e.getSQLCommand())
	require.Equal(t, tableName2, e.getTableName())

	// we have a new key so now we have 2 stats
	require.Equal(t, 2, len(s.stats))

	key = Key{
		Operation:     e.getSQLCommand(),
		TableName:     e.getTableName(),
		ConnectionKey: e.ConnTuple(),
		DatabaseName:  e.getDatabaseName(),
	}

	requestStats, ok = s.stats[key]
	require.True(t, ok)
	require.Equal(t, requestStats.Count, 1)

	////////////
	// Bind against the second statement
	////////////

	e = NewEventWrapper(&ebpf.EbpfEvent{
		Tuple: tup,
		Tx: ebpf.EbpfTx{
			Request_fragment:   createMessageFromString(BindTag, fmt.Sprintf("PORTAL\x00%s\x002342424242", statementName2)),
			Request_started:    1,
			Response_last_seen: 10,
		},
	})
	// we bind against statement one
	s.Process(e)

	require.Equal(t, databaseName, e.getDatabaseName())
	// These are the values of the statement 2
	require.Equal(t, UpdateOP, e.getSQLCommand())
	require.Equal(t, tableName2, e.getTableName())

	// we have a new key so now we have 2 stats
	require.Equal(t, 3, len(s.stats))

	key = Key{
		Operation:     e.getSQLCommand(),
		TableName:     e.getTableName(),
		ConnectionKey: e.ConnTuple(),
		DatabaseName:  e.getDatabaseName(),
	}

	requestStats, ok = s.stats[key]
	require.True(t, ok)
	require.Equal(t, requestStats.Count, 1)

	////////////
	// Close of the connection
	////////////

	e = NewEventWrapper(&ebpf.EbpfEvent{
		Tuple: tup,
		Tx: ebpf.EbpfTx{
			Request_fragment: createMessageTagOnly(TerminationTag),
		},
	})
	s.Process(e)
	// stats are untouched
	require.Equal(t, 3, len(s.stats))
	// we cannot retrieve the database name anymore
	require.Equal(t, UnobservedString, e.getDatabaseName())
	// we shouldn't have any statement anymore
	require.Equal(t, 0, statementsCache.Len())
}
