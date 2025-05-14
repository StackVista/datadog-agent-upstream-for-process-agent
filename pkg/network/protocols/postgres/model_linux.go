// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package postgres

import (
	"bytes"
	"encoding/binary"

	"github.com/DataDog/go-sqllexer"

	"github.com/DataDog/datadog-agent/pkg/network/protocols"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/postgres/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/types"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	userKey           = "user"
	databaseKey       = "database"
	logPostgresPrefix = "[postgres]: "
)

var (
	// Each TCP connection can be associated with just one database during authentication.
	postgresDBMS = sqllexer.WithDBMS(sqllexer.DBMSPostgres)
)

type queryInfo struct {
	sqlCommand Operation
	tableName  string
}

func logPostgres(level log.LogLevel, format string, params ...interface{}) {
	switch level {
	case log.InfoLvl:
		log.Infof(logPostgresPrefix+format, params...)
	case log.DebugLvl:
		log.Debugf(logPostgresPrefix+format, params...)
	case log.WarnLvl:
		log.Warnf(logPostgresPrefix+format, params...)
	case log.ErrorLvl:
		log.Errorf(logPostgresPrefix+format, params...)
	default:
		panic("invalid log level")
	}
}

func unobservedQueryInfo() queryInfo {
	return queryInfo{
		sqlCommand: UnobservedOP,
		tableName:  UnobservedString,
	}
}

func unsupportedQueryInfo() queryInfo {
	return queryInfo{
		sqlCommand: UnsupportedOP,
		tableName:  UnsupportedString,
	}
}

// EventWrapper wraps an ebpf event and provides additional methods to extract information from it.
// We use this wrapper to avoid recomputing the same values (operation and table name) multiple times.
type EventWrapper struct {
	*ebpf.EbpfEvent
	payload    []byte
	normalizer *sqllexer.Normalizer
}

// NewEventWrapper creates a new EventWrapper from an ebpf event.
func NewEventWrapper(e *ebpf.EbpfEvent) *EventWrapper {
	return &EventWrapper{
		EbpfEvent:  e,
		normalizer: sqllexer.NewNormalizer(sqllexer.WithCollectTables(true)),
	}
}

// ConnTuple returns the connection tuple for the transaction
func (e *EventWrapper) ConnTuple() types.ConnectionKey {
	return types.ConnectionKey{
		SrcIPHigh: e.Tuple.Saddr_h,
		SrcIPLow:  e.Tuple.Saddr_l,
		DstIPHigh: e.Tuple.Daddr_h,
		DstIPLow:  e.Tuple.Daddr_l,
		SrcPort:   e.Tuple.Sport,
		DstPort:   e.Tuple.Dport,
		NetNs:     e.Tuple.Netns,
	}
}

func extractDatabaseName(payload []byte) string {
	// we see the startup message so if at the end of this method we don't have a database name
	// it means this is a limit of our instrumentation, so unsupported
	userName := UnsupportedString

	i := 0
	for i < len(payload) {
		// search the key
		kEnd := bytes.IndexByte(payload[i:], 0)
		if kEnd == -1 {
			// key truncated
			break
		}
		key := string(payload[i : i+kEnd])
		// if we see the database key we should invalidate the user name even if the database value will be truncated.
		// we know that there is a database value and we don't want to use the user one.
		if key == databaseKey {
			// unsupported because if we see it and we cannot obtain it is a limit in our instrumentation.
			userName = UnsupportedString
		}

		// search the value
		i += kEnd + 1
		if i >= len(payload) {
			break
		}
		// value end relative to i
		vEndRel := bytes.IndexByte(payload[i:], 0)
		if vEndRel == -1 {
			// value truncated
			break
		}
		value := string(payload[i : i+vEndRel])

		switch key {
		case databaseKey:
			return value
		case userKey:
			// we store it but we continue because we could face the database key later
			// If the `database` string is not present by default the postgres protocol uses the user name
			// https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-STARTUPMESSAGE
			userName = value
		}

		i += vEndRel + 1
	}
	return userName
}

func extractSQLCommandAndTable(n *sqllexer.Normalizer, payload []byte) queryInfo {
	// Extract the table name. This is implemented by Datadog and seems able to extract only the table name.
	// todo!: Maybe we can evaluate other parsers to extract also the SQL command since today our detection is partial. https://github.com/xwb1989/sqlparser
	// We need to evaluate what is the overhead in term of perfomance. We can use the go benchmark built-in
	qinfo := unsupportedQueryInfo()
	qinfo.sqlCommand = extractSQLCommand(payload)
	if !hasTable(qinfo.sqlCommand) {
		qinfo.tableName = EmptyTableName
		return qinfo
	}

	_, statementMetadata, err := n.Normalize(string(payload), postgresDBMS)
	if err != nil {
		logPostgres(log.WarnLvl, "unable to normalize SQL query due to: %s. original query: %s", err, payload)
	} else if len(statementMetadata.Tables) == 0 || statementMetadata.Tables[0] == "" {
		logPostgres(log.DebugLvl, "no table name found. original query: %s", payload)
	} else {
		// Currently, we do not support complex queries with multiple tables. Therefore, we will return only a single table.
		qinfo.tableName = statementMetadata.Tables[0]
	}
	return qinfo
}

func extractStatementFromParse(n *sqllexer.Normalizer, payload []byte) (string, queryInfo) {
	// https: //www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-PARSE
	// We have 2 consecutive stings:
	// 1. The statement name (could be empty for unnamed prepared statements)
	// 2. The query string
	// ...other data...

	// Search for the first null byte
	idx := bytes.IndexByte(payload, 0)
	if idx == -1 {
		logPostgres(log.DebugLvl, "Parse message: statement name too long: truncated statement: %s", payload)
		return UnsupportedString, unsupportedQueryInfo()
	}
	// extract the command and the table from the query
	if len(payload)-idx < 4 {
		// small optimization to avoid calling the normalizer if we don't have a query
		return string(payload[:idx]), unsupportedQueryInfo()
	}
	return string(payload[:idx]), extractSQLCommandAndTable(n, payload[idx+1:])
}

func extractStatementNameFromBind(payload []byte) string {
	// https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-BIND
	// We have 2 consecutive stings:
	// 1. The portal name (we are not intested in it) so we will skip it
	// 2. The statament name
	// ...other data...

	// Search for the first null byte
	firstIdx := bytes.IndexByte(payload, 0)
	if firstIdx == -1 {
		logPostgres(log.InfoLvl, "Bind message: Portal name too long: %s", payload)
		// this could be wrong we are returning an empty statement that is a valid one
		return UnsupportedString
	}

	idx := bytes.IndexByte(payload[firstIdx+1:], 0)
	if idx == -1 {
		logPostgres(log.InfoLvl, "Bind message: statement name too long: truncated statement: %s", payload)
		return UnsupportedString
	}

	// extract the command and the table from the query
	return string(payload[firstIdx+1 : firstIdx+1+idx])
}

// RequestLatency returns the latency of the request in nanoseconds
func (e *EventWrapper) RequestLatency() float64 {
	if uint64(e.Tx.Request_started) == 0 || uint64(e.Tx.Response_last_seen) == 0 {
		return 0
	}
	return protocols.NSTimestampToFloat(e.Tx.Response_last_seen - e.Tx.Request_started)
}

func (e *EventWrapper) getTag() byte {
	return e.Tx.Request_fragment[0]
}

func (e *EventWrapper) getPayload() []byte {
	return e.payload
}

func (e *EventWrapper) setPayload() {
	// We call this method only when we are sure we have a valid postgres messages.
	// +1 because we want to consider the tag since we will compare it with our fragment len (that contains the tag)
	l := uint32(binary.BigEndian.Uint32(e.Tx.Request_fragment[1:5])) + 1

	if l > uint32(len(e.Tx.Request_fragment)) {
		e.payload = e.Tx.Request_fragment[5:]
	} else {
		e.payload = e.Tx.Request_fragment[5:l]
	}
}

func (e *EventWrapper) setStartupPayload() {
	// the len is always in the same position of the other messages
	// this len contains self + payload but not the 3 bytes of junk and the tag.
	// so we sum 4
	l := uint32(binary.BigEndian.Uint32(e.Tx.Request_fragment[1:5])) + 4
	if l > uint32(len(e.Tx.Request_fragment)) {
		// 1 byte - tag
		// 4 bytes - len
		// 3 bytes - junk
		// payload (we start from 8)
		e.payload = e.Tx.Request_fragment[8:]
	} else {
		e.payload = e.Tx.Request_fragment[8:l]
	}
}
