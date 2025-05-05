// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package postgres

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/DataDog/go-sqllexer"
	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/DataDog/datadog-agent/pkg/network/protocols"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/postgres/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/types"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	userKey     = "user"
	databaseKey = "database"
	// it should be proportional to the number of Postgres connections on the host
	databaseNameCacheDim = 1000
	// it should be proportional to the number of Postgres connections on the host, lower than the database name cache because the value is bigger
	statementsCacheDim = 500
	// it should be proportional to the number of statements in a Postgres connection
	queryInfoCacheDim = 500
)

var (
	// Each TCP connection can be associated with just one database during authentication.
	databaseNamesCache *lru.Cache[types.ConnectionKey, string]
	statementsCache    *lru.Cache[types.ConnectionKey, *lru.Cache[string, queryInfo]]
	postgresDBMS       = sqllexer.WithDBMS(sqllexer.DBMSPostgres)
)

func cleanupCaches() {
	databaseNamesCache.Purge()
	databaseNamesCache = nil
	statementsCache.Purge()
	statementsCache = nil
}

func initializeCaches() error {
	var err error
	databaseNamesCache, err = lru.New[types.ConnectionKey, string](databaseNameCacheDim)
	if err != nil {
		return err
	}

	statementsCache, err = lru.New[types.ConnectionKey, *lru.Cache[string, queryInfo]](statementsCacheDim)
	if err != nil {
		return err
	}
	return nil
}

type queryInfo struct {
	sqlCommand Operation
	tableName  string
}

func newQueryInfo() queryInfo {
	return queryInfo{
		sqlCommand: UnknownOP,
		tableName:  UnsupportedString,
	}
}

// EventWrapper wraps an ebpf event and provides additional methods to extract information from it.
// We use this wrapper to avoid recomputing the same values (operation and table name) multiple times.
type EventWrapper struct {
	*ebpf.EbpfEvent
	payload    []byte
	info       queryInfo
	normalizer *sqllexer.Normalizer
}

// NewEventWrapper creates a new EventWrapper from an ebpf event.
func NewEventWrapper(e *ebpf.EbpfEvent) *EventWrapper {
	return &EventWrapper{
		EbpfEvent:  e,
		normalizer: sqllexer.NewNormalizer(sqllexer.WithCollectTables(true)),
		info:       newQueryInfo(),
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
	var userName string

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
			userName = ""
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

	if userName == "" {
		userName = UnsupportedString
	}
	return userName
}

func extractSQLCommand(payload []byte) Operation {
	// Some simple queries have the following format
	// (1 byte) -> Q
	// (4 bytes) -> 11 (4+7)
	// (7 bytes) -> "commit\0"
	// or
	// (1 byte) -> Q
	// (4 bytes) -> 10 (4+6)
	// (6 bytes) -> "begin\0"
	//
	// Here we just want to extract the operation for the main methods (SELECT, INSERT, UPDATE, DELETE, etc...)
	// so we don't look for the first `\0` but just for the first space.
	idx := bytes.IndexByte(payload, ' ')
	if idx == -1 {
		return UnknownOP
	}
	return FromString(string(payload[:idx]))
}

func extractSQLCommandAndTable(n *sqllexer.Normalizer, payload []byte) queryInfo {
	// Extract the table name. This is implemented by Datadog and seems able to extract only the table name.
	// todo!: Maybe we can evaluate other parsers to extract also the SQL command since today our detection is partial. https://github.com/xwb1989/sqlparser
	// We need to evaluate what is the overhead in term of perfomance. We can use the go benchmark built-in
	_, statementMetadata, err := n.Normalize(string(payload), postgresDBMS)
	qinfo := newQueryInfo()
	if err != nil {
		log.Warnf("unable to normalize SQL query due to: %s", err)
	} else if len(statementMetadata.Tables) != 0 && statementMetadata.Tables[0] != "" {
		// Currently, we do not support complex queries with multiple tables. Therefore, we will return only a single table.
		qinfo.tableName = statementMetadata.Tables[0]
	}
	qinfo.sqlCommand = extractSQLCommand(payload)
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
		log.Warnf("Postgres Parse message: Statement name too long: %s", payload)
		return "", newQueryInfo()
	}
	// extract the command and the table from the query
	if len(payload)-idx < 4 {
		// small optimization to avoid calling the normalizer if we don't have a query
		return string(payload[:idx]), newQueryInfo()
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
		log.Warnf("Postgres Bind message: Portal name too long: %s", payload)
		// this could be wrong we are returning an empty statement that is a valid one
		return ""
	}

	idx := bytes.IndexByte(payload[firstIdx+1:], 0)
	if idx == -1 {
		log.Warnf("Postgres Bind message: statement name too long: %s", payload)
		// this could be wrong we are returning an empty statement that is a valid one
		return ""
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

const template = `
ebpfTx{
	Operation: %q,
	Table Name: %q,
	Latency: %f
}`

// String returns a string representation of the underlying event
func (e *EventWrapper) String() string {
	var output strings.Builder
	output.WriteString(fmt.Sprintf(template, e.getSQLCommand(), e.getTableName(), e.RequestLatency()))
	return output.String()
}

// Operation returns the operation of the query (SELECT, INSERT, UPDATE, DROP, etc.)
func (e *EventWrapper) getSQLCommand() Operation {
	return e.info.sqlCommand
}

func (e *EventWrapper) getTableName() string {
	return e.info.tableName
}

func (e *EventWrapper) getDatabaseName() string {
	name, ok := databaseNamesCache.Get(e.ConnTuple())
	if !ok {
		name = UnsupportedString
	}
	return name
}

func (e *EventWrapper) getTag() byte {
	return e.Tx.Request_fragment[0]
}

func (e *EventWrapper) getPayload() []byte {
	return e.payload
}

func (e *EventWrapper) setPayload() {
	l := uint32(binary.BigEndian.Uint32(e.Tx.Request_fragment[1:5]))
	// This is possible only in 2 cases:
	// 1. The postgres message has no payload (len==4) (e.g. Sync)
	// 2. We cannot correctly read the fragment from the kernel at it contains all 0 (so len=0)
	if l == 4 || l == 0 {
		return
	}

	if l > uint32(len(e.Tx.Request_fragment)) {
		e.payload = e.Tx.Request_fragment[5:len(e.Tx.Request_fragment)]
	} else {
		e.payload = e.Tx.Request_fragment[5:l]
	}
}

func (e *EventWrapper) handleStartup() {
	databaseNamesCache.Add(e.ConnTuple(), extractDatabaseName(e.getPayload()))
}

func (e *EventWrapper) handleParse() {
	statementName, info := extractStatementFromParse(e.normalizer, e.getPayload())
	qiCache, ok := statementsCache.Get(e.ConnTuple())
	if !ok {
		var err error
		qiCache, err = lru.New[string, queryInfo](queryInfoCacheDim)
		if err != nil {
			log.Warnf("Unable to create the query info cache for connection: %v.%s", e.ConnTuple(), err)
			return
		}
		statementsCache.Add(e.ConnTuple(), qiCache)
	}
	// if there is a statement with the same name we overwrite it.
	qiCache.Add(statementName, info)
}

func (e *EventWrapper) handleBind() {
	m, ok := statementsCache.Get(e.ConnTuple())
	// if we don't find it we cannot do anything
	if !ok {
		return
	}

	statementName := extractStatementNameFromBind(e.getPayload())
	q, ok := m.Get(statementName)
	if !ok {
		return
	}
	e.info = q
}

func (e *EventWrapper) handleQuery() {
	e.info = extractSQLCommandAndTable(e.normalizer, e.getPayload())
}

func (e *EventWrapper) handleTermination() {
	tup := e.ConnTuple()
	databaseNamesCache.Remove(tup)
	if inner, ok := statementsCache.Get(tup); ok {
		// clear all of its entries
		inner.Purge()
	}
	statementsCache.Remove(tup)
}

// process return true if we are only populating the status and we don't need to update the stats
func (e *EventWrapper) process() bool {
	e.setPayload()
	switch e.getTag() {
	case EmptyTag:
		log.Warn("Postgres message with empty tag")
		// we will return immediately
		return true
	case StartupTag:
		e.handleStartup()
		return true
	case ParseTag:
		e.handleParse()
		return true
	case BindTag:
		e.handleBind()
		return false
	case QueryTag:
		e.handleQuery()
		return false
	case TerminationTag:
		e.handleTermination()
		return true
	default:
		// this is worring enough to panic
		panic("unknown postgres message type")
	}
}
