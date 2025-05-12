// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package postgres

import (
	"fmt"
	"sync"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/types"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	lru "github.com/hashicorp/golang-lru/v2"
)

const (
	// it should be proportional to the number of Postgres connections on the host
	databaseNameCacheDim = 1024
	// it should be proportional to the number of Postgres statements
	statementsCacheDim = 1024
)

type statementConnection struct {
	conn          types.ConnectionKey
	statementName string
}

// StatKeeper is a struct to hold the records for the postgres protocol
type StatKeeper struct {
	stats               map[Key]*RequestStat
	missingDatabaseName map[types.ConnectionKey]map[queryInfo]*RequestStat
	missingStatement    map[statementConnection]*RequestStat
	telemetry           *Telemetry

	statsMutex sync.RWMutex
	maxEntries int

	// Each TCP connection can be associated with just one database during authentication.
	databaseNamesCache *lru.Cache[types.ConnectionKey, string]
	statementsCache    *lru.Cache[statementConnection, queryInfo]
}

// NewStatkeeper creates a new StatKeeper
func NewStatkeeper(c *config.Config, t *Telemetry) (*StatKeeper, error) {
	newStatKeeper := &StatKeeper{
		maxEntries: c.MaxPostgresStatsBuffered,
		telemetry:  t,
	}
	newStatKeeper.resetNoLock()

	var err error
	newStatKeeper.databaseNamesCache, err = lru.New[types.ConnectionKey, string](databaseNameCacheDim)
	if err != nil {
		return nil, fmt.Errorf("could not create database names cache: %v", err)
	}

	newStatKeeper.statementsCache, err = lru.New[statementConnection, queryInfo](statementsCacheDim)
	if err != nil {
		return nil, fmt.Errorf("could not create statements cache: %v", err)
	}

	return newStatKeeper, nil
}

// Process processes the postgres transaction
func (s *StatKeeper) Process(e *EventWrapper) {
	// we need a lock for 2 main reasons:
	// 1 - Multiple threads can be calling this function at the same time. If we call Sync() each CPU calls it.
	// 2 - While we are here someone could read the stats. See `GetAndResetAllStats()`
	s.statsMutex.Lock()
	defer s.statsMutex.Unlock()

	e.setPayload()
	switch e.getTag() {
	case EmptyTag:
		logPostgres(log.WarnLvl, "Postgres message with empty tag")
	case StartupTag:
		s.handleStartup(e)
	case ParseTag:
		s.handleParse(e)
	case QueryTag:
		s.handleQuery(e)
	case BindTag:
		s.handleBind(e)
	default:
		// this is worring enough to panic
		panic("unknown postgres message type")
	}
}

// GetAndResetAllStats returns all the records and resets the statskeeper
func (s *StatKeeper) GetAndResetAllStats() map[Key]*RequestStat {
	s.statsMutex.Lock()
	defer func() {
		s.statsMutex.Unlock()
		s.telemetry.Log()
	}()

	// clear arrays and put unobserved in the caches
	for conn, queries := range s.missingDatabaseName {
		s.databaseNamesCache.Add(conn, UnobservedString)
		s.telemetry.missingDatabaseName.Add(1)
		for queryInfo, reqStat := range queries {
			key := Key{
				Operation:     queryInfo.sqlCommand,
				TableName:     queryInfo.tableName,
				ConnectionKey: conn,
				DatabaseName:  UnobservedString,
			}
			s.addReqStat(key, reqStat)
			delete(queries, queryInfo)
		}
	}
	for k, stats := range s.missingStatement {
		s.statementsCache.Add(k, unobservedQueryInfo())
		s.telemetry.missingStatement.Add(1)
		dbName, ok := s.databaseNamesCache.Get(k.conn)
		if !ok {
			s.telemetry.missingDatabaseName.Add(1)
			s.databaseNamesCache.Add(k.conn, UnobservedString)
			dbName = UnobservedString
		}

		key := Key{
			Operation:     UnobservedOP,
			TableName:     UnobservedString,
			ConnectionKey: k.conn,
			DatabaseName:  dbName,
		}
		s.addReqStat(key, stats)
	}
	ret := s.stats // No deep copy needed since `s.statskeeper` gets reset
	s.resetNoLock()
	return ret
}

func (s *StatKeeper) resetNoLock() {
	s.stats = make(map[Key]*RequestStat)
	s.missingDatabaseName = make(map[types.ConnectionKey]map[queryInfo]*RequestStat)
	s.missingStatement = make(map[statementConnection]*RequestStat)
}

func (s *StatKeeper) handleStartup(e *EventWrapper) {
	dbName := extractDatabaseName(e.getPayload())
	if dbName == UnsupportedString {
		s.telemetry.failedDatabaseNameExtraction.Add(1)
	}
	s.databaseNamesCache.Add(e.ConnTuple(), dbName)

	queries, ok := s.missingDatabaseName[e.ConnTuple()]
	if !ok {
		// we don't have data waiting for the database name
		return
	}

	// we now have the database name we can populate the stats.
	for queryInfo, stats := range queries {
		key := Key{
			Operation:     queryInfo.sqlCommand,
			TableName:     queryInfo.tableName,
			ConnectionKey: e.ConnTuple(),
			DatabaseName:  dbName,
		}
		s.addReqStat(key, stats)
		delete(queries, queryInfo)
	}
	delete(s.missingDatabaseName, e.ConnTuple())
}

func (s *StatKeeper) handleParse(e *EventWrapper) {
	statementName, info := extractStatementFromParse(e.normalizer, e.getPayload())
	if statementName == UnsupportedString {
		// it means we have no information about the query, there is no reason to add it to the cache
		s.telemetry.failedParseStatementExtraction.Add(1)
		return
	}
	s.telemetry.queryInfoTelemetry(&info)

	stsConnection := statementConnection{
		conn:          e.ConnTuple(),
		statementName: statementName,
	}

	s.statementsCache.Add(stsConnection, info)

	stats, ok := s.missingStatement[stsConnection]
	if !ok {
		// we don't have data waiting for the statement name
		return
	}

	// if we have the database name we can populate the stats otherwise we need to wait for the startup
	dbName, ok := s.databaseNamesCache.Get(e.ConnTuple())
	if ok {
		key := Key{
			Operation:     info.sqlCommand,
			TableName:     info.tableName,
			ConnectionKey: e.ConnTuple(),
			DatabaseName:  dbName,
		}
		s.addReqStat(key, stats)
	} else {
		if _, ok := s.missingDatabaseName[e.ConnTuple()]; !ok {
			s.missingDatabaseName[e.ConnTuple()] = make(map[queryInfo]*RequestStat)
		}
		s.missingDatabaseName[e.ConnTuple()][info] = stats
	}
	delete(s.missingStatement, stsConnection)
}

func (s *StatKeeper) handleBind(e *EventWrapper) {
	// we try to extract the statement from the Bind
	statementName := extractStatementNameFromBind(e.getPayload())

	// if we have an unsupported statement we will fallback in the case `okStatement` = true
	var info queryInfo
	var okStatement bool
	stsConnection := statementConnection{
		conn:          e.ConnTuple(),
		statementName: statementName,
	}

	if statementName == UnsupportedString {
		s.telemetry.failedBindStatementExtraction.Add(1)
		info = queryInfo{
			tableName:  UnsupportedString,
			sqlCommand: UnsupportedOP,
		}
		// we don't need the parse because we don't have a valid statement name so we cannot do anything.
		okStatement = true
	} else {
		// we have a valid statement name so we try to recover it from the table.
		info, okStatement = s.statementsCache.Get(stsConnection)
	}

	// we have 3 cases:
	dbName, okDB := s.databaseNamesCache.Get(e.ConnTuple())
	switch {
	// 1 - we have the database name and the statement name -> we add a new stat
	case okDB && okStatement:
		key := Key{
			Operation:     info.sqlCommand,
			TableName:     info.tableName,
			ConnectionKey: e.ConnTuple(),
			DatabaseName:  dbName,
		}
		s.addLatency(key, e.RequestLatency())
	// 2 - we have the statement name but not the database name -> we need to wait for the startup
	case !okDB && okStatement:
		s.addMissingDatabaseEntry(e.ConnTuple(), info, e.RequestLatency())
	// 3 - we don't have the statement name -> we need to wait for the parse and maybe also the startup but we don't care here.
	default:
		s.addMissingStatementEntry(e.ConnTuple(), stsConnection, e.RequestLatency())
	}
}

func (s *StatKeeper) handleQuery(e *EventWrapper) {
	// We try to extract the SQL command and the table name from the query.
	// If we don't recognize the SQL command we set it to unsupported.
	info := extractSQLCommandAndTable(e.normalizer, e.getPayload())
	s.telemetry.queryInfoTelemetry(&info)

	// we have 2 cases:
	// 1 - we have the database name -> we create a new stat
	// 2 - we don't have the database name -> we need to wait for the startup in the missingDatabase table
	if dbName, ok := s.databaseNamesCache.Get(e.ConnTuple()); ok {
		key := Key{
			Operation:     info.sqlCommand,
			TableName:     info.tableName,
			ConnectionKey: e.ConnTuple(),
			DatabaseName:  dbName,
		}
		s.addLatency(key, e.RequestLatency())
		return
	}
	s.addMissingDatabaseEntry(e.ConnTuple(), info, e.RequestLatency())
}

func (s *StatKeeper) addLatency(key Key, latency float64) {
	requestStats, ok := s.stats[key]
	if ok {
		requestStats.addLatency(latency)
		return
	}

	// We need to create a new RequestStat
	if len(s.stats) >= s.maxEntries {
		logPostgres(log.WarnLvl, "Reached max number of stats: %d", s.maxEntries)
		return
	}
	stats, err := newRequestStats(latency)
	if err != nil {
		return
	}
	s.stats[key] = stats
}

func (s *StatKeeper) addReqStat(key Key, reqStat *RequestStat) {
	requestStats, ok := s.stats[key]
	if ok {
		requestStats.CombineWith(reqStat)
		return
	}
	if len(s.stats) >= s.maxEntries {
		logPostgres(log.WarnLvl, "Reached max number of stats: %d", s.maxEntries)
		return
	}
	s.stats[key] = reqStat
}

func (s *StatKeeper) addMissingStatementEntry(conn types.ConnectionKey, statementConn statementConnection, latency float64) {
	if requestStats, ok := s.missingStatement[statementConn]; ok {
		requestStats.addLatency(latency)
		return
	}

	requestStats, err := newRequestStats(latency)
	if err != nil {
		return
	}
	s.missingStatement[statementConn] = requestStats
}

func (s *StatKeeper) addMissingDatabaseEntry(conn types.ConnectionKey, info queryInfo, latency float64) {
	if _, ok := s.missingDatabaseName[conn]; !ok {
		s.missingDatabaseName[conn] = make(map[queryInfo]*RequestStat)
	}

	if requestStats, ok := s.missingDatabaseName[conn][info]; ok {
		requestStats.addLatency(latency)
		return
	}

	requestStats, err := newRequestStats(latency)
	if err != nil {
		return
	}
	s.missingDatabaseName[conn][info] = requestStats
}
