// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package postgres

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/go-sqllexer"
)

func TestExtractSQLCommand(t *testing.T) {
	tests := []struct {
		name       string
		mes        []byte
		sqlCommand Operation
	}{
		{
			name: "SELECT space",
			mes: []byte{
				'S', 'E', 'L', 'E', 'C', 'T', ' ', '*', ' ', 'F', 'R', 'O', 'M', ' ', 'p', 'r', 'o', 'f', 'i', 'l', 'e', 's',
			},
			sqlCommand: SelectOP,
		},
		{
			name: "SELECT no space",
			mes: []byte{
				'S', 'E', 'L', 'E', 'C', 'T',
			},
			sqlCommand: UnknownOP,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sqlComm := extractSQLCommand(tt.mes)
			require.EqualValues(t, tt.sqlCommand, sqlComm)
		})
	}
}

func TestExtractSQLCommandAndTable(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		tablesName string
		sqlComm    Operation
	}{
		{
			name:       "single table name",
			query:      `DROP TABLE IF EXISTS test1`,
			tablesName: "test1",
			sqlComm:    DropTableOP,
		},
		{
			name:       "extra space between if exists",
			query:      `DROP TABLE  IF  EXISTS test1`,
			tablesName: "test1",
			sqlComm:    DropTableOP,
		},
		{
			name:       "single table name with small caps",
			query:      `drop table if exists test1`,
			tablesName: "test1",
			sqlComm:    DropTableOP,
		},
		{
			name:       "single table name with mixed caps",
			query:      `drop TablE iF ExISts test1`,
			tablesName: "test1",
			sqlComm:    DropTableOP,
		},
		{
			name:       "no table name",
			query:      `DROP TABLE`,
			tablesName: "",
			sqlComm:    DropTableOP,
		},
		{
			name:       "SELECT",
			query:      `SELECT * FROM profiles WHERE name='Mary'`,
			tablesName: "profiles",
			sqlComm:    SelectOP,
		},
		{
			name:       "INSERT",
			query:      `INSERT INTO db VALUES (1, 2, 3)`,
			tablesName: "db",
			sqlComm:    InsertOP,
		},
		{
			name: "SELECT with a space before",
			// we cannot recognize a SELECT with a space before
			query:      ` SELECT * FROM profiles WHERE name='Mary'`,
			tablesName: "profiles",
			sqlComm:    UnknownOP,
		},
		{
			name:       "SHOW",
			query:      `SHOW param1 param2 param3`,
			tablesName: "",
			sqlComm:    ShowOP,
		},
	}
	n := sqllexer.NewNormalizer(sqllexer.WithCollectTables(true))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := extractSQLCommandAndTable(n, []byte(tt.query))
			require.EqualValues(t, tt.tablesName, q.tableName)
			require.EqualValues(t, tt.sqlComm, q.sqlCommand)
		})
	}
}

func TestExtractDatabaseName(t *testing.T) {
	tests := []struct {
		name         string
		startupMes   []byte
		databaseName string
	}{
		{
			name: "database after user",
			startupMes: []byte{
				'u', 's', 'e', 'r', 0,
				'X', 'X', 'X', 'X', 0,
				'd', 'a', 't', 'a', 'b', 'a', 's', 'e', 0,
				'Y', 'Y', 'Y', 'Y', 0, 0,
			},
			databaseName: "YYYY",
		},
		{
			name: "database before user",
			startupMes: []byte{
				'd', 'a', 't', 'a', 'b', 'a', 's', 'e', 0,
				'Y', 'Y', 0,
				'u', 's', 'e', 'r', 0,
				'X', 'X', 'X', 'X', 0, 0,
			},
			databaseName: "YY",
		},
		{
			name: "user only",
			startupMes: []byte{
				'u', 's', 'e', 'r', 0,
				'X', 'X', 'X', 'X', 0, 0,
			},
			databaseName: "XXXX",
		},
		{
			name: "database key only (truncated message)",
			startupMes: []byte{
				'u', 's', 'e', 'r', 0,
				'X', 'X', 'X', 'X', 0,
				'd', 'a', 't', 'a', 'b', 'a', 's', 'e', 0,
			},
			// we don't use the user name
			databaseName: "",
		},
		{
			name: "database key truncated",
			startupMes: []byte{
				'u', 's', 'e', 'r', 0,
				'X', 'X', 'X', 'X', 0,
				'd', 'a', 't', 'a', 'b', 'a', 's', 'e',
			},
			// we don't recognize the database key because it is null terminated so we don't erase the user name
			databaseName: "XXXX",
		},
		{
			name: "database key truncated 2",
			startupMes: []byte{
				'u', 's', 'e', 'r', 0,
				'X', 'X', 'X', 'X', 0,
				'd', 'a', 't', 'a', 'b', 'a', 's',
			},
			databaseName: "XXXX",
		},
		{
			name: "user truncated",
			startupMes: []byte{
				'u', 's', 'e', 'r', 0,
				'X', 'X', 'X', 'X',
			},
			// the user name is truncated we don't want it
			databaseName: "",
		},
		{
			name: "no database no user",
			startupMes: []byte{
				'o', 'p', 't', '1', 0,
				'X', 'X', 'X', 'X', 0,
				'o', 'p', 't', '2', 0,
				'X', 'X', 'X', 'y', 0, 0,
			},
			databaseName: "",
		},
		{
			name: "truncated user key",
			startupMes: []byte{
				'u', 's', 'e',
			},
			databaseName: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := extractDatabaseName([]byte(tt.startupMes))
			require.EqualValues(t, tt.databaseName, name)
		})
	}
}

func TestExtractStatementFromParse(t *testing.T) {
	tests := []struct {
		name          string
		parseMes      []byte
		statementName string
		qinfo         queryInfo
	}{
		{
			name: "not empty statement",
			parseMes: []byte{
				'e', 'c', 'h', 'o', '7', '7', 0,
				'S', 'E', 'L', 'E', 'C', 'T',
			},
			statementName: "echo77",
			qinfo: queryInfo{
				// we need a space to detect the SQL command
				sqlCommand: UnknownOP,
				tableName:  "",
			},
		},
		{
			name: "empty statement",
			parseMes: []byte{
				0,
				'S', 'E', 'L', 'E', 'C', 'T',
			},
			statementName: "",
		},
		{
			name: "statement+query",
			parseMes: append([]byte{
				'e', 'c', 'h', 'o', '7', '7', 0,
			}, []byte("INSERT INTO db VALUES (1, 2, 3)")...),
			statementName: "echo77",
			qinfo: queryInfo{
				sqlCommand: InsertOP,
				tableName:  "db",
			},
		},
	}
	n := sqllexer.NewNormalizer(sqllexer.WithCollectTables(true))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, q := extractStatementFromParse(n, tt.parseMes)
			require.EqualValues(t, tt.statementName, name)
			require.EqualValues(t, tt.qinfo, q)
		})
	}
}
