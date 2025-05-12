// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package postgres

import (
	"strings"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// Operation represents a postgres query operation supported by our decoder.
type Operation uint8

const (
	UnobservedString  = "<unobserved>"
	UnsupportedString = "<unsupported>"
	EmptyTableName    = ""
)

const (
	// UnobservedOP represents an operation we don't receive from ebpf.
	UnobservedOP Operation = iota
	// SelectOP represents a SELECT operation.
	SelectOP
	// InsertOP represents an INSERT operation.
	InsertOP
	// UpdateOP represents an UPDATE operation.
	UpdateOP
	// CreateTableOP represents a CREATE TABLE operation.
	CreateTableOP
	// DropTableOP represents a DROP TABLE operation.
	DropTableOP
	// DeleteTableOP represents a DELETE TABLE operation.
	DeleteTableOP
	// AlterTableOP represents an ALTER TABLE operation.
	AlterTableOP
	// TruncateTableOP represents a TRUNCATE operation.
	TruncateTableOP
	// ShowOP represents a command SHOW
	ShowOP
	// BeginOP represents a command BEGIN
	BeginOP
	// CommitOP represents a command COMMIT
	CommitOP
	// RollbackOP represents a command ROLLBACK
	RollbackOP
	// LockOP represents a command LOCK
	LockOP
	// UnsupportedOP represents something we cannot parse correctly
	UnsupportedOP
)

var (
	commands = map[Operation]string{
		SelectOP:        "SELECT",
		InsertOP:        "INSERT",
		UpdateOP:        "UPDATE",
		CreateTableOP:   "CREATE",
		DropTableOP:     "DROP",
		DeleteTableOP:   "DELETE",
		AlterTableOP:    "ALTER",
		TruncateTableOP: "TRUNCATE",
		ShowOP:          "SHOW",
		BeginOP:         "BEGIN",
		CommitOP:        "COMMIT",
		RollbackOP:      "ROLLBACK",
		LockOP:          "LOCK",
	}
)

// String returns the string representation of the operation.
func (op Operation) String() string {
	switch op {
	case UnobservedOP:
		return UnobservedString
	case UnsupportedOP:
		return UnsupportedString
	default:
		if command, ok := commands[op]; ok {
			return command
		}
		panic("unrecognized operation")
	}
}

func extractSQLCommand(payload []byte) Operation {
	// some operations have a space after them others have a \0 (e.g. "commit\0", "select ")
	// so we check for a prefix match
	payloadStr := strings.ToUpper(string(payload))
	for op, strOP := range commands {
		if strings.HasPrefix(payloadStr, strOP) {
			return op
		}
	}
	logPostgres(log.InfoLvl, "unrecognized SQL command `%s`", string(payload))
	return UnsupportedOP
}

func hasTable(op Operation) bool {
	switch op {
	case SelectOP, InsertOP, UpdateOP, DeleteTableOP, TruncateTableOP, CreateTableOP, DropTableOP, AlterTableOP, LockOP:
		return true
	// UnsupportedOP means that we don't know if it has a table or not, so by default we assume it has none
	case ShowOP, BeginOP, CommitOP, RollbackOP, UnsupportedOP:
		return false
	// UnobservedOP shoule be never called that's the reason why we don't handle it
	default:
		panic("unrecognized operation")
	}
}
