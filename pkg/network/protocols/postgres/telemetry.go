// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux_bpf

package postgres

import (
	libtelemetry "github.com/DataDog/datadog-agent/pkg/network/protocols/telemetry"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// Telemetry is a struct to hold the telemetry for the postgres protocol
type Telemetry struct {
	metricGroup *libtelemetry.MetricGroup

	unsupportedSQLOperation        *libtelemetry.Counter
	unsupportedTableName           *libtelemetry.Counter
	failedBindStatementExtraction  *libtelemetry.Counter
	failedParseStatementExtraction *libtelemetry.Counter
	missingDatabaseName            *libtelemetry.Counter
	missingStatement               *libtelemetry.Counter
	failedDatabaseNameExtraction   *libtelemetry.Counter
}

type TelemetryValues struct {
	unsupportedSQLOperation        int64
	unsupportedTableName           int64
	failedBindStatementExtraction  int64
	failedParseStatementExtraction int64
	missingDatabaseName            int64
	missingStatement               int64
	failedDatabaseNameExtraction   int64
}

func (t *Telemetry) getTelemetryValues() TelemetryValues {
	return TelemetryValues{
		unsupportedSQLOperation:        t.unsupportedSQLOperation.Get(),
		unsupportedTableName:           t.unsupportedTableName.Get(),
		failedBindStatementExtraction:  t.failedBindStatementExtraction.Get(),
		failedParseStatementExtraction: t.failedParseStatementExtraction.Get(),
		missingDatabaseName:            t.missingDatabaseName.Get(),
		missingStatement:               t.missingStatement.Get(),
		failedDatabaseNameExtraction:   t.failedDatabaseNameExtraction.Get(),
	}
}

// NewTelemetry creates a new Telemetry
func NewTelemetry() *Telemetry {
	metricGroup := libtelemetry.NewMetricGroup("usm.postgres")

	return &Telemetry{
		metricGroup:                    metricGroup,
		missingDatabaseName:            metricGroup.NewCounter("missing_database_name", libtelemetry.OptStatsd),
		missingStatement:               metricGroup.NewCounter("missing_statement", libtelemetry.OptStatsd),
		unsupportedTableName:           metricGroup.NewCounter("unsupported_table_name", libtelemetry.OptStatsd),
		unsupportedSQLOperation:        metricGroup.NewCounter("unsupported_sql_operation", libtelemetry.OptStatsd),
		failedBindStatementExtraction:  metricGroup.NewCounter("failed_bind_statement_extraction", libtelemetry.OptStatsd),
		failedParseStatementExtraction: metricGroup.NewCounter("failed_parse_statement_extraction", libtelemetry.OptStatsd),
		failedDatabaseNameExtraction:   metricGroup.NewCounter("failed_database_name_extraction", libtelemetry.OptStatsd),
	}
}

func (t *Telemetry) queryInfoTelemetry(qi *queryInfo) {
	if qi.sqlCommand == UnsupportedOP {
		t.unsupportedSQLOperation.Add(1)
	}
	if qi.tableName == UnsupportedString {
		t.unsupportedTableName.Add(1)
	}
}

// Log logs the postgres stats summary
func (t *Telemetry) Log() {
	log.Infof("postgres stats summary: %s", t.metricGroup.Summary())
}
