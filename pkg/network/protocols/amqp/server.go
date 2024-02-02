// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package amqp

import (
	"regexp"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/network/protocols/http/testutil"
	protocolsUtils "github.com/DataDog/datadog-agent/pkg/network/protocols/testutil"
)

const (
	User = "guest"
	Pass = "guest"
)

func RunServer(t testing.TB, serverAddr, serverPort string) error {
	t.Helper()
	env := []string{
		"AMQP_SERVER_ADDR=" + serverAddr,
		"AMQP_SERVER_PORT=" + serverPort,
	}
	dir, _ := testutil.CurDir()
	return protocolsUtils.RunDockerServer(t, "amqp", dir+"/testdata/docker-compose.yml", env, regexp.MustCompile(".*Server startup complete.*"), protocolsUtils.DefaultTimeout)
}
