// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build test

package mongo

import (
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/network/protocols/http/testutil"
	globalutils "github.com/DataDog/datadog-agent/pkg/util/testutil"
	dockerutils "github.com/DataDog/datadog-agent/pkg/util/testutil/docker"
)

const (
	// User is the username to use for authentication
	User = "root"
	// Pass is the password to use for authentication
	Pass = "password"
)

// RunServer runs a mongo server in a docker container
func RunServer(t testing.TB, serverAddress, serverPort string, mongoVersion string) error {
	env := []string{
		"MONGO_ADDR=" + serverAddress,
		"MONGO_PORT=" + serverPort,
		"MONGO_USER=" + User,
		"MONGO_PASSWORD=" + Pass,
		"MONGO_VERSION=" + mongoVersion,
	}
	t.Helper()
	dir, _ := testutil.CurDir()
	scanner, err := globalutils.NewScanner(regexp.MustCompile(`.*istening .*`), globalutils.NoPattern)
	require.NoError(t, err, "failed to create pattern scanner")
	dockerCfg := dockerutils.NewComposeConfig("mongo",
		3*time.Minute,
		dockerutils.DefaultRetries,
		scanner,
		env,
		filepath.Join(dir, "testdata", "docker-compose.yml"))
	return dockerutils.Run(t, dockerCfg)
}
