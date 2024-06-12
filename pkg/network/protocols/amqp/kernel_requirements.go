// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package amqp

import (
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// MinimumKernelVersion indicates the minimum kernel version required for HTTP2 monitoring
var MinimumKernelVersion kernel.Version

func init() {
	MinimumKernelVersion = kernel.VersionCode(4, 15, 0)
}

// AMQP monitoring is supported on Linux kernels >= 4.15
// The per-CPU map type and lookup on non-stack keys are required
func Supported() bool {
	kversion, err := kernel.HostVersion()
	if err != nil {
		log.Warn("could not determine the current kernel version. AMQP monitoring disabled.")
		return false
	}

	return kversion >= MinimumKernelVersion
}
