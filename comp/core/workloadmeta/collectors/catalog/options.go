// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package catalog is a wrapper that loads the available workloadmeta
// collectors. It exists as a shorthand for importing all packages manually in
// all of the agents.
package catalog

import (
	"go.uber.org/fx"

	cfcontainer "github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/cloudfoundry/container"
	cfvm "github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/cloudfoundry/vm"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/containerd"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/crio"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/docker"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/ecs"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/ecsfargate"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/kubeapiserver"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/kubelet"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/kubemetadata"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/podman"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/remote/processcollector"
	remoteworkloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/remote/workloadmeta"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
)

func getCollectorOptions() []fx.Option {
	return []fx.Option{
		cfcontainer.GetFxOptions(),
		cfvm.GetFxOptions(),
		containerd.GetFxOptions(),
		crio.GetFxOptions(),
		docker.GetFxOptions(),
		ecs.GetFxOptions(),
		ecsfargate.GetFxOptions(),
		kubeapiserver.GetFxOptions(),
		kubelet.GetFxOptions(),
		kubemetadata.GetFxOptions(),
		podman.GetFxOptions(),
		remoteworkloadmeta.GetFxOptions(),
		remoteWorkloadmetaParams(),
		processcollector.GetFxOptions(),
	}
}

// [STS] Our own function to get the collectors we use in the ProcessAgent
func GetCollectors() []workloadmeta.Collector {
	// These are the only ones that have the `workloadmeta.ProcessAgent` flag
	providers := []func() (workloadmeta.CollectorProvider, error){
		containerd.NewCollector,
		docker.NewCollector,
		kubelet.NewCollector,
		kubemetadata.NewCollector,
		// todo!: actually we are not compiling these packages in the process agent, if we look at the logs before the sync we don't have them
		// crio.NewCollector,
		// podman.NewCollector,

		// It seems we don't use these ones.
		// ecs.NewCollector,
		// cfcontainer.NewCollector,
		// cfvm.NewCollector,
		// ecsfargate.NewCollector,
		// kubeapiserver.NewCollector,
		// remoteworkloadmeta.NewCollector,
		// remoteWorkloadmetaParams,
		// processcollector.NewCollector,
	}

	collectors := make([]workloadmeta.Collector, 0)
	for _, p := range providers {
		c, _ := p()
		collectors = append(collectors, c.Collector)
	}
	return collectors
}
