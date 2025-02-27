// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux_bpf

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
)

const (
	numTestCPUs = 4
)

func TestBatchExtract(t *testing.T) {
	t.Run("normal flush", func(t *testing.T) {
		extractor := newBatchExtractor(numTestCPUs)

		batch := new(netebpf.Batch)
		batch.Len = 4
		batch.Id = 0
		batch.Cpu = 0
		// [STS] we need to use the port because we don't have the PID in STS
		batch.C0.Tup.Sport = 1
		batch.C1.Tup.Sport = 2
		batch.C2.Tup.Sport = 3
		batch.C3.Tup.Sport = 4

		var conns []*netebpf.Conn
		for rc := extractor.NextConnection(batch); rc != nil; rc = extractor.NextConnection(batch) {
			conns = append(conns, rc)
		}
		require.Len(t, conns, 4)
		assert.Equal(t, uint16(1), conns[0].Tup.Sport)
		assert.Equal(t, uint16(2), conns[1].Tup.Sport)
		assert.Equal(t, uint16(3), conns[2].Tup.Sport)
		assert.Equal(t, uint16(4), conns[3].Tup.Sport)
	})

	t.Run("partial flush", func(t *testing.T) {
		extractor := newBatchExtractor(numTestCPUs)
		// Simulate a partial flush
		extractor.stateByCPU[0].processed = map[uint64]batchState{
			0: {offset: 3},
		}

		batch := new(netebpf.Batch)
		batch.Len = 4
		batch.Id = 0
		batch.Cpu = 0
		batch.C0.Tup.Sport = 1
		batch.C1.Tup.Sport = 2
		batch.C2.Tup.Sport = 3
		batch.C3.Tup.Sport = 4

		var conns []*netebpf.Conn
		for rc := extractor.NextConnection(batch); rc != nil; rc = extractor.NextConnection(batch) {
			conns = append(conns, rc)
		}
		assert.Len(t, conns, 1)
		assert.Equal(t, uint16(4), conns[0].Tup.Sport)
	})
}
