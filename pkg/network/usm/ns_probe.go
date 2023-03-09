//go:build linux_bpf

package usm

import (
	manager "github.com/DataDog/ebpf-manager"

	filterpkg "github.com/DataDog/datadog-agent/pkg/network/filter"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type NsProbe struct {
	ebpfProgram *ebpfProgram
	probe       *manager.Probe
	packetSrc   *filterpkg.AFPacketSource
}

func (n *NsProbe) Close() {
	program := n.probe.Program()
	err := n.ebpfProgram.DetachHook(n.probe.ProbeIdentificationPair)
	if err != nil {
		log.Errorf("Error detaching hook %v : %s", n.probe.ProbeIdentificationPair, err)
	}
	if program != nil {
		err = program.Close()
		if err != nil {
			log.Errorf("Error closing program %v : %s", n.probe.ProbeIdentificationPair, err)
		}
	}

	n.packetSrc.Close()
}
