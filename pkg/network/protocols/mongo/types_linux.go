// Code generated by cmd/cgo -godefs; DO NOT EDIT.
// cgo -godefs -- -I ../../ebpf/c -I ../../../ebpf/c -fsigned-char types.go

package mongo

type ConnTuple struct {
	Saddr_h   uint64
	Saddr_l   uint64
	Daddr_h   uint64
	Daddr_l   uint64
	Sport     uint16
	Dport     uint16
	Netns     uint32
	Metadata  uint32
	Pad_cgo_0 [4]byte
}

type EbpfTx struct {
	Tup        ConnTuple
	Latency_ns uint64
}
