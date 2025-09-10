// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package netlink

import (
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/DataDog/datadog-agent/pkg/network/netlink/testutil"
	nettestutil "github.com/DataDog/datadog-agent/pkg/network/testutil"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	stsutil "github.com/DataDog/datadog-agent/pkg/util/testutil"
)

func TestMain(m *testing.M) {
	logLevel := os.Getenv("DD_LOG_LEVEL")
	if logLevel == "" {
		logLevel = "warn"
	}
	log.SetupLogger(log.Default(), logLevel)
	os.Exit(m.Run())
}

func TestConntrackExists(t *testing.T) {
	rootNs, err := kernel.GetRootNetNamespace("/proc")
	require.NoError(t, err)
	defer rootNs.Close()

	// We create a netns with a DNAT rule that maps port 80 to 8080
	// One veth extremity is in the root netns while the other one is the netns
	// in this way we should have conntrack entries in both netns
	ns := testutil.SetupCrossNsDNAT(t)

	protoToString := func(proto uint8) string {
		if proto == unix.IPPROTO_TCP {
			return "tcp"
		}
		return "udp"
	}

	nsToString := func(ns netns.NsHandle) string {
		if ns == rootNs {
			return "root_ns"
		}
		return "test_ns"
	}

	// 2.2.2.4 is within the test namespace, while 2.2.2.3 is a peer in the root namespace.
	testNsIP := "2.2.2.4"
	rootNSIP := "2.2.2.3"
	randomIP := "2.2.2.5"
	randomPort := uint16(12245)
	noTranslatedPort := uint16(80)
	translatedPort := uint16(8080)

	// TCP server in the test ns on port 8080
	tcpCloser := nettestutil.StartServerTCPNs(t, net.ParseIP(testNsIP), int(translatedPort), ns)
	defer tcpCloser.Close()

	// UDP server in the test ns on port 8080
	udpCloser := nettestutil.StartServerUDPNs(t, net.ParseIP(testNsIP), int(translatedPort), ns)
	defer udpCloser.Close()

	// TCP Connection to port 80 that will be DNAT'ed to 8080 in the test ns
	// we expect a tuple like (root ns) 2.2.2.3 -> (test ns) 2.2.2.4
	tcpConn := nettestutil.MustPingTCP(t, net.ParseIP(testNsIP), int(noTranslatedPort))
	defer tcpConn.Close()

	// UDP Connection to port 80 that will be DNAT'ed to 8080 in the test ns
	udpConn := nettestutil.MustPingUDP(t, net.ParseIP(testNsIP), int(noTranslatedPort))
	defer udpConn.Close()

	testNs, err := netns.GetFromName(ns)
	require.NoError(t, err)
	defer testNs.Close()

	ctrks := map[netns.NsHandle]Conntrack{}
	defer func() {
		for _, ctrk := range ctrks {
			ctrk.Close()
		}
	}()

	tcpLaddr := tcpConn.LocalAddr().(*net.TCPAddr)
	tcpClientPort := uint16(tcpLaddr.Port)
	udpLaddr := udpConn.LocalAddr().(*net.UDPAddr)
	udpClientPort := uint16(udpLaddr.Port)

	// test a combination of (tcp, udp) x (root ns, test ns)
	tests := []struct {
		desc   string
		origin ConTuple
		reply  ConTuple
		ns     netns.NsHandle
	}{
		{
			// we don't expect any translation here, just the original tuple inverted
			ns:     rootNs,
			origin: newIPTuple(rootNSIP, testNsIP, tcpClientPort, noTranslatedPort, unix.IPPROTO_TCP),
			reply:  newIPTuple(testNsIP, rootNSIP, noTranslatedPort, tcpClientPort, unix.IPPROTO_TCP),
		},
		{
			ns:     rootNs,
			origin: newIPTuple(rootNSIP, testNsIP, udpClientPort, noTranslatedPort, unix.IPPROTO_UDP),
			reply:  newIPTuple(testNsIP, rootNSIP, noTranslatedPort, udpClientPort, unix.IPPROTO_UDP),
		},
		{
			// we expect the translated port in the reply tuple
			ns:     testNs,
			origin: newIPTuple(rootNSIP, testNsIP, tcpClientPort, noTranslatedPort, unix.IPPROTO_TCP),
			reply:  newIPTuple(testNsIP, rootNSIP, translatedPort, tcpClientPort, unix.IPPROTO_TCP),
		},
		{
			ns:     testNs,
			origin: newIPTuple(rootNSIP, testNsIP, udpClientPort, noTranslatedPort, unix.IPPROTO_UDP),
			reply:  newIPTuple(testNsIP, rootNSIP, translatedPort, udpClientPort, unix.IPPROTO_UDP),
		},
		{
			// this entry should not exist
			desc:   "no conntrack entry",
			ns:     rootNs,
			origin: newIPTuple(randomIP, randomIP, randomPort, randomPort, unix.IPPROTO_TCP),
		},
		{
			// this entry should not exist
			desc:   "no conntrack entry",
			ns:     rootNs,
			origin: newIPTuple(randomIP, randomIP, randomPort, randomPort, unix.IPPROTO_UDP),
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s %s_%s", tt.desc, nsToString(tt.ns), protoToString(tt.origin.Proto)), func(t *testing.T) {
			ctrk, ok := ctrks[tt.ns]
			if !ok {
				var err error
				ctrk, err = NewConntrack(tt.ns)
				require.NoError(t, err)
				ctrks[tt.ns] = ctrk
			}
			input := Con{
				Origin: tt.origin,
			}

			// Enable this to see the conntrack table in both namespaces
			//
			// t.Logf("Conntrack test ns:\n %v", nettestutil.RunCommands(t, []string{
			// 	fmt.Sprintf("ip netns exec %s conntrack -L", ns),
			// }, false))
			// t.Logf("Conntrack root ns:\n %v", nettestutil.RunCommands(t, []string{
			// 	fmt.Sprintf("conntrack -L"),
			// }, false))

			///////////////
			// Exists
			///////////////

			ok, err := ctrk.Exists(&input)
			// even if the entry doesn't exist we shouldn't have an error. `ErrNotExist` is converted to nil
			require.NoError(t, err)
			// if we don't define a reply tuple, we expect the conntrack entry to not exist
			if tt.reply.IsZero() {
				require.False(t, ok, "expected no conntrack entry")
			} else {
				require.True(t, ok, "expected conntrack entry")
			}

			///////////////
			// Get
			///////////////
			conn, err := ctrk.Get(&input)
			// like before we shouldn't have errors even if the entry is missing
			require.NoError(t, err)
			t.Logf("conn:\n %v", conn)
			if tt.reply.IsZero() {
				// we will have an empty conn
				require.Equal(t, Con{}, conn, "expected empty conn")
			} else {
				require.Equal(t, tt.reply, conn.Reply, "expected conn")
			}
		})
	}
}

func BenchmarkConntrackExists(b *testing.B) {
	ns := testutil.SetupCrossNsDNAT(b)

	tcpCloser := nettestutil.StartServerTCPNs(b, net.ParseIP("2.2.2.4"), 8080, ns)
	defer tcpCloser.Close()

	tcpConn := nettestutil.MustPingTCP(b, net.ParseIP("2.2.2.4"), 80)
	defer tcpConn.Close()

	testNs, err := netns.GetFromName(ns)
	require.NoError(b, err)
	defer testNs.Close()

	ctrks := map[netns.NsHandle]Conntrack{}
	defer func() {
		for _, ctrk := range ctrks {
			ctrk.Close()
		}
	}()

	tcpAddr := tcpConn.LocalAddr().(*net.TCPAddr)
	laddrIP := tcpAddr.IP.String()
	laddrPort := tcpAddr.Port
	rootNs, err := kernel.GetRootNetNamespace("/proc")
	require.NoError(b, err)
	defer rootNs.Close()

	var ipProto uint8 = unix.IPPROTO_TCP
	tests := []struct {
		c  Con
		ns netns.NsHandle
	}{
		{
			c: Con{
				Origin: newIPTuple(laddrIP, "2.2.2.4", uint16(laddrPort), 80, ipProto),
			},
			ns: rootNs,
		},
		{
			c: Con{
				Reply: newIPTuple("2.2.2.4", laddrIP, 80, uint16(laddrPort), ipProto),
			},
			ns: rootNs,
		},
		{
			c: Con{
				Origin: newIPTuple(laddrIP, "2.2.2.3", uint16(laddrPort), 80, ipProto),
			},
			ns: rootNs,
		},
		{
			c: Con{
				Origin: newIPTuple(laddrIP, "2.2.2.4", uint16(laddrPort), 80, ipProto),
			},
			ns: testNs,
		},
		{
			c: Con{
				Reply: newIPTuple("2.2.2.4", laddrIP, 8080, uint16(laddrPort), ipProto),
			},
			ns: testNs,
		},
		{
			c: Con{
				Origin: newIPTuple(laddrIP, "2.2.2.3", uint16(laddrPort), 80, ipProto),
			},
			ns: testNs,
		},
	}

	ctrkRoot, err := NewConntrack(rootNs)
	require.NoError(b, err)
	b.Cleanup(func() { ctrkRoot.Close() })

	ctrkTest, err := NewConntrack(testNs)
	require.NoError(b, err)
	b.Cleanup(func() { ctrkTest.Close() })

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, te := range tests {
			switch te.ns {
			case rootNs:
				_, _ = ctrkRoot.Exists(&te.c)
			case testNs:
				_, _ = ctrkTest.Exists(&te.c)
			}
		}
	}
}

func TestConntrackExists6(t *testing.T) {
	stsutil.SkipIfIpPackagesRequired(t)
	ns := testutil.SetupCrossNsDNAT6(t)

	tcpCloser := nettestutil.StartServerTCPNs(t, net.ParseIP("fd00::2"), 8080, ns)
	defer tcpCloser.Close()

	udpCloser := nettestutil.StartServerUDPNs(t, net.ParseIP("fd00::2"), 8080, ns)
	defer udpCloser.Close()

	tcpConn := nettestutil.MustPingTCP(t, net.ParseIP("fd00::2"), 80)
	defer tcpConn.Close()

	udpConn := nettestutil.MustPingUDP(t, net.ParseIP("fd00::2"), 80)
	defer udpConn.Close()

	testNs, err := netns.GetFromName(ns)
	require.NoError(t, err)
	defer testNs.Close()

	ctrks := map[netns.NsHandle]Conntrack{}
	defer func() {
		for _, ctrk := range ctrks {
			ctrk.Close()
		}
	}()

	tcpLaddr := tcpConn.LocalAddr().(*net.TCPAddr)
	udpLaddr := udpConn.LocalAddr().(*net.UDPAddr)
	// test a combination of (tcp, udp) x (root ns, test ns)
	testConntrackExists6(t, tcpLaddr.IP.String(), tcpLaddr.Port, "tcp", testNs, ctrks)
	testConntrackExists6(t, udpLaddr.IP.String(), udpLaddr.Port, "udp", testNs, ctrks)
}

func TestConntrackExistsRootDNAT(t *testing.T) {
	stsutil.SkipIfIpPackagesRequired(t)
	destIP := "10.10.1.1"
	destPort := 80
	listenIP := "2.2.2.4"
	listenPort := 8080
	ns := testutil.SetupCrossNsDNATWithPorts(t, destPort, listenPort)

	nettestutil.IptablesSave(t)
	nettestutil.RunCommands(t, []string{
		"iptables --table nat --new-chain CLUSTERIPS",
		"iptables --table nat --append PREROUTING --jump CLUSTERIPS",
		"iptables --table nat --append OUTPUT --jump CLUSTERIPS",
		fmt.Sprintf("iptables --table nat --append CLUSTERIPS --destination %s --protocol tcp --match tcp --dport %d --jump DNAT --to-destination %s:%d", destIP, destPort, listenIP, destPort),
		fmt.Sprintf("ip route add %s dev veth1", destIP),
	}, false)

	testNs, err := netns.GetFromName(ns)
	require.NoError(t, err)
	defer testNs.Close()

	rootNs, err := kernel.GetRootNetNamespace("/proc")
	require.NoError(t, err)
	defer rootNs.Close()

	tcpCloser := nettestutil.StartServerTCPNs(t, net.ParseIP(listenIP), listenPort, ns)
	defer tcpCloser.Close()

	tcpConn := nettestutil.MustPingTCP(t, net.ParseIP(destIP), destPort)
	defer tcpConn.Close()

	rootck, err := NewConntrack(rootNs)
	require.NoError(t, err)

	testck, err := NewConntrack(testNs)
	require.NoError(t, err)

	tcpLaddr := tcpConn.LocalAddr().(*net.TCPAddr)
	c := &Con{
		Origin: newIPTuple(tcpLaddr.IP.String(), destIP, uint16(tcpLaddr.Port), uint16(destPort), unix.IPPROTO_TCP),
	}

	exists, err := rootck.Exists(c)
	require.NoError(t, err)
	assert.True(t, exists)

	exists, err = testck.Exists(c)
	require.NoError(t, err)
	assert.False(t, exists)
}

func testConntrackExists6(t *testing.T, laddrIP string, laddrPort int, proto string, testNs netns.NsHandle, ctrks map[netns.NsHandle]Conntrack) {
	rootNs, err := kernel.GetRootNetNamespace("/proc")
	require.NoError(t, err)
	defer rootNs.Close()

	var ipProto uint8 = unix.IPPROTO_UDP
	if proto == "tcp" {
		ipProto = unix.IPPROTO_TCP
	}
	tests := []struct {
		desc   string
		c      Con
		exists bool
		ns     netns.NsHandle
	}{
		{
			desc: fmt.Sprintf("net ns 0, origin exists, proto %s", proto),
			c: Con{
				Origin: newIPTuple(laddrIP, "fd00::2", uint16(laddrPort), 80, ipProto),
			},
			exists: true,
			ns:     rootNs,
		},
		{
			desc: fmt.Sprintf("net ns 0, reply exists, proto %s", proto),
			c: Con{
				Reply: newIPTuple("fd00::2", laddrIP, 80, uint16(laddrPort), ipProto),
			},
			exists: true,
			ns:     rootNs,
		},
		{
			desc: fmt.Sprintf("net ns 0, origin does not exist, proto %s", proto),
			c: Con{
				Origin: newIPTuple(laddrIP, "fd00::1", uint16(laddrPort), 80, ipProto),
			},
			exists: false,
			ns:     rootNs,
		},
		{
			desc: fmt.Sprintf("net ns %d, origin exists, proto %s", int(testNs), proto),
			c: Con{
				Origin: newIPTuple(laddrIP, "fd00::2", uint16(laddrPort), 80, ipProto),
			},
			exists: true,
			ns:     testNs,
		},
		{
			desc: fmt.Sprintf("net ns %d, reply exists, proto %s", int(testNs), proto),
			c: Con{
				Reply: newIPTuple("fd00::2", laddrIP, 8080, uint16(laddrPort), ipProto),
			},
			exists: true,
			ns:     testNs,
		},
		{
			desc: fmt.Sprintf("net ns %d, origin does not exist, proto %s", int(testNs), proto),
			c: Con{
				Origin: newIPTuple(laddrIP, "fd00::1", uint16(laddrPort), 80, ipProto),
			},
			exists: false,
			ns:     testNs,
		},
	}

	for _, te := range tests {
		t.Run(te.desc, func(t *testing.T) {
			ctrk, ok := ctrks[te.ns]
			if !ok {
				var err error
				ctrk, err = NewConntrack(te.ns)
				require.NoError(t, err)

				ctrks[te.ns] = ctrk
			}

			ok, err := ctrk.Exists(&te.c)
			require.NoError(t, err)
			require.Equal(t, te.exists, ok)
		})
	}
}
