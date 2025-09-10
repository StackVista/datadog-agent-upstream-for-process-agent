// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package netlink

import (
	"errors"
	"fmt"
	"os"

	"github.com/mdlayher/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Conntrack is an interface to the system conntrack table
type Conntrack interface {
	// Exists checks if a connection exists in the conntrack
	// table based on matches to `conn.Origin` or `conn.Reply`.
	Exists(conn *Con) (bool, error)
	// Dump dumps the conntrack table.
	Dump() ([]Con, error)
	// Get gets the conntrack record for a connection. Similar to
	// Exists, but returns the full connection information.
	Get(conn *Con) (Con, error)
	// Close closes the conntrack object
	Close() error
}

// NewConntrack creates an implementation of the Conntrack interface.
// `netNS` is the network namespace for the conntrack operations.
// A value of `0` will use the current thread's network namespace
func NewConntrack(netNS netns.NsHandle) (Conntrack, error) {
	if !isNetlinkConntrackSupported() {
		return nil, ErrNotPermitted
	}

	conn, err := NewSocket(netNS)
	if err != nil {
		return nil, err
	}

	return &conntrack{
		conn: conn,
		msg: netlink.Message{
			Header: netlink.Header{
				Type:  netlink.HeaderType((unix.NFNL_SUBSYS_CTNETLINK << 8) | ipctnlMsgCtGet),
				Flags: netlink.Request | netlink.Acknowledge,
			},
		},
		// this is the initial buffer size, it will be resized if needed
		buffer: make([]byte, os.Getpagesize()),
		dec:    NewDecoder(),
	}, nil
}

type conntrack struct {
	// [STS] We have a unique client that consumes the connections so we don't need a mutex around the netlink socket
	conn   *Socket
	msg    netlink.Message
	buffer []byte
	dec    *Decoder
}

func (c *conntrack) sendNetlinkMess(conn *Con) error {
	data, err := EncodeConn(conn)
	if err != nil {
		return fmt.Errorf("cannot encode connection: %w", err)
	}

	var family byte = unix.AF_INET
	if (!conn.Origin.IsZero() && !AddrPortIsZero(conn.Origin.Src) && conn.Origin.Src.Addr().Is6() && !conn.Origin.Src.Addr().Is4In6()) ||
		(!conn.Reply.IsZero() && !AddrPortIsZero(conn.Reply.Src) && conn.Reply.Src.Addr().Is6() && !conn.Reply.Src.Addr().Is4In6()) {
		family = unix.AF_INET6
	}

	if cap(c.msg.Data) < 4+len(data) {
		c.msg.Data = make([]byte, 0, 4+len(data))
	}
	c.msg.Data = append(c.msg.Data, []byte{family, unix.NFNETLINK_V0, 0, 0}...)
	c.msg.Data = append(c.msg.Data, data...)

	defer func() {
		c.msg.Data = c.msg.Data[:0]
	}()

	if err = c.conn.Send(c.msg); err != nil {
		return fmt.Errorf("error sending conntrack exists query: %w", err)
	}
	return nil
}

func (c *conntrack) Exists(conn *Con) (bool, error) {
	if err := c.sendNetlinkMess(conn); err != nil {
		return false, err
	}

	_, replies, err := c.conn.ReceiveAndDiscard()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) {
			return false, nil
		}

		return false, err
	}

	if replies > 0 {
		return true, nil
	}

	return false, fmt.Errorf("no replies received from netlink call")
}

func (c *conntrack) Dump() ([]Con, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *conntrack) Get(conn *Con) (Con, error) {
	// [STS] Used by the process-agent
	resolvedConn := Con{}
	if err := c.sendNetlinkMess(conn); err != nil {
		return resolvedConn, err
	}

	// Read the first message
	msgs, _, err := c.conn.ReceiveInto(c.buffer)
	if err != nil {
		return resolvedConn, fmt.Errorf("consumer netlink socket error: %s", err)
	}

	if len(msgs) != 1 {
		return resolvedConn, fmt.Errorf("unexpected number of messages received from netlink call: %d", len(msgs))
	}

	// If the entry is not present we receive only 1 message with type `2` (netlink.Error). We can return immediately
	if msgs[0].Header.Type == netlink.Error {
		return resolvedConn, nil
	}

	// If we expect the entry to be present we should receive 2 packets from the kernel.
	// 1. with type `256` (0x0100) where `0x01` is the `NFNL_SUBSYS_CTNETLINK` and `0x00` is the `NLM_F_DUMP`
	// 2. with type `2` (NLMSG_ERROR) this is used also as an ACK message.
	if msgs[0].Header.Type != 256 {
		return resolvedConn, fmt.Errorf("unexpected message type received from netlink call: %d", msgs[0].Header.Type)
	}
	if err := c.dec.scanner.ResetTo(msgs[0].Data); err != nil {
		return resolvedConn, fmt.Errorf("error while resetting the scanner: %s", err)
	}
	if err = c.dec.unmarshalCon(&resolvedConn); err != nil {
		return resolvedConn, fmt.Errorf("error decoding netlink message: %s", err)
	}

	// we obtained our conversion, but before returning we need to clean the socket and read also the other message, otherwise we will invalid the socket for the next call.
	// please note that the implementation of `noallocRecvmsg` reads only one message in the socket buffer but the kernel should send 2 different messages so we need to read again.
	msgs, _, err = c.conn.ReceiveInto(c.buffer)
	if err != nil {
		return resolvedConn, fmt.Errorf("consumer netlink socket error: %s", err)
	}

	if len(msgs) != 1 {
		return resolvedConn, fmt.Errorf("unexpected number of messages received from netlink call: %d", len(msgs))
	}

	if msgs[0].Header.Type != netlink.Error {
		return resolvedConn, fmt.Errorf("expected ack message but got: %d", msgs[0].Header.Type)
	}
	return resolvedConn, nil
}

func (c *conntrack) Close() error {
	return c.conn.Close()
}
