// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

var (
	client = netip.MustParseAddr("fd20:10:ff01::10")
	served = netip.MustParseAddr("fd00:ed9e:1:100::1")
)

func echoRequest(t *testing.T) []byte {
	t.Helper()
	m := icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Body: &icmp.Echo{ID: 7, Seq: 3, Data: []byte("ping")}}
	b, err := m.Marshal(icmp.IPv6PseudoHeader(client.AsSlice(), served.AsSlice()))
	if err != nil {
		t.Fatal(err)
	}
	return packetOf(client, served, protoICMPv6, b)
}

func udpRequest(payload string) []byte {
	out := make([]byte, udpHeaderLen+len(payload))
	binary.BigEndian.PutUint16(out[0:2], 40000)
	binary.BigEndian.PutUint16(out[2:4], 7777)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(out)))
	copy(out[udpHeaderLen:], payload)
	binary.BigEndian.PutUint16(out[6:8], checksum(client, served, protoUDP, out))
	return packetOf(client, served, protoUDP, out)
}

func addrs(t *testing.T, p []byte) (netip.Addr, netip.Addr) {
	t.Helper()
	src, _ := netip.AddrFromSlice(p[8:24])
	dst, _ := netip.AddrFromSlice(p[24:40])
	return src, dst
}

func TestEchoReply(t *testing.T) {
	reply, err := Reply(echoRequest(t), "p/pod/svc")
	if err != nil {
		t.Fatal(err)
	}
	if src, dst := addrs(t, reply); src != served || dst != client {
		t.Fatalf("reply %s -> %s, want %s -> %s", src, dst, served, client)
	}
	if reply[6] != protoICMPv6 {
		t.Fatalf("next header %d", reply[6])
	}
	if checksum(served, client, protoICMPv6, reply[headerLen:]) != 0 {
		t.Fatal("ICMPv6 checksum does not verify")
	}
	m, err := icmp.ParseMessage(protoICMPv6, reply[headerLen:])
	if err != nil {
		t.Fatal(err)
	}
	echo, ok := m.Body.(*icmp.Echo)
	if m.Type != ipv6.ICMPTypeEchoReply || !ok || echo.ID != 7 || echo.Seq != 3 || string(echo.Data) != "ping" {
		t.Fatalf("reply %+v", m)
	}
}

func TestUDPReply(t *testing.T) {
	reply, err := Reply(udpRequest("hello"), "p/pod/svc")
	if err != nil {
		t.Fatal(err)
	}
	if src, dst := addrs(t, reply); src != served || dst != client {
		t.Fatalf("reply %s -> %s", src, dst)
	}
	body := reply[headerLen:]
	if got := binary.BigEndian.Uint16(body[0:2]); got != 7777 {
		t.Fatalf("source port %d", got)
	}
	if got := binary.BigEndian.Uint16(body[2:4]); got != 40000 {
		t.Fatalf("destination port %d", got)
	}
	if checksum(served, client, protoUDP, body) != 0 {
		t.Fatal("UDP checksum does not verify")
	}
	if !bytes.Equal(body[udpHeaderLen:], []byte("p/pod/svc hello")) {
		t.Fatalf("payload %q", body[udpHeaderLen:])
	}
}

func TestIgnored(t *testing.T) {
	short := echoRequest(t)[:30]
	notEcho := echoRequest(t)
	notEcho[headerLen] = 129
	multicast := udpRequest("x")
	copy(multicast[24:40], netip.MustParseAddr("ff02::1").AsSlice())
	tcp := udpRequest("x")
	tcp[6] = 6
	ipv4 := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}
	for name, p := range map[string][]byte{"short": short, "echo reply": notEcho, "multicast": multicast,
		"tcp": tcp, "ipv4": ipv4} {
		if _, err := Reply(p, "id"); !errors.Is(err, ErrIgnored) {
			t.Errorf("%s: got %v, want ErrIgnored", name, err)
		}
	}
}
