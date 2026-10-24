// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command edgeprobe is the Galactic Edge conformance suite's packet probe.
// The suite copies it onto a lab node and runs it inside a pod's network
// namespace with nsenter. Every event it prints is a JSON line stamped with
// CLOCK_BOOTTIME, the clock edge leases are timed on, so the suite can
// compare packet times with a lease's renew-start.
//
//	edgeprobe send -to [addr]:port -interval 20ms -duration 30s
//	    sends numbered UDP datagrams and prints each reply: {"t","seq","from","reply"}
//	edgeprobe sniff -iface link -port 7777 -duration 30s
//	    prints each IPv6 UDP datagram to port on link: {"t","src","dst"}
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: edgeprobe send|sniff [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "send":
		err = send(os.Args[2:])
	case "sniff":
		err = sniff(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "edgeprobe:", err)
		os.Exit(1)
	}
}

func boottime() int64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return ts.Nano()
}

var out = json.NewEncoder(os.Stdout)

func send(args []string) error {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	to := fs.String("to", "", "destination [address]:port")
	interval := fs.Duration("interval", 20*time.Millisecond, "time between datagrams")
	duration := fs.Duration("duration", 10*time.Second, "how long to send")
	_ = fs.Parse(args)
	dst, err := netip.ParseAddrPort(*to)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp6", nil)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			t := boottime()
			reply := string(buf[:n])
			seq := -1
			if i := strings.LastIndexByte(reply, ' '); i >= 0 {
				seq, _ = strconv.Atoi(reply[i+1:])
			}
			_ = out.Encode(map[string]any{"t": t, "seq": seq, "from": from.Addr().String(), "reply": reply})
		}
	}()
	tick := time.NewTicker(*interval)
	defer tick.Stop()
	deadline := time.Now().Add(*duration)
	sent := 0
	for time.Now().Before(deadline) {
		if _, err := conn.WriteToUDPAddrPort([]byte(strconv.Itoa(sent)), dst); err != nil &&
			!errors.Is(err, unix.ENETUNREACH) && !errors.Is(err, unix.EHOSTUNREACH) {
			return err
		}
		sent++
		<-tick.C
	}
	time.Sleep(200 * time.Millisecond)
	_ = conn.Close()
	<-done
	return out.Encode(map[string]any{"t": boottime(), "sent": sent})
}

func sniff(args []string) error {
	fs := flag.NewFlagSet("sniff", flag.ExitOnError)
	iface := fs.String("iface", "", "link to capture on")
	port := fs.Uint("port", 7777, "UDP destination port")
	duration := fs.Duration("duration", 10*time.Second, "how long to capture")
	_ = fs.Parse(args)
	ifi, err := net.InterfaceByName(*iface)
	if err != nil {
		return err
	}
	proto := htons(unix.ETH_P_IPV6)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(proto))
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: proto, Ifindex: ifi.Index}); err != nil {
		return err
	}
	tv := unix.NsecToTimeval((100 * time.Millisecond).Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	deadline := time.Now().Add(*duration)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		// Both directions are read: on a TUN device, a packet the kernel
		// delivers to the provider is outgoing. The port filter keeps
		// requests and drops the provider's replies.
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		t := boottime()
		p := buf[:n]
		if len(p) < 48 || p[0]>>4 != 6 || p[6] != unix.IPPROTO_UDP ||
			uint(binary.BigEndian.Uint16(p[42:44])) != *port {
			continue
		}
		src, _ := netip.AddrFromSlice(p[8:24])
		dst, _ := netip.AddrFromSlice(p[24:40])
		_ = out.Encode(map[string]any{"t": t, "src": src.String(), "dst": dst.String()})
	}
	return nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }
