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
//	    prints each IPv6 UDP datagram to port on link: {"t","src","dst"},
//	    then {"t","end"} when the capture ends
//	edgeprobe clock
//	    prints the node's CLOCK_BOOTTIME and CLOCK_REALTIME, read back to
//	    back: {"boot","real"}
//	edgeprobe pid -container id
//	    prints the host PID of a container's first process: the earliest
//	    started process whose /proc/<pid>/cgroup names the container ID; it
//	    needs the host's PID namespace
//	edgeprobe start -pid pid
//	    prints when process pid started, on CLOCK_BOOTTIME in nanoseconds,
//	    to the kernel's 10 ms resolution
//	edgeprobe clockserve -port 7779 -duration 10s
//	    answers each UDP datagram to port with its CLOCK_REALTIME
//	edgeprobe clockping -to [addr]:port -count 20
//	    asks a clockserve for its CLOCK_REALTIME count times and prints the
//	    exchange with the shortest round trip: {"offset","rtt"}, offset
//	    being the server's realtime less this host's at the midpoint
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
		fmt.Fprintln(os.Stderr, "usage: edgeprobe send|sniff|clock|pid|start|clockserve|clockping [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "send":
		err = send(os.Args[2:])
	case "sniff":
		err = sniff(os.Args[2:])
	case "clock":
		err = clock()
	case "pid":
		err = containerPID(os.Args[2:])
	case "start":
		err = processStart(os.Args[2:])
	case "clockserve":
		err = clockServe(os.Args[2:])
	case "clockping":
		err = clockPing(os.Args[2:])
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
	// ETH_P_ALL: a device's transmit path, which is how the kernel hands
	// a packet to a TUN device's reader, is copied only to sockets bound
	// to every protocol.
	proto := htons(unix.ETH_P_ALL)
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
		if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENXIO) || errors.Is(err, unix.ENETDOWN) {
			// The device went away, as when its pod is deleted: the
			// capture ends there.
			return out.Encode(map[string]any{"t": boottime(), "end": true, "error": err.Error()})
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
	return out.Encode(map[string]any{"t": boottime(), "end": true})
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func clock() error {
	var ts unix.Timespec
	b := boottime()
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &ts); err != nil {
		return err
	}
	return out.Encode(map[string]int64{"boot": b, "real": ts.Nano()})
}

func containerPID(args []string) error {
	fs := flag.NewFlagSet("pid", flag.ExitOnError)
	id := fs.String("container", "", "container ID")
	_ = fs.Parse(args)
	if len(*id) < 12 {
		return fmt.Errorf("container ID %q is too short", *id)
	}
	in := func(pid string) bool {
		b, err := os.ReadFile("/proc/" + pid + "/cgroup")
		return err == nil && strings.Contains(string(b), *id)
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	// The container's first process is the one in its cgroup that started
	// first: an exec into the container joins the cgroup later.
	found, first := "", uint64(0)
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil || !in(e.Name()) {
			continue
		}
		start, err := startTicks(e.Name())
		if err == nil && (found == "" || start < first) {
			found, first = e.Name(), start
		}
	}
	if found != "" {
		fmt.Println(found)
		return nil
	}
	return fmt.Errorf("no process of container %s", *id)
}

// startTicks returns /proc/<pid>/stat's starttime: clock ticks of
// CLOCK_BOOTTIME at which the process started.
func startTicks(pid string) (uint64, error) {
	stat, err := os.ReadFile("/proc/" + pid + "/stat")
	if err != nil {
		return 0, err
	}
	// Field 22, starttime, counted from the state field after the
	// parenthesized name, which is field 3.
	fields := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+1:]))
	if len(fields) < 20 {
		return 0, fmt.Errorf("short /proc/%s/stat", pid)
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

// userHZ is the kernel's USER_HZ, the unit of starttime, which Linux fixes
// at 100 on every architecture it exports to user space.
const userHZ = 100

func processStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	pid := fs.Int("pid", 0, "process ID")
	_ = fs.Parse(args)
	ticks, err := startTicks(strconv.Itoa(*pid))
	if err != nil {
		return err
	}
	fmt.Println(ticks * uint64(time.Second/userHZ))
	return nil
}

func realtime() int64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_REALTIME, &ts)
	return ts.Nano()
}

func clockServe(args []string) error {
	fs := flag.NewFlagSet("clockserve", flag.ExitOnError)
	port := fs.Int("port", 7779, "UDP port")
	duration := fs.Duration("duration", 10*time.Second, "how long to answer")
	_ = fs.Parse(args)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: *port})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(*duration)); err != nil {
		return err
	}
	buf := make([]byte, 64)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil
		} else if err != nil {
			return err
		}
		reply := binary.BigEndian.AppendUint64(append([]byte(nil), buf[:n]...), uint64(realtime()))
		if _, err := conn.WriteToUDP(reply, from); err != nil {
			return err
		}
	}
}

func clockPing(args []string) error {
	fs := flag.NewFlagSet("clockping", flag.ExitOnError)
	to := fs.String("to", "", "clockserve [address]:port")
	count := fs.Int("count", 20, "exchanges")
	_ = fs.Parse(args)
	ap, err := netip.ParseAddrPort(*to)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(ap))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	var best struct{ Offset, RTT int64 }
	got := false
	buf := make([]byte, 64)
	for i := range *count {
		seq := binary.BigEndian.AppendUint64(nil, uint64(i))
		sent := realtime()
		if _, err := conn.Write(seq); err != nil {
			return err
		}
		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		n, err := conn.Read(buf)
		recv := realtime()
		if err != nil || n != 16 || binary.BigEndian.Uint64(buf[:8]) != uint64(i) {
			continue
		}
		rtt := recv - sent
		if !got || rtt < best.RTT {
			best.Offset, best.RTT, got = int64(binary.BigEndian.Uint64(buf[8:16]))-(sent+rtt/2), rtt, true
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !got {
		return errors.New("no answer")
	}
	return out.Encode(map[string]int64{"offset": best.Offset, "rtt": best.RTT})
}
