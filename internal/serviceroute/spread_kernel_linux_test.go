//go:build linux

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"k8s.io/apimachinery/pkg/types"

	api "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
)

// spreadLab is one node's network namespace holding a consumer and two
// producers of one service address, each behind a veth whose host side runs
// the production service classifier.
type spreadLab struct {
	node, consumer string
	producers      map[string]string // name -> namespace path
	programmer     *EBPFRouteProgrammer
}

const (
	spreadLabService = "fd53::53"
	spreadLabUDPPort = 5353
	spreadLabTCPPort = 5354
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN, CAP_BPF); re-run via sudo")
	}
}

func spreadNS(t *testing.T, name string) string {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = orig.Close() }()
	handle, err := netns.NewNamed(name)
	if err != nil {
		t.Fatal(err)
	}
	_ = handle.Close()
	// Links created later skip duplicate address detection, so the lab is
	// usable as soon as it is built.
	err = os.WriteFile("/proc/sys/net/ipv6/conf/default/accept_dad", []byte("0"), 0o644)
	if err == nil {
		var lo netlink.Link
		if lo, err = netlink.LinkByName("lo"); err == nil {
			err = netlink.LinkSetUp(lo)
		}
	}
	if setErr := netns.Set(orig); setErr != nil {
		t.Fatal(setErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netns.DeleteNamed(name) })
	return filepath.Join("/run/netns", name)
}

// inNS runs fn with the calling thread in the namespace at path.
func inNS(path string, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		return err
	}
	defer func() { _ = orig.Close() }()
	target, err := netns.GetFromPath(path)
	if err != nil {
		return err
	}
	defer func() { _ = target.Close() }()
	if err := netns.Set(target); err != nil {
		return err
	}
	fnErr := fn()
	if err := netns.Set(orig); err != nil {
		return errors.Join(fnErr, err)
	}
	return fnErr
}

func mustInNS(t *testing.T, path string, fn func() error) {
	t.Helper()
	if err := inNS(path, fn); err != nil {
		t.Fatal(err)
	}
}

func addr(t *testing.T, cidr string) *netlink.Addr {
	t.Helper()
	a, err := netlink.ParseAddr(cidr)
	if err != nil {
		t.Fatal(err)
	}
	a.Flags |= 0x02 // IFA_F_NODAD
	return a
}

// connect puts a veth between the node and namespace peer: hostName with
// hostCIDR on the node, guestName with guestCIDR in peer.
func connect(t *testing.T, node, peer, hostName, guestName, hostCIDR, guestCIDR string) {
	t.Helper()
	peerNS, err := netns.GetFromPath(peer)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peerNS.Close() }()
	mustInNS(t, node, func() error {
		veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: hostName}, PeerName: guestName}
		if err := netlink.LinkAdd(veth); err != nil {
			return err
		}
		guest, err := netlink.LinkByName(guestName)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetNsFd(guest, int(peerNS)); err != nil {
			return err
		}
		host, err := netlink.LinkByName(hostName)
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(host, addr(t, hostCIDR)); err != nil {
			return err
		}
		return netlink.LinkSetUp(host)
	})
	mustInNS(t, peer, func() error {
		guest, err := netlink.LinkByName(guestName)
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(guest, addr(t, guestCIDR)); err != nil {
			return err
		}
		return netlink.LinkSetUp(guest)
	})
}

func newSpreadLab(t *testing.T) *spreadLab {
	t.Helper()
	requireRoot(t)
	suffix := strconv.Itoa(os.Getpid())
	pinDir := filepath.Join("/sys/fs/bpf", "galactic-spread-test-"+suffix)
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	objects, err := attach.Load(pinDir)
	if err != nil {
		t.Fatalf("load datapath: %v", err)
	}
	t.Cleanup(func() { _ = objects.Close() })

	lab := &spreadLab{
		node:      spreadNS(t, "gspread-n-"+suffix),
		consumer:  spreadNS(t, "gspread-c-"+suffix),
		producers: map[string]string{},
	}
	connect(t, lab.node, lab.consumer, "hc", "c0", "fd00:c::1/64", "fd00:c::2/64")
	mustInNS(t, lab.consumer, func() error {
		c0, err := netlink.LinkByName("c0")
		if err != nil {
			return err
		}
		_, service, _ := net.ParseCIDR(spreadLabService + "/128")
		return netlink.RouteAdd(&netlink.Route{LinkIndex: c0.Attrs().Index, Dst: service,
			Gw: net.ParseIP("fd00:c::1")})
	})
	for i, name := range []string{"p1", "p2"} {
		path := spreadNS(t, fmt.Sprintf("gspread-%s-%s", name, suffix))
		lab.producers[name] = path
		subnet := fmt.Sprintf("fd00:%d::", i+1)
		connect(t, lab.node, path, "h"+name, "p0", subnet+"1/64", subnet+"2/64")
		mustInNS(t, path, func() error {
			lo, err := netlink.LinkByName("lo")
			if err != nil {
				return err
			}
			if err := netlink.AddrAdd(lo, addr(t, spreadLabService+"/128")); err != nil {
				return err
			}
			p0, err := netlink.LinkByName("p0")
			if err != nil {
				return err
			}
			return netlink.RouteAdd(&netlink.Route{LinkIndex: p0.Attrs().Index, Gw: net.ParseIP(subnet + "1")})
		})
		serveProducer(t, path, name)
	}
	mustInNS(t, lab.node, func() error {
		for _, name := range []string{"hc", "hp1", "hp2"} {
			link, err := netlink.LinkByName(name)
			if err != nil {
				return err
			}
			if err := attach.AttachEgressWithIdentity(objects.UsidServiceEgress, objects.UsidEgress,
				objects.AttachmentIdentityTable, uint32(link.Attrs().Index), name); err != nil {
				return fmt.Errorf("attach %s: %w", name, err)
			}
		}
		return nil
	})
	lab.programmer = &EBPFRouteProgrammer{PinDir: pinDir}
	mustInNS(t, lab.node, lab.programmer.Initialize)
	return lab
}

// serveProducer answers on the service address in namespace path: every UDP
// datagram, and every line of every TCP connection, with "name payload".
func serveProducer(t *testing.T, path, name string) {
	t.Helper()
	var udp net.PacketConn
	var tcp net.Listener
	mustInNS(t, path, func() error {
		var listen net.ListenConfig
		var err error
		udp, err = listen.ListenPacket(context.Background(), "udp6",
			fmt.Sprintf("[%s]:%d", spreadLabService, spreadLabUDPPort))
		if err != nil {
			return err
		}
		tcp, err = listen.Listen(context.Background(), "tcp6", fmt.Sprintf("[%s]:%d", spreadLabService, spreadLabTCPPort))
		return err
	})
	t.Cleanup(func() { _ = udp.Close(); _ = tcp.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo([]byte(name+" "+string(buf[:n])), from)
		}
	}()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				scanner := bufio.NewScanner(conn)
				for scanner.Scan() {
					if _, err := fmt.Fprintf(conn, "%s %s\n", name, scanner.Text()); err != nil {
						return
					}
				}
				if err := scanner.Err(); err != nil {
					t.Logf("%s: read TCP request: %v", name, err)
				}
			}()
		}
	}()
}

// apply replaces the consumer's LocalSet intent the way the policy
// controller does: the new one goes in before the old one comes out.
func (lab *spreadLab) apply(t *testing.T, old *RouteIntent, producers ...ProducerTarget) RouteIntent {
	t.Helper()
	_, service, _ := net.ParseCIDR(spreadLabService + "/128")
	next := RouteIntent{
		Attachment: types.NamespacedName{Namespace: eligibilityNamespace, Name: spreadConsumerName},
		Kind:       RouteIntentLocalSet, Service: service, ConsumerDevice: "hc",
		ConsumerNextHop: net.ParseIP("fd00:c::2"),
		Ports: []api.ServiceRouteProtocolPort{
			{Protocol: api.NetworkServiceProtocolUDP, Port: spreadLabUDPPort},
			{Protocol: api.NetworkServiceProtocolTCP, Port: spreadLabTCPPort},
		},
		Producers: producers,
	}
	mustInNS(t, lab.node, func() error {
		if err := lab.programmer.Apply(next); err != nil {
			return err
		}
		if old != nil {
			if err := lab.programmer.Remove(*old); err != nil {
				return err
			}
		}
		return lab.programmer.Finalize()
	})
	return next
}

func spreadProducer(name string, draining bool) ProducerTarget {
	index := strings.TrimPrefix(name, "p")
	return ProducerTarget{Attachment: types.NamespacedName{Namespace: spreadProducerNamespace, Name: name},
		Device:  "h" + name,
		NextHop: net.ParseIP("fd00:" + index + "::2"), Draining: draining}
}

// udpClient is one consumer UDP socket.
type udpClient struct{ conn net.Conn }

func (lab *spreadLab) udpClient(t *testing.T) *udpClient {
	t.Helper()
	var conn net.Conn
	mustInNS(t, lab.consumer, func() error {
		var dialer net.Dialer
		var err error
		conn, err = dialer.DialContext(context.Background(), "udp6",
			fmt.Sprintf("[%s]:%d", spreadLabService, spreadLabUDPPort))
		return err
	})
	t.Cleanup(func() { _ = conn.Close() })
	return &udpClient{conn: conn}
}

// query sends one request and returns the producer that answered.
func (c *udpClient) query(payload string) (string, error) {
	if _, err := c.conn.Write([]byte(payload)); err != nil {
		return "", err
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			return "", err
		}
		producer, got, _ := strings.Cut(string(buf[:n]), " ")
		if got == payload {
			return producer, nil
		}
	}
}

// tcpClient is one consumer TCP connection.
type tcpClient struct {
	conn    net.Conn
	scanner *bufio.Scanner
}

func (lab *spreadLab) tcpClient(t *testing.T) *tcpClient {
	t.Helper()
	var conn net.Conn
	mustInNS(t, lab.consumer, func() error {
		dialer := net.Dialer{Timeout: 2 * time.Second}
		var err error
		conn, err = dialer.DialContext(context.Background(), "tcp6",
			fmt.Sprintf("[%s]:%d", spreadLabService, spreadLabTCPPort))
		return err
	})
	t.Cleanup(func() { _ = conn.Close() })
	return &tcpClient{conn: conn, scanner: bufio.NewScanner(conn)}
}

func (c *tcpClient) query(payload string) (string, error) {
	_ = c.conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := fmt.Fprintf(c.conn, "%s\n", payload); err != nil {
		return "", err
	}
	if !c.scanner.Scan() {
		return "", fmt.Errorf("read reply: %w", errors.Join(c.scanner.Err(), errors.New("connection closed")))
	}
	producer, got, _ := strings.Cut(c.scanner.Text(), " ")
	if got != payload {
		return "", fmt.Errorf("reply %q to %q", c.scanner.Text(), payload)
	}
	return producer, nil
}

// waitReady waits up to 5 seconds for the first answer through a fresh
// topology, which needs its neighbors resolved, before anything is measured.
func (lab *spreadLab) waitReady(t *testing.T, udp *udpClient) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for i := 0; ; i++ {
		_, err := udp.query(fmt.Sprintf("ready%d", i))
		if err == nil {
			if i != 0 {
				t.Logf("service path answered after %d lost requests", i)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("service path never answered: %v", err)
		}
	}
}

// TestSpreadKernelPath sends real UDP and TCP traffic from a consumer through
// the production classifier and route programmer to two producers of one
// service address on one node, then drains and removes one of them.
func TestSpreadKernelPath(t *testing.T) {
	lab := newSpreadLab(t)
	intent := lab.apply(t, nil, spreadProducer("p1", false), spreadProducer("p2", false))
	udp := lab.udpClient(t)
	lab.waitReady(t, udp)

	checkUDPSpread(t, udp)
	connections := openPinnedConnections(t, lab)

	// Drain p1: no request fails meanwhile, new requests and connections
	// avoid p1, and p1's open connection keeps working.
	intent = drainWithoutFailures(t, lab, intent)
	for i := range 100 {
		if producer, err := udp.query(fmt.Sprintf("d%d", i)); err != nil || producer != "p2" {
			t.Fatalf("UDP request %d after draining p1: producer %q err %v, want p2", i, producer, err)
		}
	}
	expectProducer(t, connections["p1"], "p1", "after draining p1")
	for i := range 8 {
		if got, err := lab.tcpClient(t).query(fmt.Sprintf("new%d", i)); err != nil || got != "p2" {
			t.Fatalf("new TCP connection %d after draining p1: producer %q err %v, want p2", i, got, err)
		}
	}

	// Remove p1: p2's connections are untouched.
	lab.apply(t, &intent, spreadProducer("p2", false))
	expectProducer(t, connections["p2"], "p2", "after removing p1")
	if producer, err := udp.query("last"); err != nil || producer != "p2" {
		t.Fatalf("UDP request after removing p1: producer %q err %v", producer, err)
	}
}

// checkUDPSpread checks that the requests of one UDP socket reach both
// producers.
func checkUDPSpread(t *testing.T, udp *udpClient) {
	t.Helper()
	seen := map[string]int{}
	for i := range 200 {
		producer, err := udp.query(fmt.Sprintf("u%d", i))
		if err != nil {
			t.Fatalf("UDP query %d: %v", i, err)
		}
		seen[producer]++
	}
	if seen["p1"] == 0 || seen["p2"] == 0 {
		t.Fatalf("UDP requests by producer = %v, want both", seen)
	}
	t.Logf("UDP requests by producer: %v", seen)
}

// openPinnedConnections opens TCP connections until each producer holds one,
// checking that every connection stays on its producer.
func openPinnedConnections(t *testing.T, lab *spreadLab) map[string][]*tcpClient {
	t.Helper()
	connections := map[string][]*tcpClient{}
	for i := 0; i < 64 && (len(connections["p1"]) == 0 || len(connections["p2"]) == 0); i++ {
		client := lab.tcpClient(t)
		producer, err := client.query("hello")
		if err != nil {
			t.Fatalf("TCP connection %d: %v", i, err)
		}
		expectProducer(t, []*tcpClient{client, client, client}, producer, fmt.Sprintf("connection %d", i))
		connections[producer] = append(connections[producer], client)
	}
	if len(connections["p1"]) == 0 || len(connections["p2"]) == 0 {
		t.Fatalf("64 TCP connections did not reach both producers: %v", connections)
	}
	return connections
}

// drainWithoutFailures drains p1 while another UDP socket keeps sending
// requests, and fails the test if any request fails.
func drainWithoutFailures(t *testing.T, lab *spreadLab, intent RouteIntent) RouteIntent {
	t.Helper()
	var failures, sent atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	client := lab.udpClient(t)
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			sent.Add(1)
			if _, err := client.query(fmt.Sprintf("bg%d", i)); err != nil {
				failures.Add(1)
			}
		}
	})
	time.Sleep(200 * time.Millisecond)
	intent = lab.apply(t, &intent, spreadProducer("p1", true), spreadProducer("p2", false))
	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d of %d UDP requests failed while p1 drained", failures.Load(), sent.Load())
	}
	t.Logf("UDP requests while draining p1: %d sent, 0 failed", sent.Load())
	return intent
}

// expectProducer sends one request over each connection and fails unless
// producer answers it.
func expectProducer(t *testing.T, connections []*tcpClient, producer, when string) {
	t.Helper()
	for i, client := range connections {
		if got, err := client.query(fmt.Sprintf("check%d", i)); err != nil || got != producer {
			t.Fatalf("TCP request %s: producer %q err %v, want %s", when, got, err, producer)
		}
	}
}
