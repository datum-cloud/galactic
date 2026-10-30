// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/nldump"
)

const (
	directionVPC        = "kV7"
	directionAttachment = "abc"
	directionPort       = 40000
	// Payload sizes differ by more than the frame overhead of the extra
	// datagrams and any neighbor or link-local traffic the links carry.
	instanceSendBytes = 200 * 1000
	hostSendBytes     = 50 * 1000
	datagramSize      = 1000
)

var (
	directionHostAddr     = &net.IPNet{IP: net.ParseIP("fd00:db8::1"), Mask: net.CIDRMask(64, 128)}
	directionInstanceAddr = &net.IPNet{IP: net.ParseIP("fd00:db8::2"), Mask: net.CIDRMask(64, 128)}
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_NET_ADMIN) to create a network namespace; re-run via sudo")
	}
}

// TestAttachmentCollector_DirectionOnRealVeth sends a known number of bytes
// each way across a veth whose host end is named as an attachment's host link,
// and requires transmit_bytes_total to count what the instance side sent and
// receive_bytes_total to count what the host side sent toward it.
func TestAttachmentCollector_DirectionOnRealVeth(t *testing.T) {
	requireRoot(t)

	hostNS, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create host netns: %v", err)
	}
	t.Cleanup(func() { _ = hostNS.Close() })
	instanceNS, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create instance netns: %v", err)
	}
	t.Cleanup(func() { _ = instanceNS.Close() })

	hostName := intf.GenerateInterfaceNameHost(directionVPC, directionAttachment)
	err = hostNS.Do(func(ns.NetNS) error {
		return setupDirectionVeth(hostName, int(instanceNS.Fd()))
	})
	if err != nil {
		t.Fatalf("set up veth: %v", err)
	}
	if err := instanceNS.Do(func(ns.NetNS) error { return configurePeer("peer0") }); err != nil {
		t.Fatalf("configure instance side: %v", err)
	}
	waitForDAD(t, hostNS, hostName, directionHostAddr.IP)
	waitForDAD(t, instanceNS, "peer0", directionInstanceAddr.IP)

	before := gatherDirection(t, hostNS)
	sendUDP(t, instanceNS, hostNS, directionHostAddr.IP, instanceSendBytes)
	sendUDP(t, hostNS, instanceNS, directionInstanceAddr.IP, hostSendBytes)
	after := gatherDirection(t, hostNS)

	transmit := after[attachmentTransmitName] - before[attachmentTransmitName]
	receive := after[attachmentReceiveName] - before[attachmentReceiveName]
	t.Logf("instance sent %d payload bytes, transmit_bytes_total rose %v; host sent %d, receive_bytes_total rose %v",
		instanceSendBytes, transmit, hostSendBytes, receive)
	if transmit < instanceSendBytes {
		t.Errorf("transmit_bytes_total rose %v, want >= %d bytes the instance sent", transmit, instanceSendBytes)
	}
	if receive < hostSendBytes {
		t.Errorf("receive_bytes_total rose %v, want >= %d bytes sent to the instance", receive, hostSendBytes)
	}
	if transmit <= receive {
		t.Errorf("transmit_bytes_total rose %v, receive_bytes_total %v; want transmit larger, as the instance sent more",
			transmit, receive)
	}
}

// setupDirectionVeth creates the veth in the current namespace, moves the peer
// into the namespace behind instanceFd, and brings up the host end.
func setupDirectionVeth(hostName string, instanceFd int) error {
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: hostName}, PeerName: "peer0"}
	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("add veth %s: %w", hostName, err)
	}
	peer, err := netlink.LinkByName("peer0")
	if err != nil {
		return fmt.Errorf("find peer: %w", err)
	}
	if err := netlink.LinkSetNsFd(peer, instanceFd); err != nil {
		return fmt.Errorf("move peer: %w", err)
	}
	host, err := netlink.LinkByName(hostName)
	if err != nil {
		return fmt.Errorf("find host end: %w", err)
	}
	if err := netlink.AddrAdd(host, &netlink.Addr{IPNet: directionHostAddr, Flags: unix.IFA_F_NODAD}); err != nil {
		return fmt.Errorf("add host address: %w", err)
	}
	return netlink.LinkSetUp(host)
}

// configurePeer addresses and brings up the instance end.
func configurePeer(name string) error {
	peer, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find peer: %w", err)
	}
	if err := netlink.AddrAdd(peer, &netlink.Addr{IPNet: directionInstanceAddr, Flags: unix.IFA_F_NODAD}); err != nil {
		return fmt.Errorf("add peer address: %w", err)
	}
	return netlink.LinkSetUp(peer)
}

// waitForDAD waits until the address is no longer tentative on the link.
func waitForDAD(t *testing.T, netns ns.NetNS, link string, ip net.IP) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ready := false
		err := netns.Do(func(ns.NetNS) error {
			l, err := netlink.LinkByName(link)
			if err != nil {
				return err
			}
			addrs, err := netlink.AddrList(l, netlink.FAMILY_V6)
			if err != nil {
				return err
			}
			for _, a := range addrs {
				if a.IP.Equal(ip) && a.Flags&unix.IFA_F_TENTATIVE == 0 {
					ready = l.Attrs().OperState == netlink.OperUp
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("check %s on %s: %v", ip, link, err)
		}
		if ready {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s on %s not usable after 5s", ip, link)
}

// sendUDP sends total payload bytes from fromNS to dst, a socket listening in
// toNS, and waits until the receiver has read them all.
func sendUDP(t *testing.T, fromNS, toNS ns.NetNS, dst net.IP, total int) {
	t.Helper()
	var conn *net.UDPConn
	err := toNS.Do(func(ns.NetNS) error {
		var err error
		conn, err = net.ListenUDP("udp6", &net.UDPAddr{IP: dst, Port: directionPort})
		return err
	})
	if err != nil {
		t.Fatalf("listen on %s: %v", dst, err)
	}
	defer conn.Close() //nolint:errcheck // best-effort close of the test socket

	got := make(chan int, 1)
	go func() {
		buf := make([]byte, 2*datagramSize)
		n := 0
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		for n < total {
			m, err := conn.Read(buf)
			if err != nil {
				break
			}
			n += m
		}
		got <- n
	}()

	err = fromNS.Do(func(ns.NetNS) error {
		out, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: dst, Port: directionPort})
		if err != nil {
			return err
		}
		defer out.Close() //nolint:errcheck // best-effort close of the test socket
		payload := make([]byte, datagramSize)
		for sent := 0; sent < total; sent += datagramSize {
			if _, err := out.Write(payload); err != nil {
				return err
			}
			// Pace the sender so the receive queue does not overflow.
			time.Sleep(100 * time.Microsecond)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("send to %s: %v", dst, err)
	}
	if n := <-got; n < total {
		t.Fatalf("receiver at %s read %d bytes, want %d", dst, n, total)
	}
}

// gatherDirection gathers the attachment collector over nldump.LinkList in
// netns and returns each family's value for the test link. The registry runs
// collectors on their own goroutines, so the lister enters netns itself.
func gatherDirection(t *testing.T, netns ns.NetNS) map[string]float64 {
	t.Helper()
	list := func() (links []netlink.Link, err error) {
		err = netns.Do(func(ns.NetNS) error {
			links, err = nldump.LinkList()
			return err
		})
		return links, err
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(NewAttachmentCollector(list))
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := map[string]float64{}
	for _, name := range []string{attachmentReceiveName, attachmentTransmitName} {
		got := attachmentSeries(families, name)
		if len(got) != 1 {
			t.Fatalf("%s: got %d series, want 1", name, len(got))
		}
		if v := labelValue(got[0], "vpc"); v != directionVPC {
			t.Fatalf("%s: vpc = %q, want %q", name, v, directionVPC)
		}
		out[name] = metricValue(got[0])
	}
	return out
}
