// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostattach

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The target tests run on a real node, not in CI. TestTargetProvisioner runs
// in a privileged pod with the host's network and PID namespaces; it finds a
// consumer pod by UID, attaches it to a fixture VRF and checks traffic.
// TestTargetConsumer runs in that unprivileged consumer pod; it receives its
// TUN device as a file descriptor and answers on it and on a VRF-bound socket.
// Both skip unless GALACTIC_EDGE_TARGET names their role.
//
// Every name they create starts with edgefx and matches none of the patterns
// galactic's garbage collection and repair act on, and they register nothing
// in the shared eBPF maps.
const (
	targetRoleEnv  = "GALACTIC_EDGE_TARGET"
	targetVRF      = "edgefx-vrf"
	targetTable    = 0x7EDC0001
	targetHostLink = "edgefx-h1"
	targetPodLink  = "edgefx0"
	targetTUN      = "edgefx-tun"
	targetWorkload = "edgefx-wl"
	targetSocket   = "consumer.sock"
	targetSiteMTU  = 1400
)

func targetRole(t *testing.T, role string) {
	t.Helper()
	if os.Getenv(targetRoleEnv) != role {
		t.Skipf("skipping: set %s=%s on a target node", targetRoleEnv, role)
	}
}

func targetDir() string {
	if d := os.Getenv("GALACTIC_EDGE_TARGET_DIR"); d != "" {
		return d
	}
	return "/run/edgefx"
}

// findPodProcess returns a process of the pod with uid, identified by the
// kernel-maintained cgroup path the kubelet places every container of the pod
// under. The path cannot be forged by the pod, unlike any value it reports.
func findPodProcess(uid string) (int, error) {
	marker := "pod" + uid
	alt := "pod" + strings.ReplaceAll(uid, "-", "_")
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if ok, _ := processInPod(pid, marker, alt); ok {
			return pid, nil
		}
	}
	return 0, fmt.Errorf("no process in pod %s", uid)
}

// processInPod reports whether the process's cgroup path names one of
// markers as a whole path element, as the cgroupfs driver writes it
// (".../pod<uid>/...") or the systemd driver does
// (".../kubepods-besteffort-pod<uid_with_underscores>.slice/...").
func processInPod(pid int, markers ...string) (bool, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		for _, elem := range strings.Split(line, "/") {
			for _, m := range markers {
				if elem == m || strings.HasSuffix(elem, "-"+m+".slice") {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// openPodNamespace opens the network namespace of the pod with uid and
// confirms afterwards that the process it came from still belongs to the pod,
// so a PID reused between the lookup and the open is detected.
func openPodNamespace(t *testing.T, uid string) (*Namespace, int) {
	t.Helper()
	pid, err := findPodProcess(uid)
	if err != nil {
		t.Fatal(err)
	}
	h, err := OpenNamespace(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := processInPod(pid, "pod"+uid, "pod"+strings.ReplaceAll(uid, "-", "_")); !ok {
		_ = h.Close()
		t.Fatalf("process %d left pod %s while its namespace was opened (%v)", pid, uid, err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h, pid
}

// sendFD passes fd to the consumer listening on path, waiting up to 30
// seconds for the consumer to start listening.
func sendFD(path string, fd int) error {
	var c *net.UnixConn
	var err error
	for range 60 {
		if c, err = net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"}); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_, _, err = c.WriteMsgUnix([]byte("tun"), unix.UnixRights(fd), nil)
	return err
}

// openTUNIn opens the named TUN device inside h's namespace and returns its
// descriptor.
func openTUNIn(h *Namespace, name string) (int, error) {
	var fd int
	err := h.do(func() error {
		var err error
		fd, err = unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		ifr, err := unix.NewIfreq(name)
		if err != nil {
			_ = unix.Close(fd)
			return err
		}
		ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
		if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
			_ = unix.Close(fd)
			return err
		}
		return nil
	})
	return fd, err
}

// attachedPrograms lists every BPF program and tc filter attached to link:
// classic tc filters, tcx programs, which classic filter listings do not
// show, and XDP.
func attachedPrograms(t *testing.T, name string) []string {
	t.Helper()
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		filters, err := netlink.FilterList(l, parent)
		if err != nil {
			continue
		}
		for _, f := range filters {
			if b, ok := f.(*netlink.BpfFilter); ok {
				out = append(out, "tc:"+b.Name)
			} else {
				out = append(out, "tc:"+f.Type())
			}
		}
	}
	for _, attach := range []ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress} {
		res, err := link.QueryPrograms(link.QueryOptions{Target: l.Attrs().Index, Attach: attach})
		if err != nil {
			t.Fatalf("query %v programs on %q: %v", attach, name, err)
		}
		for _, p := range res.Programs {
			out = append(out, fmt.Sprintf("%v:%d", attach, p.ID))
		}
	}
	if xdp := l.Attrs().Xdp; xdp != nil && xdp.Attached {
		out = append(out, fmt.Sprintf("xdp:%d", xdp.ProgId))
	}
	return out
}

// TestTargetProvisioner attaches a running consumer pod to a fixture VRF on
// the node it runs on and checks that the attachment works with the node's
// real CNI, kernel and runtime. Set GALACTIC_EDGE_TARGET_POD_UID to the
// consumer pod's UID and GALACTIC_EDGE_TARGET_UID to its user.
func TestTargetProvisioner(t *testing.T) {
	targetRole(t, "provision")
	requireRoot(t)
	uid := os.Getenv("GALACTIC_EDGE_TARGET_POD_UID")
	owner, err := strconv.ParseUint(os.Getenv("GALACTIC_EDGE_TARGET_UID"), 10, 32)
	if uid == "" || err != nil {
		t.Fatal("GALACTIC_EDGE_TARGET_POD_UID and GALACTIC_EDGE_TARGET_UID are required")
	}
	host, err := OpenNamespace("/proc/1/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	pod, pid := openPodNamespace(t, uid)
	t.Logf("pod %s: process %d, namespace %s", uid, pid, pod.Path())

	setupTargetVRF(t)
	current, err := ns.GetCurrentNS()
	if err != nil {
		t.Fatal(err)
	}
	workload := newWorkload(t, testNS{current}, targetVRF, targetWorkload, workloadAddr.String())

	att := Attachment{
		ID: "edgefx-" + uid, HostVRF: targetVRF, HostLink: targetHostLink, PodVRF: targetVRF, PodTable: podTable,
		PodLink: targetPodLink, MTU: tenantMTU, Address: netip.MustParseAddr("fd00:aa::1"),
		Prefixes: []netip.Prefix{sitePrefix},
		TUN:      &TUN{Name: targetTUN, Owner: uint32(owner), Group: uint32(owner), MTU: targetSiteMTU},
	}
	// Registered before provisioning, so a provisioning failure part way
	// through still removes what was created.
	t.Cleanup(func() { _ = Release(host, pod, att) })
	start := time.Now()
	res, err := Provision(host, pod, att)
	if err != nil {
		t.Fatalf("provision into pod %s: %v", uid, err)
	}
	t.Logf("provisioned in %v: host ifindex %d, pod ifindex %d", time.Since(start), res.HostIndex, res.PodIndex)

	fd, err := openTUNIn(pod, targetTUN)
	if err != nil {
		t.Fatalf("open TUN in the pod: %v", err)
	}
	if err := sendFD(filepath.Join(targetDir(), targetSocket), fd); err != nil {
		t.Fatalf("pass TUN to the consumer: %v", err)
	}
	_ = unix.Close(fd)

	t.Run("CNILeavesAttachmentLinksAlone", func(t *testing.T) {
		if p := attachedPrograms(t, targetHostLink); len(p) > 0 {
			t.Errorf("programs attached to the host link: %v", p)
		}
		if err := pod.do(func() error {
			if p := attachedPrograms(t, targetPodLink); len(p) > 0 {
				t.Errorf("programs attached to the pod link: %v", p)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	if os.Getenv("GALACTIC_EDGE_TARGET_BPF_CNI") != "" {
		t.Run("AttachmentCheckSeesCNIPrograms", func(t *testing.T) { checkCNIProgramsVisible(t, pod) })
	}
	t.Run("PacketConsumerOverPassedDescriptor", func(t *testing.T) {
		if err := retryPing(workload, siteHost, 128); err != nil {
			t.Fatalf("ping to the site behind the consumer's TUN: %v", err)
		}
	})
	t.Run("PacketTooBigFromNarrowerTUN", func(t *testing.T) {
		err := ping(workload, siteHost, targetSiteMTU+50)
		var tooBig *packetTooBigError
		if !errors.As(err, &tooBig) || tooBig.MTU != targetSiteMTU {
			t.Fatalf("oversized ping = %v, want Packet Too Big %d", err, targetSiteMTU)
		}
		if err := ping(workload, siteHost, targetSiteMTU); err != nil {
			t.Fatalf("%d-byte ping: %v", targetSiteMTU, err)
		}
	})
	t.Run("UnprivilegedVRFBoundSocket", func(t *testing.T) {
		// The consumer binds once it sees the pod VRF, so allow it a moment.
		var got string
		var err error
		for range 20 {
			if got, err = dialIdentity(workload, "", netip.MustParseAddrPort("[fd00:aa::1]:8000")); err == nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if err != nil || got != "consumer" {
			t.Fatalf("dial the consumer's VRF-bound socket = %q, %v", got, err)
		}
	})
	t.Run("MissingRouteFailsInsideVRF", func(t *testing.T) {
		if err := netlink.RouteDel(&netlink.Route{Table: targetTable, Dst: prefixNet(sitePrefix)}); err != nil {
			t.Fatal(err)
		}
		if err := ping(workload, siteHost, 128); !errors.Is(err, errUnreachable) {
			t.Fatalf("ping with the site route removed = %v, want unreachable", err)
		}
		if _, err := Provision(host, pod, att); err != nil {
			t.Fatal(err)
		}
		if err := ping(workload, siteHost, 128); err != nil {
			t.Fatalf("ping after repair: %v", err)
		}
	})
	if wait := os.Getenv("GALACTIC_EDGE_TARGET_REPLACE_WAIT"); wait != "" {
		t.Run("ReplacedSandboxIsRejected", func(t *testing.T) {
			d, err := time.ParseDuration(wait)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("delete the consumer pod within %v", d)
			deadline := time.Now().Add(d)
			for pod.Verify() == nil {
				if time.Now().After(deadline) {
					t.Fatal("the consumer pod was not replaced")
				}
				time.Sleep(time.Second)
			}
			if _, err := Provision(host, pod, att); !errors.Is(err, ErrNamespaceReplaced) {
				t.Fatalf("provision into the replaced sandbox = %v, want ErrNamespaceReplaced", err)
			}
		})
	}
}

// setupTargetVRF creates the fixture's stand-in for a canonical host VRF,
// refusing to start on a node that already has anything with the fixture's
// names or routes in its table: none of it would be the fixture's to remove.
func setupTargetVRF(t *testing.T) {
	t.Helper()
	for _, name := range []string{targetVRF, targetHostLink, targetWorkload} {
		if _, err := netlink.LinkByName(name); err == nil {
			t.Fatalf("link %q already exists on this node", name)
		}
	}
	if routes, err := netlink.RouteListFiltered(unix.AF_INET6,
		&netlink.Route{Table: targetTable}, netlink.RT_FILTER_TABLE); err != nil || len(routes) > 0 {
		t.Fatalf("table %#x is not empty (%d routes, %v)", targetTable, len(routes), err)
	}
	vrfDev := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: targetVRF}, Table: targetTable}
	if err := netlink.LinkAdd(vrfDev); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if l, err := netlink.LinkByName(targetVRF); err == nil {
			_ = netlink.LinkDel(l)
		}
		_ = flushTable(targetTable)
	})
	for _, dst := range []string{"0.0.0.0/0", "::/0"} {
		_, n, _ := net.ParseCIDR(dst)
		if err := netlink.RouteReplace(&netlink.Route{
			Dst: n, Table: targetTable, Type: unix.RTN_UNREACHABLE, Priority: UnreachableDefaultMetric,
		}); err != nil {
			t.Fatal(err)
		}
	}
	vrfLink, err := netlink.LinkByName(targetVRF)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(vrfLink); err != nil {
		t.Fatal(err)
	}
}

// checkCNIProgramsVisible is the control for the attachment program check:
// the pod's own interface is the CNI's, so on a CNI that attaches BPF
// programs attachedPrograms must find them on its host side, or an empty
// result for the attachment links proves nothing.
func checkCNIProgramsVisible(t *testing.T, pod *Namespace) {
	t.Helper()
	var peer int
	if err := pod.do(func() error {
		l, err := netlink.LinkByName(podEth0)
		if err != nil {
			return err
		}
		peer = l.Attrs().ParentIndex
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	l, err := netlink.LinkByIndex(peer)
	if err != nil {
		t.Fatal(err)
	}
	p := attachedPrograms(t, l.Attrs().Name)
	if len(p) == 0 {
		t.Fatalf("no programs found on the CNI's host link %q", l.Attrs().Name)
	}
	t.Logf("CNI host link %q carries %v", l.Attrs().Name, p)
}

func retryPing(n testNS, dst netip.Addr, size int) error {
	var err error
	for range 20 {
		if err = ping(n, dst, size); err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return err
}

func flushTable(table int) error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return err
		}
		for i := range routes {
			_ = netlink.RouteDel(&routes[i])
		}
	}
	return nil
}

// TestTargetConsumer is the consumer side: it runs unprivileged in the pod
// the provisioner attaches, receives the TUN descriptor over a Unix socket,
// answers echo requests on it, and serves its identity on a socket bound to
// the pod VRF.
func TestTargetConsumer(t *testing.T) {
	targetRole(t, "consumer")
	path := filepath.Join(targetDir(), targetSocket)
	_ = os.Remove(path)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		serveVRFBound(ctx, t)
	}()
	t.Cleanup(func() {
		cancel()
		<-served
	})

	c, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	buf, oob := make([]byte, 16), make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		t.Fatalf("control message: %v", err)
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		t.Fatalf("descriptor: %v", err)
	}
	t.Logf("received TUN descriptor as uid %d", os.Getuid())
	if err := unix.SetNonblock(fds[0], true); err != nil {
		t.Fatal(err)
	}
	r := &tunResponder{f: os.NewFile(uintptr(fds[0]), targetTUN)}
	go r.run()
	d := 10 * time.Minute
	if v := os.Getenv("GALACTIC_EDGE_TARGET_SERVE"); v != "" {
		if d, err = time.ParseDuration(v); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(d)
	t.Logf("answered %d echo requests, largest %d bytes", r.echoes.Load(), r.largest.Load())
}

// serveVRFBound binds to the pod VRF once it exists and answers every
// connection with the consumer's identity until ctx is done.
func serveVRFBound(ctx context.Context, t *testing.T) {
	lc := net.ListenConfig{Control: bindToDevice(targetVRF)}
	var ln net.Listener
	var err error
	for ctx.Err() == nil {
		if ln, err = lc.Listen(ctx, "tcp6", "[::]:8000"); err == nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(500 * time.Millisecond):
		}
	}
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		t.Logf("VRF-bound listen failed as uid %d: %v", os.Getuid(), err)
		return
	}
	t.Logf("listening on %s bound to %s as uid %d", ln.Addr(), targetVRF, os.Getuid())
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = io.WriteString(c, "consumer")
		_ = c.Close()
	}
}
