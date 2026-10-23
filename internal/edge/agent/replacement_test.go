// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/claim"
	"go.datum.net/galactic/internal/edge/hostattach"
	"go.datum.net/galactic/internal/edge/ownership"
	edgeprovider "go.datum.net/galactic/internal/edge/provider"
	"go.datum.net/galactic/internal/edge/route"
	"go.datum.net/galactic/internal/edge/timing"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/forwardgatemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
)

// e2eParams is the cell's timing scaled down so the scenario runs in seconds;
// every bound scales with it.
var e2eParams = claim.Params{Duration: 2 * time.Second, MaxDrift: 0.001, Margin: 500 * time.Millisecond,
	MaxSkew: 2 * time.Second}

var (
	e2eSite     = netip.MustParsePrefix("fd00:10:5::/48")
	e2eSiteHost = netip.MustParseAddr("fd00:10:5::1")
	e2eSource   = netip.MustParseAddr("fd00:10:0:1::99")
)

// e2e is one edge node, its galactic-edge agent with the real uSID
// datapath's pinned gate maps, galactic-controller's route reconcilers on a
// real API server, and provider processes driving the real claim code.
type e2e struct {
	t      *testing.T
	admin  client.Client
	cfg    *rest.Config
	scheme *kruntime.Scheme
	host   string
	pinDir string
	gates  *forwardgatemap.Table
	pods   *resolver
	svc    *galacticv1alpha1.EdgeService
	vpc    *cloudv1alpha1.VPC
	bootID string
	stop   func()
	reader *switchReader
}

// switchReader fails every read while down, as an agent cut off from the API
// server sees.
type switchReader struct {
	client.Reader
	down atomic.Bool
}

func (r *switchReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object,
	opts ...client.GetOption) error {
	if r.down.Load() {
		return errors.New("API server unreachable")
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

// nsDatapath runs the pinned datapath's registration in the host namespace,
// as galactic-edge, which runs there, does.
type nsDatapath struct {
	PinnedDatapath
	host string
}

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
		panic(err)
	}
	return fnErr
}

func (d nsDatapath) Register(vrfTable, ifindex uint32, ifname string, addr netip.Addr) error {
	return inNS(d.host, func() error { return d.PinnedDatapath.Register(vrfTable, ifindex, ifname, addr) })
}

func (d nsDatapath) Unregister(ifindex uint32) error {
	return inNS(d.host, func() error { return d.PinnedDatapath.Unregister(ifindex) })
}

func startE2E(t *testing.T) *e2e {
	t.Helper()
	requireRoot(t)
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("KUBEBUILDER_ASSETS not set in CI")
		}
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	e := &e2e{t: t, pods: &resolver{paths: map[string]string{}}}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	e.bootID = strings.TrimSpace(string(boot))

	te := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "config", "crd")},
		ErrorIfCRDPathMissing: true,
	}
	if e.cfg, err = te.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = te.Stop() })
	e.scheme = kruntime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(e.scheme))
	utilruntime.Must(galacticv1alpha1.AddToScheme(e.scheme))
	utilruntime.Must(cloudv1alpha1.AddToScheme(e.scheme))
	utilruntime.Must(bgpv1alpha1.AddToScheme(e.scheme))
	if e.admin, err = client.New(e.cfg, client.Options{Scheme: e.scheme}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, n := range []string{tenantNS, edgeNS} {
		e.create(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}})
	}
	e.vpc = &cloudv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Name: vpcName, Namespace: tenantNS},
		Spec: cloudv1alpha1.VPCSpec{Networks: []cloudv1alpha1.Network{"fd00:10::/32"}}}
	e.create(e.vpc)
	p := &galacticv1alpha1.EdgeProvider{
		ObjectMeta: metav1.ObjectMeta{Name: providerName},
		Spec: galacticv1alpha1.EdgeProviderSpec{
			ContractVersions: []string{contract},
			Capabilities:     []galacticv1alpha1.EdgeCapability{{Name: route.PrefixReachability, Version: "v1"}},
			ServiceAccounts:  []galacticv1alpha1.ServiceAccountReference{{Namespace: edgeNS, Name: providerName}},
			Configuration:    galacticv1alpha1.ConfigurationKind{Group: "connect.example.com", Kind: "Config"},
		},
	}
	e.create(p)
	p.Status.Approved = true
	if err := e.admin.Status().Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	e.svc = &galacticv1alpha1.EdgeService{
		ObjectMeta: metav1.ObjectMeta{Name: svcName, Namespace: tenantNS},
		Spec: galacticv1alpha1.EdgeServiceSpec{
			ProviderRef:  galacticv1alpha1.EdgeProviderReference{Name: providerName},
			VPCRef:       galacticv1alpha1.EdgeVPCReference{Name: vpcName, UID: string(e.vpc.UID)},
			Capabilities: []string{"PacketAccess", route.PrefixReachability},
			Prefixes:     []string{e2eSite.String()},
		},
	}
	e.create(e.svc)

	// The node: VPC A's host VRF, the uSID datapath loaded with the VRF's
	// uSID entry, as galactic-cni leaves them.
	e.host = newNS(t)
	in(t, e.host, func() error {
		vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: intf.GenerateInterfaceNameVRF(vpcA)}, Table: vrfTables[vpcA]}
		if err := netlink.LinkAdd(vrf); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(vrf); err != nil {
			return err
		}
		return os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0o644)
	})
	e.pinDir = fmt.Sprintf("/sys/fs/bpf/galactic-edge-e2e-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(e.pinDir) })
	objs, err := attach.Load(e.pinDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	registry, closer, err := usidmap.OpenPinnedRegistry(e.pinDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closer.Close() }()
	if err := registry.VRF.Register(0xfc0000010000, 0x101, vrfTables[vpcA], usidmap.EgressKindVeth); err != nil {
		t.Fatal(err)
	}
	if e.gates, err = forwardgatemap.OpenPinned(e.pinDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.gates.Close() })

	e.run(func(mgr ctrl.Manager) error { return route.Setup(mgr, e2eParams, timing.BootClock, "galactic-system") })
	e.reader = &switchReader{}
	e.stop = e.startAgent(1)
	return e
}

func (e *e2e) create(obj client.Object) {
	e.t.Helper()
	if err := e.admin.Create(context.Background(), obj); err != nil {
		e.t.Fatalf("create %T %s: %v", obj, obj.GetName(), err)
	}
}

// run starts a manager with what setup registers, and returns its stop.
func (e *e2e) run(setup func(ctrl.Manager) error) func() {
	e.t.Helper()
	mgr, err := ctrl.NewManager(e.cfg, ctrl.Options{
		Scheme: e.scheme, Metrics: metricsserver.Options{BindAddress: "0"},
		Cache:      cache.Options{ByObject: route.LeaseCache()},
		Controller: config.Controller{SkipNameValidation: ptr.To(true)},
	})
	if err != nil {
		e.t.Fatal(err)
	}
	if err := setup(mgr); err != nil {
		e.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			if err := <-done; err != nil {
				e.t.Errorf("manager: %v", err)
			}
		})
	}
	e.t.Cleanup(stop)
	return stop
}

// startAgent starts galactic-edge process seq on the node and returns its
// stop.
func (e *e2e) startAgent(seq int) func() {
	auth, err := ownership.New(filepath.Join(os.TempDir(), fmt.Sprintf("galactic-edge-e2e-%d", os.Getpid())))
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() {
		_ = os.RemoveAll(filepath.Join(os.TempDir(), fmt.Sprintf("galactic-edge-e2e-%d", os.Getpid())))
	})
	host, err := hostattach.OpenNamespace(e.host)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = host.Close() })
	return e.run(func(mgr ctrl.Manager) error {
		e.reader.Reader = mgr.GetAPIReader()
		a := &Agent{
			Client: mgr.GetClient(), NodeName: node, Owner: NewOwner(node, time.Unix(int64(seq), 0), "e2e"),
			Ownership: auth, Host: host, Namespaces: e.pods,
			Datapath: nsDatapath{PinnedDatapath: PinnedDatapath{PinDir: e.pinDir}, host: e.host},
			MTU:      mtu, APIReader: e.reader, Gates: PinnedGates{PinDir: e.pinDir},
			Params: e2eParams, BootID: e.bootID,
		}
		return a.SetupWithManager(mgr)
	})
}

// site is a provider pod with its packet attachment, the TUN responder
// standing in for the site behind it, and its process's lease.
type site struct {
	e     *e2e
	name  string
	pod   *corev1.Pod
	inst  *galacticv1alpha1.EdgeInstance
	att   *galacticv1alpha1.EdgeAttachment
	addr  netip.Addr
	ns    string
	proc  *claim.Instance
	lease claim.Lease
	// stop ends the process's renewals without releasing anything, as a
	// crash or a pause does.
	stop    chan struct{}
	stopped chan struct{}

	mu       sync.Mutex
	received []time.Duration
}

func (e *e2e) site(name, address string) *site {
	e.t.Helper()
	ctx := context.Background()
	s := &site{e: e, name: name, addr: netip.MustParseAddr(address), ns: newNS(e.t)}
	s.pod = &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: edgeNS},
		Spec: corev1.PodSpec{NodeName: node, Containers: []corev1.Container{{Name: "p", Image: "p"}}}}
	e.create(s.pod)
	e.pods.set(string(s.pod.UID), s.ns)
	s.inst = edgeprovider.NewInstance(edgeNS, providerName, name, string(s.pod.UID), node, e.bootID)
	e.create(s.inst)
	s.att = &galacticv1alpha1.EdgeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "att-" + name, Namespace: edgeNS},
		Spec: galacticv1alpha1.EdgeAttachmentSpec{
			ProviderRef:     galacticv1alpha1.EdgeProviderReference{Name: providerName},
			ServiceRef:      galacticv1alpha1.EdgeServiceReference{Namespace: tenantNS, Name: svcName, UID: string(e.svc.UID)},
			InstanceRef:     galacticv1alpha1.EdgeInstanceReference{Name: s.inst.Name},
			PodUID:          string(s.pod.UID),
			ContractVersion: contract,
			Capabilities:    []galacticv1alpha1.EdgeCapability{{Name: "PacketAccess", Version: "v1"}},
			PacketDevice:    &galacticv1alpha1.EdgePacketDevice{Owner: 0, Group: 0},
		},
	}
	e.create(s.att)
	s.att.Status = galacticv1alpha1.EdgeAttachmentStatus{NodeName: node, VPC: vpcA, Address: address}
	for _, c := range []string{galacticv1alpha1.EdgeAttachmentAdmitted, galacticv1alpha1.EdgeAttachmentAllocated} {
		meta.SetStatusCondition(&s.att.Status.Conditions, metav1.Condition{Type: c, Status: metav1.ConditionTrue, Reason: c})
	}
	if err := e.admin.Status().Update(ctx, s.att); err != nil {
		e.t.Fatal(err)
	}
	// The provider waits for its device, opens it, then reports Ready.
	var tun string
	eventually(e.t, name+" programmed", func() bool {
		var a galacticv1alpha1.EdgeAttachment
		if err := e.admin.Get(ctx, client.ObjectKeyFromObject(s.att), &a); err != nil {
			return false
		}
		tun = a.Status.PacketDevice
		return meta.IsStatusConditionTrue(a.Status.Conditions, galacticv1alpha1.EdgeAttachmentProgrammed)
	})
	s.serve(tun)
	if err := e.admin.Get(ctx, client.ObjectKeyFromObject(s.att), s.att); err != nil {
		e.t.Fatal(err)
	}
	meta.SetStatusCondition(&s.att.Status.Conditions, metav1.Condition{Type: galacticv1alpha1.EdgeAttachmentReady,
		Status: metav1.ConditionTrue, Reason: "Ready"})
	if err := e.admin.Status().Update(ctx, s.att); err != nil {
		e.t.Fatal(err)
	}
	return s
}

// serve answers nothing: it records when each packet for the site reaches
// the pod's TUN device, which only a forwarding node delivers.
func (s *site) serve(tun string) {
	var f *os.File
	if err := inNS(s.ns, func() error {
		fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		ifr, err := unix.NewIfreq(tun)
		if err != nil {
			_ = unix.Close(fd)
			return err
		}
		ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
		if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
			_ = unix.Close(fd)
			return err
		}
		f = os.NewFile(uintptr(fd), tun)
		return nil
	}); err != nil {
		s.e.t.Fatal(err)
	}
	s.e.t.Cleanup(func() { _ = f.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := f.Read(buf)
			if err != nil {
				return
			}
			if n >= 40 && buf[0]>>4 == 6 && netip.AddrFrom16([16]byte(buf[24:40])) == e2eSiteHost {
				now := timing.BootClock()
				s.mu.Lock()
				s.received = append(s.received, now)
				s.mu.Unlock()
			}
		}
	}()
}

func (s *site) times() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.received)
}

// start runs the provider process: it takes its instance lease, through the
// quarantine of a new record, claims the route and keeps renewing every
// third of the lease, claiming again whenever its claim ended.
func (s *site) start(routeName string) {
	ctx := context.Background()
	s.proc = &claim.Instance{ID: s.name + "-proc", Store: edgeprovider.InstanceStore{Client: s.e.admin, Namespace: edgeNS},
		Clock: timing.BootClock, Params: e2eParams}
	eventually(s.e.t, s.name+" lease", func() bool {
		l, err := s.proc.Acquire(ctx, s.inst.Name)
		s.lease = l
		return err == nil
	})
	s.claim(routeName)
	s.stop, s.stopped = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(s.stopped)
		tick := time.NewTicker(e2eParams.Duration / 3)
		defer tick.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-tick.C:
			}
			if l, err := s.proc.Renew(ctx, s.lease); err == nil {
				s.lease = l
			}
			s.claim(routeName)
		}
	}()
}

func (s *site) claim(routeName string) {
	ctx := context.Background()
	var rt galacticv1alpha1.EdgeRoute
	if err := s.e.admin.Get(ctx, client.ObjectKey{Namespace: edgeNS, Name: routeName}, &rt); err != nil {
		return
	}
	_ = edgeprovider.Claim(ctx, s.e.admin, &rt, s.att.Name, string(s.pod.UID), s.lease)
}

// kill stops the process without releasing anything.
func (s *site) kill() {
	close(s.stop)
	<-s.stopped
}

// prober sends one packet for the site through each listed host link, every
// interval, straight onto the link as the node itself transmits: it passes
// the link's tc egress, and so its gate, whatever the host routes say.
type prober struct {
	stop chan struct{}
	done chan struct{}
}

func (e *e2e) probe(interval time.Duration, sites ...*site) *prober {
	e.t.Helper()
	type target struct {
		fd    int
		frame []byte
	}
	targets := make([]target, 0, len(sites))
	for _, s := range sites {
		var hostMAC, podMAC net.HardwareAddr
		var index int
		in(e.t, e.host, func() error {
			var a galacticv1alpha1.EdgeAttachment
			if err := e.admin.Get(context.Background(), client.ObjectKeyFromObject(s.att), &a); err != nil {
				return err
			}
			l, err := netlink.LinkByName(a.Status.HostLink)
			if err != nil {
				return err
			}
			hostMAC, index = l.Attrs().HardwareAddr, l.Attrs().Index
			neighs, err := netlink.NeighList(index, unix.AF_INET6)
			if err != nil {
				return err
			}
			for _, n := range neighs {
				if n.IP.Equal(s.addr.AsSlice()) {
					podMAC = n.HardwareAddr
				}
			}
			if podMAC == nil {
				return fmt.Errorf("no neighbor for %s on %s", s.addr, a.Status.HostLink)
			}
			return nil
		})
		var fd int
		in(e.t, e.host, func() error {
			var err error
			fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_IPV6)))
			if err != nil {
				return err
			}
			return unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IPV6), Ifindex: index})
		})
		e.t.Cleanup(func() { _ = unix.Close(fd) })
		frame := make([]byte, 14+40+8)
		copy(frame[0:6], podMAC)
		copy(frame[6:12], hostMAC)
		binary.BigEndian.PutUint16(frame[12:14], unix.ETH_P_IPV6)
		ip := frame[14:]
		ip[0] = 6 << 4
		binary.BigEndian.PutUint16(ip[4:6], 8)
		ip[6], ip[7] = 58, 64
		src, dst := e2eSource.As16(), e2eSiteHost.As16()
		copy(ip[8:24], src[:])
		copy(ip[24:40], dst[:])
		ip[40] = 128
		targets = append(targets, target{fd: fd, frame: frame})
	}
	p := &prober{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(p.done)
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-tick.C:
			}
			for _, t := range targets {
				_, _ = unix.Write(t.fd, t.frame)
			}
		}
	}()
	return p
}

func (p *prober) end() {
	close(p.stop)
	<-p.done
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func (e *e2e) acceptedAttachment(routeName string) string {
	var rt galacticv1alpha1.EdgeRoute
	if err := e.admin.Get(context.Background(), client.ObjectKey{Namespace: edgeNS, Name: routeName}, &rt); err != nil {
		return ""
	}
	if rt.Status.Accepted == nil || !meta.IsStatusConditionTrue(rt.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted) {
		return ""
	}
	return rt.Status.Accepted.Attachment
}

func (e *e2e) lastRenewStart(s *site) time.Duration {
	r, err := edgeprovider.InstanceStore{Client: e.admin, Namespace: edgeNS}.Get(context.Background(), s.inst.Name)
	if err != nil {
		e.t.Fatal(err)
	}
	return r.RenewStart
}

// receivedAfter reports whether s received anything at or after t.
func receivedAfter(s *site, t time.Duration) bool {
	ts := s.times()
	return len(ts) > 0 && ts[len(ts)-1] >= t
}

// TestReplacement drives a prefix through its whole ownership lifecycle on a
// real kernel and API server and checks, packet by packet, that no two
// attachments forward it at once: failure-matrix rows 10 and 11 (the holder
// crashes or pauses), 13 (replacement, here by another attachment on the same
// node, with each link probed directly so a stale route cannot hide it), 13a
// (a takeover claimed while the holder renews), 12 (the agent cut off from
// the API server while packets flow), 15 (galactic-edge restarts) and late
// renewal (an expired holder's renewal written after its replacement). The
// lease is scaled down to 2 s; every bound scales with it.
func TestReplacement(t *testing.T) {
	e := startE2E(t)
	ctx := context.Background()
	p := e2eParams
	a := e.site("a", "fd00:10:0:e::1")
	b := e.site("b", "fd00:10:0:e::2")

	rt := edgeprovider.NewRoute(edgeNS, providerName, string(e.vpc.UID), e2eSite)
	e.create(rt)
	a.start(rt.Name)
	eventually(t, "a accepted", func() bool { return e.acceptedAttachment(rt.Name) == a.att.Name })
	probes := e.probe(20*time.Millisecond, a, b)
	eventually(t, "a forwarding", func() bool { return len(a.times()) > 0 })

	// Row 13a: b takes the route over while a renews; nothing changes.
	b.start(rt.Name)
	held := timing.BootClock()
	time.Sleep(3 * p.TakeoverWait())
	if got := e.acceptedAttachment(rt.Name); got != a.att.Name {
		t.Fatalf("takeover accepted while the holder renews: %s", got)
	}
	if receivedAfter(b, held) || len(b.times()) != 0 {
		t.Fatal("b forwarded while a holds the route")
	}

	// Row 15: galactic-edge restarts with a forwarding; nothing pauses
	// beyond a missed renewal or two.
	e.stop()
	restarted := timing.BootClock()
	e.stop = e.startAgent(2)
	time.Sleep(2 * p.Duration)
	gap := largestGap(a.times(), restarted, timing.BootClock())
	t.Logf("galactic-edge restart: largest gap in a's forwarding %v", gap)
	if gap > p.Duration {
		t.Fatalf("forwarding paused %v across an agent restart", gap)
	}

	// Rows 10 and 11, then 13: a stops renewing, as a crashed or paused
	// process does. Its gate closes on its own deadline, b is accepted no
	// earlier than the takeover interval after a's last renewal, and the two
	// never forward at once.
	a.kill()
	lastA := e.lastRenewStart(a)
	eventually(t, "b accepted", func() bool { return e.acceptedAttachment(rt.Name) == b.att.Name })
	accepted := timing.BootClock()
	eventually(t, "b forwarding", func() bool { return len(b.times()) > 0 })
	aTimes, bTimes := a.times(), b.times()
	lastAReceived, firstB := aTimes[len(aTimes)-1], bTimes[0]
	t.Logf("holder stopped: a's last renewal +%v last forwarded, b accepted at +%v, first forwarded at +%v (outage %v)",
		lastAReceived-lastA, accepted-lastA, firstB-lastA, firstB-lastAReceived)
	if lastAReceived-lastA > p.Duration+p.Margin {
		t.Fatalf("a forwarded %v after its last renewal, past the %v bound", lastAReceived-lastA, p.Duration+p.Margin)
	}
	// Core accepts b once a's node records its gate closed, which it does
	// only after the gate's deadline, or after the takeover interval: never
	// before a's deadline.
	if accepted-lastA < p.Duration {
		t.Fatalf("b accepted %v after a's last renewal, before a's gate deadline %v", accepted-lastA, p.Duration)
	}
	if lastAReceived >= firstB {
		t.Fatalf("a and b both forwarded: a until +%v, b from +%v", lastAReceived-lastA, firstB-lastA)
	}

	// Late renewal: a's lease written fresh after b took over reopens
	// nothing.
	lease := e.lastRenewStart(a)
	aStore := edgeprovider.InstanceStore{Client: e.admin, Namespace: edgeNS}
	stale, err := aStore.Get(ctx, a.inst.Name)
	if err != nil {
		t.Fatal(err)
	}
	stale.Sequence += 100
	stale.RenewStart = timing.BootClock()
	if _, err := aStore.Update(ctx, stale); err != nil {
		t.Fatal(err)
	}
	late := timing.BootClock()
	time.Sleep(2 * p.Duration)
	if receivedAfter(a, late) {
		t.Fatalf("a's late renewal (its lease was from +%v) reopened its gate", late-lease)
	}

	// Row 12: the agent loses the API server while b's packets flow and b
	// keeps renewing. b's gate closes by its last applied renewal's deadline;
	// once the agent is back, b claims again and forwards.
	e.reader.down.Store(true)
	cut := timing.BootClock()
	time.Sleep(p.Duration + 2*p.Margin)
	bTimes = b.times()
	stoppedAt := bTimes[len(bTimes)-1]
	t.Logf("API cut: b forwarded until +%v", stoppedAt-cut)
	if stoppedAt-cut > p.Duration+p.Margin {
		t.Fatalf("b forwarded %v into an API outage, past the %v bound", stoppedAt-cut, p.Duration+p.Margin)
	}
	e.reader.down.Store(false)
	restored := timing.BootClock()
	eventually(t, "b forwarding after the outage", func() bool { return receivedAfter(b, restored) })
	if receivedAfter(a, late) {
		t.Fatal("a forwarded again")
	}
	probes.end()
	b.kill()
}

// largestGap is the longest interval between successive times in [from, to].
func largestGap(times []time.Duration, from, to time.Duration) time.Duration {
	prev, gap := from, time.Duration(0)
	for _, t := range times {
		if t < from || t > to {
			continue
		}
		gap = max(gap, t-prev)
		prev = t
	}
	return max(gap, to-prev)
}
