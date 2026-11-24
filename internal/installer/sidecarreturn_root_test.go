// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	tcx "github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/cni/vpcfence"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
)

func TestSidecarReturnMixedVersion(t *testing.T) {
	requireRoot(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = orig.Close() }()
	isolated, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = netns.Set(orig)
		_ = isolated.Close()
	}()

	pinDir, ingress, registry, policy := sidecarReturnTestDatapath(t)

	const (
		node       = "node-a"
		vpc        = "vpcone"
		hostTable  = 200
		argument   = 5
		oldTable   = sidecarReturnTableBase + argument
		attachment = "proxy-attachment"
	)
	sidecarTestVRF(t, vpc, hostTable)
	legacy, legacyMAC, legacyPeer := sidecarReturnTestLink(t, "legacy0", "")
	gateway := &net.IPNet{IP: net.ParseIP("2001:db8:aa::5"), Mask: net.CIDRMask(128, 128)}
	if err := netlink.RouteAdd(&netlink.Route{Dst: gateway, Table: oldTable, LinkIndex: legacy}); err != nil {
		t.Fatal(err)
	}

	r := router(node, testLocator, 1)
	instance := vrfInstance(crdnames.BGPVRFInstanceName(vpc, node), r.Name, argument)
	endDT46 := bgpv1alpha1.SRv6FunctionEndDT46
	advertisement := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: crdnames.BGPAdvertisementName(vpc, legacyIngressAttachment, node), Namespace: testNamespace,
			Annotations: map[string]string{
				legacyIngressHostIfindex: strconv.Itoa(legacy),
				legacyIngressHostMAC:     legacyMAC.String(),
			},
		},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: r.Name},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			VRFID:         &instance.Spec.VRFID, Function: &endDT46,
			Prefixes: []bgpv1alpha1.Prefix{bgpv1alpha1.Prefix(gateway.String())},
		},
	}
	scheme := k8sruntime.NewScheme()
	if err := bgpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(r, instance, advertisement).Build()
	ctx := t.Context()
	sid, block := sidecarReturnTestSID(t, k8s, node, argument)
	if err := registry.VRF.Register(block, argument, oldTable, usidmap.EgressKindVeth); err != nil {
		t.Fatal(err)
	}
	kinds, kindMap, err := ifindexvrfmap.OpenPinnedEgressKind(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kindMap.Close() }()
	installSidecarTestNeighbor(t, kinds, policy, legacy, gateway.IP, legacyMAC)
	if err := ensureLegacySidecarSID(registry, block, 1); err != nil {
		t.Fatal(err)
	}

	reply := sidecarReplyFixture(t, ingress, sid, gateway.IP)

	reconcile := func() {
		t.Helper()
		if err := reconcileSidecarReturn(ctx, k8s, testNamespace, node, pinDir); err != nil {
			t.Fatal(err)
		}
	}
	assertRoute := func(table, ifindex int, want bool) {
		t.Helper()
		filter := &netlink.Route{Dst: gateway, Table: table, LinkIndex: ifindex}
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, filter,
			netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST|netlink.RT_FILTER_OIF)
		if err != nil || (len(routes) > 0) != want {
			t.Fatalf("route in table %d through ifindex %d = %v, %v; want presence %t", table, ifindex, routes, err, want)
		}
	}

	// Upgrading the installer preserves the main sidecar and prepares the
	// route in the canonical table before switching the shared SRv6 entry.
	reply(legacyPeer, "legacy before installer upgrade")
	reconcile()
	assertRoute(oldTable, legacy, true)
	assertRoute(hostTable, legacy, true)
	reply(legacyPeer, "legacy after installer upgrade")
	reconcile()
	reply(legacyPeer, "legacy after another installer reconciliation")
	if row, found, err := registry.VRF.Get(block, argument); err != nil || !found || row.VRFTableID != hostTable {
		t.Fatalf("SRv6 return row = %+v, %t, %v; want table %d", row, found, err, hostTable)
	}

	// A Worker advertisement by itself is insufficient, even for the same
	// address and VPC. The routed link and its route must also be in place.
	workerAdvertisement := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: crdnames.WorkerAdvertisementName(vpc, attachment, node), Namespace: testNamespace,
			Labels: map[string]string{
				crdnames.LabelWorkerNode: node, crdnames.LabelWorkerVPC: vpc, crdnames.LabelWorkerAttachment: attachment,
			},
			Annotations: map[string]string{crdnames.AnnotationWorkerPod: "proxy-pod"},
		},
		Spec: advertisement.Spec,
	}
	if err := k8s.Create(ctx, workerAdvertisement); err != nil {
		t.Fatal(err)
	}
	reconcile()
	assertRoute(oldTable, legacy, true)
	assertRoute(hostTable, legacy, true)
	reply(legacyPeer, "legacy while Worker has only advertised")

	// Another legacy VPC can share the same gateway address and host veth.
	// Taking over the first VPC must leave their shared neighbor in place.
	const otherVPC, otherArgument, otherTable = "1", 6, 201
	sidecarTestVRF(t, otherVPC, otherTable)
	otherInstance := vrfInstance(crdnames.BGPVRFInstanceName(otherVPC, node), r.Name, otherArgument)
	if err := k8s.Create(ctx, otherInstance); err != nil {
		t.Fatal(err)
	}
	otherAdvertisement := advertisement.DeepCopy()
	otherAdvertisement.Name = crdnames.BGPAdvertisementName(otherVPC, legacyIngressAttachment, node)
	otherAdvertisement.ResourceVersion = ""
	otherAdvertisement.Spec.VRFID = &otherInstance.Spec.VRFID
	if err := k8s.Create(ctx, otherAdvertisement); err != nil {
		t.Fatal(err)
	}

	reconcile()
	assertRoute(otherTable, legacy, true)

	worker, workerMAC, workerPeer := sidecarReturnTestLink(t, "worker0", attach.InternalAliasPrefix+vpc+"/"+attachment)
	workerRoute := &netlink.Route{Dst: gateway, Table: hostTable, LinkIndex: worker, Scope: netlink.SCOPE_LINK}
	if err := netlink.RouteReplace(workerRoute); err != nil {
		t.Fatal(err)
	}
	installSidecarTestNeighbor(t, kinds, policy, worker, gateway.IP, workerMAC)
	// A later reconciliation or installer restart must not restore the
	// legacy path while the Worker path remains programmed.
	for range 2 {
		reconcile()
		assertRoute(oldTable, legacy, false)
		assertRoute(hostTable, legacy, false)
		assertRoute(hostTable, worker, true)
		assertRoute(otherTable, legacy, true)
		reply(workerPeer, "Worker after takeover reconciliation")
		assertSidecarNeighbor(t, legacy, gateway.IP)
	}
	if err := k8s.Delete(ctx, otherAdvertisement); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if infra, err := policy.IsInfra(uint32(legacy)); err != nil || infra { //nolint:gosec // kernel ifindex
		t.Fatalf("legacy traffic-policy row after Worker takeover = %t, %v; want absent", infra, err)
	}

	// Rolling the proxy back can give it a different primary veth. Reconcile
	// from the new advertisement even though the old table is already empty.
	if err := k8s.Delete(ctx, workerAdvertisement); err != nil {
		t.Fatal(err)
	}
	if err := netlink.RouteDel(workerRoute); err != nil {
		t.Fatal(err)
	}
	rolledBack, rollbackMAC, rollbackPeer := sidecarReturnTestLink(t, "legacy1", "")
	advertisement.Annotations[legacyIngressHostIfindex] = strconv.Itoa(rolledBack)
	advertisement.Annotations[legacyIngressHostMAC] = rollbackMAC.String()
	if err := k8s.Update(ctx, advertisement); err != nil {
		t.Fatal(err)
	}
	reconcile()
	assertRoute(hostTable, rolledBack, true)
	assertRoute(hostTable, worker, false)
	reply(rollbackPeer, "legacy after rollback")
	reconcile()
	reply(rollbackPeer, "legacy after another rollback reconciliation")

	// Link removal also removes the kernel route before the installer can
	// inspect it. The stale advertisement still names the old map entries.
	removeSidecarTestLink(t, rolledBack)
	reconcile()
	if err := k8s.Get(ctx, client.ObjectKeyFromObject(advertisement), advertisement); !apierrors.IsNotFound(err) {
		t.Fatalf("legacy advertisement after the pod disappears: %v, want not found", err)
	}
	if _, present, err := kinds.Get(uint32(rolledBack)); err != nil || present { //nolint:gosec // kernel ifindex
		t.Fatalf("legacy redirect kind after the pod disappears = %t, %v; want absent", present, err)
	}
}

func installSidecarTestNeighbor(
	t *testing.T, kinds *ifindexvrfmap.EgressKindTable, policy *tpmap.Maps, index int, addr net.IP, mac net.HardwareAddr,
) {
	t.Helper()
	ifindex := uint32(index) //nolint:gosec // positive kernel ifindex
	if err := policy.PutInfra(ifindex); err != nil {
		t.Fatal(err)
	}
	if err := kinds.Register(ifindex, usidmap.EgressKindVeth); err != nil {
		t.Fatal(err)
	}
	addSidecarTestNeighbor(t, index, addr, mac)
}

func removeSidecarTestLink(t *testing.T, ifindex int) {
	t.Helper()
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkDel(link); err != nil {
		t.Fatal(err)
	}
}

func sidecarReturnTestSID(t *testing.T, k8s client.Client, node string, argument uint16) (netip.Addr, uint64) {
	t.Helper()
	locator, err := nodeLocatorPrefix(t.Context(), k8s, testNamespace, node)
	if err != nil {
		t.Fatal(err)
	}
	block, err := uformat.Block(locator.Addr())
	if err != nil {
		t.Fatal(err)
	}
	nodeID, err := uformat.NodeID(locator.Addr())
	if err != nil {
		t.Fatal(err)
	}
	sid, err := uformat.Encode(uformat.Fields{
		Block: block, NodeID: nodeID, Function: uformat.FunctionEndDT46, Argument: argument,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sid, block
}

func sidecarReturnTestDatapath(t *testing.T) (string, *ebpf.Program, *usidmap.Registry, *tpmap.Maps) {
	t.Helper()
	prevDir := vpcfence.Dir
	vpcfence.Dir = t.TempDir()
	t.Cleanup(func() { vpcfence.Dir = prevDir })

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-installer-legacy-return-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	objs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	registry, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closer.Close() })
	policy, err := tpmap.OpenPinned(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(policy.Close)

	return pinDir, objs.UsidIngress, registry, policy
}

func sidecarTestVRF(t *testing.T, vpc string, table uint32) {
	t.Helper()
	link := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: intf.GenerateInterfaceNameVRF(vpc)},
		Table:     table,
	}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
}

func assertSidecarNeighbor(t *testing.T, ifindex int, addr net.IP) {
	t.Helper()
	neighbors, err := netlink.NeighList(ifindex, netlink.FAMILY_V6)
	if err != nil {
		t.Fatal(err)
	}
	for _, neighbor := range neighbors {
		if neighbor.IP.Equal(addr) && neighbor.State&netlink.NUD_PERMANENT != 0 {
			return
		}
	}
	t.Fatal("Worker takeover removed a neighbor still used by another legacy VPC")
}

func sidecarReturnTestLink(t *testing.T, name, alias string) (int, net.HardwareAddr, netns.NsHandle) {
	t.Helper()
	pair := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "-peer"}
	if err := netlink.LinkAdd(pair); err != nil {
		t.Fatal(err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetAlias(link, alias); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	peerName := name + "-peer"
	peer, err := netlink.LinkByName(peerName)
	if err != nil {
		t.Fatal(err)
	}
	hostNS, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hostNS.Close() }()
	podNS, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = podNS.Close() })
	defer func() {
		if err := netns.Set(hostNS); err != nil {
			t.Fatal(err)
		}
	}()
	host, err := netlink.NewHandleAt(hostNS)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()
	if err := host.LinkSetNsFd(peer, int(podNS)); err != nil {
		t.Fatal(err)
	}
	peer, err = netlink.LinkByName(peerName)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(peer); err != nil {
		t.Fatal(err)
	}
	return link.Attrs().Index, peer.Attrs().HardwareAddr, podNS
}

func sidecarReplyFixture(
	t *testing.T, ingress *ebpf.Program, sid netip.Addr, gateway net.IP,
) func(netns.NsHandle, string) {
	t.Helper()
	const uplink = "fabric0"
	const peer = "fabric-peer"
	pair := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: uplink}, PeerName: peer}
	if err := netlink.LinkAdd(pair); err != nil {
		t.Fatal(err)
	}
	fabric, err := netlink.LinkByName(uplink)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := netlink.LinkByName(peer)
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range []netlink.Link{fabric, backend} {
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/fabric0/forwarding", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	program, err := tcx.AttachTCX(tcx.TCXOptions{
		Interface: fabric.Attrs().Index, Program: ingress, Attach: ebpf.AttachTCXIngress,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = program.Close() })

	backendIP := netip.MustParseAddr("2001:db8:2::1")
	tunnelSource := netip.MustParseAddr("2001:db8:3::1")
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(loopback); err != nil {
		t.Fatal(err)
	}
	addSidecarTestAddress(t, loopback, backendIP.AsSlice())
	addSidecarTestAddress(t, backend, tunnelSource.AsSlice())
	// Both ends of the underlay veth are in this namespace. Give the tunnel
	// an on-link route to the synthetic SID rather than assigning it locally.
	if err := netlink.RouteAdd(&netlink.Route{
		Dst: sidecarTestHostPrefix(sid.AsSlice()), LinkIndex: backend.Attrs().Index,
	}); err != nil {
		t.Fatal(err)
	}
	addSidecarTestNeighbor(t, backend.Attrs().Index, sid.AsSlice(), fabric.Attrs().HardwareAddr)
	const ignoreEncapsulationLimit = 1 // IP6_TNL_F_IGN_ENCAP_LIMIT from linux/ip6_tunnel.h
	tunnel := &netlink.Ip6tnl{
		LinkAttrs: netlink.LinkAttrs{Name: "proxy-replies"}, Local: tunnelSource.AsSlice(), Remote: sid.AsSlice(),
		Ttl: 64, Proto: unix.IPPROTO_IPV6, Flags: ignoreEncapsulationLimit,
	}
	if err := netlink.LinkAdd(tunnel); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(tunnel); err != nil {
		t.Fatal(err)
	}
	if err := netlink.RouteAdd(&netlink.Route{
		Dst: sidecarTestHostPrefix(gateway), LinkIndex: tunnel.Attrs().Index,
	}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenTCP("tcp6", net.TCPAddrFromAddrPort(netip.AddrPortFrom(backendIP, 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	// A live TCP session is reused until the proxy's namespace changes.
	// Requests reach the listener over a separate veth. Every response,
	// starting with the SYN-ACK, comes back through the installer datapath.
	type flow struct{ proxy, backend *net.TCPConn }
	flows := map[netns.NsHandle]flow{}
	return func(pod netns.NsHandle, stage string) {
		t.Helper()
		connection, ok := flows[pod]
		if !ok {
			proxy, backend := sidecarTestTCPFlow(t, pod, gateway, backendIP, listener, stage)
			connection = flow{proxy, backend}
			flows[pod] = connection
		}
		if err := connection.proxy.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := connection.backend.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(connection.backend, stage); err != nil {
			t.Fatalf("%s: write backend reply: %v", stage, err)
		}
		buf := make([]byte, len(stage))
		if _, err := io.ReadFull(connection.proxy, buf); err != nil {
			t.Fatalf("%s: receive backend reply on the same TCP connection: %v", stage, err)
		}
		if string(buf) != stage {
			t.Fatalf("backend reply = %q, want %q", buf, stage)
		}
	}
}

func sidecarTestTCPFlow(
	t *testing.T, pod netns.NsHandle, gateway net.IP, backendIP netip.Addr, listener *net.TCPListener, stage string,
) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	name := fmt.Sprintf("proxy-req-%d", pod)
	const podRequests = "proxy-requests"
	pair := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: podRequests, PeerNamespace: netlink.NsFd(pod),
	}
	if err := netlink.LinkAdd(pair); err != nil {
		t.Fatal(err)
	}
	outbound, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(outbound); err != nil {
		t.Fatal(err)
	}
	host, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()
	if err := netns.Set(pod); err != nil {
		t.Fatal(err)
	}
	proxy := func() *net.TCPConn {
		defer func() {
			if err := netns.Set(host); err != nil {
				t.Fatal(err)
			}
		}()
		link, err := netlink.LinkByName(podRequests)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
		addSidecarTestAddress(t, link, gateway)
		if err := netlink.RouteAdd(&netlink.Route{
			Dst: sidecarTestHostPrefix(backendIP.AsSlice()), LinkIndex: link.Attrs().Index,
		}); err != nil {
			t.Fatal(err)
		}
		addSidecarTestNeighbor(t, link.Attrs().Index, backendIP.AsSlice(), outbound.Attrs().HardwareAddr)
		dialer := net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: gateway}}
		conn, err := dialer.DialContext(t.Context(), "tcp6", listener.Addr().String())
		if err != nil {
			t.Fatalf("%s: establish proxy flow: %v", stage, err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn.(*net.TCPConn)
	}()
	if err := listener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	backend, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	return proxy, backend
}

func sidecarTestHostPrefix(addr net.IP) *net.IPNet {
	return &net.IPNet{IP: addr, Mask: net.CIDRMask(128, 128)}
}

func addSidecarTestAddress(t *testing.T, link netlink.Link, addr net.IP) {
	t.Helper()
	address := &netlink.Addr{IPNet: sidecarTestHostPrefix(addr), Flags: unix.IFA_F_NODAD}
	if err := netlink.AddrAdd(link, address); err != nil {
		t.Fatal(err)
	}
}

func addSidecarTestNeighbor(t *testing.T, ifindex int, addr net.IP, mac net.HardwareAddr) {
	t.Helper()
	if err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex: ifindex, Family: netlink.FAMILY_V6, State: netlink.NUD_PERMANENT, IP: addr, HardwareAddr: mac,
	}); err != nil {
		t.Fatal(err)
	}
}
