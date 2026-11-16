// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nodevpc_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/nodevpc"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

const (
	testNode      = "edge-1"
	testNamespace = "galactic-system"
	testRouter    = "edge-1-router"
	testLocator   = "fd00:10::/48"
	testNodeID    = 7
	// testVPC has no VRF in the test namespace until Ensure creates it.
	testVPC = "0000000e1"
	// otherTable is another VPC's host table, which no test VRF uses.
	otherTable = 4321
	// otherVPCNum is the decoded identifier of the VPC that held the stale
	// row's Argument before.
	otherVPCNum = 0x99
)

var testScheme = func() *k8sruntime.Scheme {
	s := k8sruntime.NewScheme()
	utilruntime.Must(bgpv1alpha1.AddToScheme(s))
	return s
}()

func router(locator string, nodeID int32) *bgpv1alpha1.BGPRouter {
	return &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: testRouter, Namespace: testNamespace},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef:   bgpv1alpha1.TargetRef{Kind: "Node", Name: testNode},
			LocalASN:    65000,
			RouterID:    "10.0.0.1",
			SRv6Locator: locator,
			NodeID:      nodeID,
			AddressFamilies: []bgpv1alpha1.AddressFamily{
				{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			},
		},
	}
}

func instance(t *testing.T, k8s client.Client) *bgpv1alpha1.BGPVRFInstance {
	t.Helper()
	var inst bgpv1alpha1.BGPVRFInstance
	key := client.ObjectKey{Namespace: testNamespace, Name: crdnames.BGPVRFInstanceName(testVPC, testNode)}
	if err := k8s.Get(context.Background(), key, &inst); err != nil {
		t.Fatalf("get BGPVRFInstance %s: %v", key.Name, err)
	}
	return &inst
}

// TestEnsureNoSRv6Identity refuses a node whose router has no SRv6 identity
// before it creates anything.
func TestEnsureNoSRv6Identity(t *testing.T) {
	k8s := fake.NewClientBuilder().WithScheme(testScheme).WithObjects(router("", 0)).Build()
	_, err := nodevpc.Ensure(context.Background(),
		nodevpc.Config{K8s: k8s, Namespace: testNamespace, Node: testNode, PinDir: t.TempDir()}, testVPC)
	if !errors.Is(err, nodevpc.ErrNoSRv6Identity) {
		t.Fatalf("Ensure = %v, want ErrNoSRv6Identity", err)
	}
	list := &bgpv1alpha1.BGPVRFInstanceList{}
	if err := k8s.List(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 0 {
		t.Fatalf("Ensure wrote %d BGPVRFInstances for a node with no SRv6 identity, want none", len(list.Items))
	}
}

// TestEnsure creates a VPC's host VRF, BGPVRFInstance and vrf_table row on a
// node where none exist, changes nothing on a repeated call, and reuses the
// Argument and row a CNI ADD already wrote without overwriting them.
func TestEnsure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN/CAP_BPF); re-run via sudo")
	}
	nodevpc.ArgumentLockDir = t.TempDir()

	block, err := attachreg.Node{Locator: testLocator, NodeID: testNodeID}.Block()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		// cniArgument, when nonzero, is the Argument a CNI ADD already
		// claimed for the VPC, with a tap vrf_table row on the VRF's table.
		cniArgument int32
		// staleRow leaves a tap vrf_table row for the Argument Ensure will
		// claim, mapping to another VPC's table, as a VPC that held the
		// Argument before leaves it until GC sweeps it.
		staleRow bool
	}{
		{name: "no state on the node"},
		{name: "state from a CNI ADD", cniArgument: 0x99},
		{name: "stale row for the free Argument", staleRow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			orig, err := netns.Get()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = orig.Close() }()
			ns, err := netns.New()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ns.Close(); _ = netns.Set(orig) }()
			defer func() { _ = vrf.Delete(testVPC) }()

			pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-nodevpc-%d", os.Getpid())
			t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
			objs, err := attach.Load(pinDir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = objs.Close() }()
			registry, closer, err := usidmap.OpenPinnedRegistry(pinDir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = closer.Close() }()

			objects := []client.Object{router(testLocator, testNodeID)}
			if tc.cniArgument != 0 {
				if err := vrf.Add(testVPC); err != nil {
					t.Fatal(err)
				}
				table, err := vrf.TableID(testVPC)
				if err != nil {
					t.Fatal(err)
				}
				if err := registry.VRF.Register(block, uint16(tc.cniArgument), table, usidmap.EgressKindTap); err != nil {
					t.Fatal(err)
				}
				objects = append(objects, &bgpv1alpha1.BGPVRFInstance{
					ObjectMeta: metav1.ObjectMeta{
						Name: crdnames.BGPVRFInstanceName(testVPC, testNode), Namespace: testNamespace,
					},
					Spec: nodevpc.InstanceSpec(testRouter, "65000:225", tc.cniArgument),
				})
			}
			if tc.staleRow {
				if err := registry.VRF.Register(block, uformat.ArgumentMin, otherTable, usidmap.EgressKindTap); err != nil {
					t.Fatal(err)
				}
				if err := registry.VPCAttribution.Register(block, uformat.ArgumentMin, otherVPCNum, 1,
					"G00000other"); err != nil {
					t.Fatal(err)
				}
			}
			k8s := fake.NewClientBuilder().WithScheme(testScheme).WithObjects(objects...).Build()
			cfg := nodevpc.Config{K8s: k8s, Namespace: testNamespace, Node: testNode, PinDir: pinDir}

			want := uint16(uformat.ArgumentMin)
			wantKind := usidmap.EgressKindVeth
			switch {
			case tc.cniArgument != 0:
				want, wantKind = uint16(tc.cniArgument), usidmap.EgressKindTap
			case tc.staleRow:
				wantKind = usidmap.EgressKindTap
			}
			var first nodevpc.State
			for pass := range 2 {
				s, err := nodevpc.Ensure(context.Background(), cfg, testVPC)
				if err != nil {
					t.Fatalf("Ensure pass %d: %v", pass, err)
				}
				if pass == 0 {
					first = s
				} else if s != first {
					t.Fatalf("Ensure pass %d = %+v, want the first pass's %+v", pass, s, first)
				}
				checkState(t, k8s, registry, s, block, want, wantKind)
				if attr, ok, err := registry.VPCAttribution.Get(block, want); err != nil || (ok && attr.VPC == otherVPCNum) {
					t.Fatalf("vpc_attribution_table row %+v ok=%v err=%v still names another VPC", attr, ok, err)
				}
			}
		})
	}
}

// checkState fails unless s, Ensure's result, has Block block and Argument
// want, and the test namespace holds the VPC's VRF on s's table, its
// BGPVRFInstance on the test router with VRFID want, and a vrf_table row
// mapping that Argument to s's table with egress kind wantKind.
func checkState(t *testing.T, k8s client.Client, registry *usidmap.Registry, s nodevpc.State, block uint64,
	want uint16, wantKind uint32) {
	t.Helper()
	if s.Argument != want || s.Block != block {
		t.Fatalf("Ensure = Block %#x Argument %#x, want %#x %#x", s.Block, s.Argument, block, want)
	}
	link, err := netlink.LinkByName(intf.GenerateInterfaceNameVRF(testVPC))
	if err != nil {
		t.Fatalf("host VRF after Ensure: %v", err)
	}
	if v, ok := link.(*netlink.Vrf); !ok || v.Table != s.Table {
		t.Fatalf("host VRF %+v, want a VRF on table %d", link.Attrs(), s.Table)
	}
	inst := instance(t, k8s)
	if inst.Spec.VRFID != int32(want) || inst.Spec.RouterRef == nil || inst.Spec.RouterRef.Name != testRouter {
		t.Fatalf("BGPVRFInstance spec %+v, want VRFID %#x on router %s", inst.Spec, want, testRouter)
	}
	row, ok, err := registry.VRF.Get(block, want)
	if err != nil || !ok {
		t.Fatalf("vrf_table row for Argument %#x: ok=%v err=%v", want, ok, err)
	}
	if row.VRFTableID != s.Table || row.EgressKind != wantKind {
		t.Fatalf("vrf_table row %+v, want table %d egress kind %d", row, s.Table, wantKind)
	}
}

// TestEnsureWithConcurrentClaim runs Ensure while a CNI ADD claims the same
// VPC's BGPVRFInstance on the node. Both take the node's Argument lock, so
// they converge on one instance and one Argument, and the vrf_table row maps
// that Argument to the VPC's VRF.
func TestEnsureWithConcurrentClaim(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN/CAP_BPF); re-run via sudo")
	}
	nodevpc.ArgumentLockDir = t.TempDir()
	block, err := attachreg.Node{Locator: testLocator, NodeID: testNodeID}.Block()
	if err != nil {
		t.Fatal(err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = orig.Close() }()
	ns, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ns.Close(); _ = netns.Set(orig) }()
	defer func() { _ = vrf.Delete(testVPC) }()

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-nodevpc-claim-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	objs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = objs.Close() }()

	// Another VPC's instance holds the lowest Argument, so a claim that
	// ignored the lock could pick a different free value than Ensure.
	other := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Name: crdnames.BGPVRFInstanceName("0000000e2", testNode), Namespace: testNamespace},
		Spec:       nodevpc.InstanceSpec(testRouter, "65000:226", uformat.ArgumentMin),
	}
	k8s := fake.NewClientBuilder().WithScheme(testScheme).WithObjects(router(testLocator, testNodeID), other).Build()
	cfg := nodevpc.Config{K8s: k8s, Namespace: testNamespace, Node: testNode, PinDir: pinDir}
	name := crdnames.BGPVRFInstanceName(testVPC, testNode)

	start := make(chan struct{})
	claimed := make(chan error, 1)
	var cniArgument int32
	go func() {
		<-start
		var err error
		cniArgument, _, err = nodevpc.ClaimArgument(context.Background(), k8s, testNamespace, testRouter, name, false,
			func() ([]string, error) { return nil, nil },
			func(vrfID int32) bgpv1alpha1.BGPVRFInstanceSpec {
				return nodevpc.InstanceSpec(testRouter, "65000:225", vrfID)
			},
			func(int32) error { return nil })
		claimed <- err
	}()
	close(start)
	s, err := nodevpc.Ensure(context.Background(), cfg, testVPC)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := <-claimed; err != nil {
		t.Fatalf("concurrent claim: %v", err)
	}
	if int32(s.Argument) != cniArgument {
		t.Fatalf("Ensure claimed Argument %#x, the concurrent CNI claim %#x; want one Argument", s.Argument, cniArgument)
	}
	if inst := instance(t, k8s); inst.Spec.VRFID != cniArgument {
		t.Fatalf("BGPVRFInstance VRFID %#x, want %#x", inst.Spec.VRFID, cniArgument)
	}
	registry, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closer.Close() }()
	if row, ok, err := registry.VRF.Get(block, s.Argument); err != nil || !ok || row.VRFTableID != s.Table {
		t.Fatalf("vrf_table row for Argument %#x = %+v ok=%v err=%v, want table %d", s.Argument, row, ok, err, s.Table)
	}
}

// TestEnsureRecreatesInstance creates the VPC's state, has its
// BGPVRFInstance deleted while the VRF and row stay, as galactic-router GC
// can before an attachment's link joins the VRF, and runs Ensure again: the
// instance comes back on the same Argument.
func TestEnsureRecreatesInstance(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN/CAP_BPF); re-run via sudo")
	}
	nodevpc.ArgumentLockDir = t.TempDir()
	block, err := attachreg.Node{Locator: testLocator, NodeID: testNodeID}.Block()
	if err != nil {
		t.Fatal(err)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = orig.Close() }()
	ns, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ns.Close(); _ = netns.Set(orig) }()
	defer func() { _ = vrf.Delete(testVPC) }()

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-nodevpc-recreate-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	objs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = objs.Close() }()
	registry, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closer.Close() }()

	k8s := fake.NewClientBuilder().WithScheme(testScheme).WithObjects(router(testLocator, testNodeID)).Build()
	cfg := nodevpc.Config{K8s: k8s, Namespace: testNamespace, Node: testNode, PinDir: pinDir}
	first, err := nodevpc.Ensure(context.Background(), cfg, testVPC)
	if err != nil {
		t.Fatal(err)
	}
	if err := k8s.Delete(context.Background(), instance(t, k8s)); err != nil {
		t.Fatal(err)
	}
	again, err := nodevpc.Ensure(context.Background(), cfg, testVPC)
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Fatalf("Ensure after the instance's deletion = %+v, want %+v", again, first)
	}
	checkState(t, k8s, registry, again, block, first.Argument, usidmap.EgressKindVeth)
}

// testHost runs the rest of the test on this goroutine's thread in a new
// network namespace, with the uSID maps pinned under a directory of their
// own, and returns that directory and the maps.
func testHost(t *testing.T, vpc string) (string, *usidmap.Registry) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN/CAP_BPF); re-run via sudo")
	}
	nodevpc.ArgumentLockDir = t.TempDir()
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	ns, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = vrf.Delete(vpc)
		_ = ns.Close()
		_ = netns.Set(orig)
		_ = orig.Close()
		runtime.UnlockOSThread()
	})
	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-nodevpc-%s-%d", vpc, os.Getpid())
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
	return pinDir, registry
}

// TestEnsureWideVPC creates the state of a VPC whose identifier exceeds the
// 48 bits vpc_attribution_table names a VPC by. Forwarding does not depend on
// attribution, so Ensure succeeds, leaves attribution as it is, and finds the
// state in place on a second call.
func TestEnsureWideVPC(t *testing.T) {
	const wide = "zzzzzzzzz"
	pinDir, registry := testHost(t, wide)
	block, err := attachreg.Node{Locator: testLocator, NodeID: testNodeID}.Block()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.VPCAttribution.Register(block, uformat.ArgumentMin, otherVPCNum, 1, "G00000other"); err != nil {
		t.Fatal(err)
	}
	k8s := fake.NewClientBuilder().WithScheme(testScheme).WithObjects(router(testLocator, testNodeID)).Build()
	cfg := nodevpc.Config{K8s: k8s, Namespace: testNamespace, Node: testNode, PinDir: pinDir}
	first, err := nodevpc.Ensure(context.Background(), cfg, wide)
	if err != nil {
		t.Fatalf("Ensure for a VPC wider than 48 bits: %v", err)
	}
	again, err := nodevpc.Ensure(context.Background(), cfg, wide)
	if err != nil || again != first {
		t.Fatalf("second Ensure = %+v, %v; want %+v", again, err, first)
	}
	if row, ok, err := registry.VRF.Get(block, first.Argument); err != nil || !ok || row.VRFTableID != first.Table {
		t.Fatalf("vrf_table row %+v ok=%v err=%v, want table %d", row, ok, err, first.Table)
	}
	if _, ok, err := registry.VPCAttribution.Get(block, uformat.ArgumentMin); err != nil || !ok {
		t.Fatalf("attribution row removed (ok=%v err=%v) though no number names this VPC", ok, err)
	}
}
