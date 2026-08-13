// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroute

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/vrf"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	testNamespace   = "ns"
	testNodeName    = "compute-1"
	testGatewayNode = "gw-a"
	testVPC         = "vpc-a"
	testAttachment  = "attach-1"
	testEgressSID   = "2001:db8:eeee::1"
	testVRFID       = int32(42)
)

// testLogger discards everything -- these tests assert on Result and
// fake-client state directly, not log output.
type testLogger struct{}

func (testLogger) Info(string, ...any)         {}
func (testLogger) Error(error, string, ...any) {}

func newEgressTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := bgpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return scheme
}

// acceptedPolicy builds a NetworkEgressPolicy fixture with the Accepted
// condition already set true and assigned to testGatewayNode -- this
// package (unlike internal/controller) has no existing acceptRule-style
// fixture to reuse.
func acceptedPolicy(vpc string) *bgpv1alpha1.NetworkEgressPolicy {
	return &bgpv1alpha1.NetworkEgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: vpc + "-" + testAttachment},
		Spec:       bgpv1alpha1.NetworkEgressPolicySpec{VPCRef: vpc, VPCAttachmentRef: testAttachment},
		Status: bgpv1alpha1.NetworkEgressPolicyStatus{
			AssignedGatewayNode: testGatewayNode,
			Conditions: []metav1.Condition{{
				Type:   bgpv1alpha1.ConditionTypeAccepted,
				Status: metav1.ConditionTrue,
				Reason: bgpv1alpha1.AcceptedReasonOwnershipVerified,
			}},
		},
	}
}

func testGateway(egressSID string) *bgpv1alpha1.NetworkGateway {
	return &bgpv1alpha1.NetworkGateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testGatewayNode},
		Status:     bgpv1alpha1.NetworkGatewayStatus{EgressSID: egressSID},
	}
}

func testVRFInstance(vpc, node string, vrfID int32) *bgpv1alpha1.BGPVRFInstance {
	return &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: crdnames.BGPVRFInstanceName(vpc, node)},
		Spec:       bgpv1alpha1.BGPVRFInstanceSpec{VRFID: vrfID},
	}
}

// --- acceptedEgressPolicyByVPC -----------------------------------------

func TestAcceptedEgressPolicyByVPC_OnlyAcceptedIncluded(t *testing.T) {
	scheme := newEgressTestScheme(t)
	accepted := acceptedPolicy(testVPC)
	notAccepted := &bgpv1alpha1.NetworkEgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "vpc-b-attach"},
		Spec:       bgpv1alpha1.NetworkEgressPolicySpec{VPCRef: "vpc-b", VPCAttachmentRef: "attach"},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(accepted, notAccepted).Build()

	byVPC, err := acceptedEgressPolicyByVPC(context.Background(), c, testNamespace)
	if err != nil {
		t.Fatalf("acceptedEgressPolicyByVPC: %v", err)
	}
	if _, ok := byVPC[testVPC]; !ok {
		t.Errorf("accepted policy for %q missing from result", testVPC)
	}
	if _, ok := byVPC["vpc-b"]; ok {
		t.Errorf("non-accepted policy for vpc-b should not appear in result")
	}
}

func TestAcceptedEgressPolicyByVPC_DeletingExcluded(t *testing.T) {
	scheme := newEgressTestScheme(t)
	policy := acceptedPolicy(testVPC)
	now := metav1.Now()
	policy.DeletionTimestamp = &now
	policy.Finalizers = []string{"keep-alive-for-test"} // fake client requires a finalizer to accept a deletion timestamp

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build()

	byVPC, err := acceptedEgressPolicyByVPC(context.Background(), c, testNamespace)
	if err != nil {
		t.Fatalf("acceptedEgressPolicyByVPC: %v", err)
	}
	if _, ok := byVPC[testVPC]; ok {
		t.Error("a policy being deleted must be excluded, even if still Accepted")
	}
}

// --- resolveEgressDestination -------------------------------------------

func TestResolveEgressDestination_NotEnabledReturnsNil(t *testing.T) {
	scheme := newEgressTestScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	dest, err := resolveEgressDestination(context.Background(), c, testNamespace, testNodeName, testVPC, nil)
	if err != nil {
		t.Fatalf("resolveEgressDestination: %v", err)
	}
	if dest != nil {
		t.Errorf("dest = %v, want nil (no enabled policy for this VPC)", dest)
	}
}

func TestResolveEgressDestination_AssignedGatewayMissingIsNilNotError(t *testing.T) {
	scheme := newEgressTestScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	enabled := map[string]*bgpv1alpha1.NetworkEgressPolicy{
		testVPC: acceptedPolicy(testVPC),
	}
	dest, err := resolveEgressDestination(context.Background(), c, testNamespace, testNodeName, testVPC, enabled)
	if err != nil {
		t.Fatalf("resolveEgressDestination: %v", err)
	}
	if dest != nil {
		t.Errorf("dest = %v, want nil (assigned NetworkGateway doesn't exist yet)", dest)
	}
}

func TestResolveEgressDestination_GatewayNotOfferingEgressIsNilNotError(t *testing.T) {
	scheme := newEgressTestScheme(t)
	gw := testGateway("") // EgressSID empty -- not offering egress
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw).Build()

	enabled := map[string]*bgpv1alpha1.NetworkEgressPolicy{
		testVPC: acceptedPolicy(testVPC),
	}
	dest, err := resolveEgressDestination(context.Background(), c, testNamespace, testNodeName, testVPC, enabled)
	if err != nil {
		t.Fatalf("resolveEgressDestination: %v", err)
	}
	if dest != nil {
		t.Errorf("dest = %v, want nil (assigned gateway's EgressSID is empty)", dest)
	}
}

func TestResolveEgressDestination_NoLocalVRFInstanceIsNilNotError(t *testing.T) {
	scheme := newEgressTestScheme(t)
	gw := testGateway(testEgressSID)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw).Build()

	enabled := map[string]*bgpv1alpha1.NetworkEgressPolicy{
		testVPC: acceptedPolicy(testVPC),
	}
	dest, err := resolveEgressDestination(context.Background(), c, testNamespace, testNodeName, testVPC, enabled)
	if err != nil {
		t.Fatalf("resolveEgressDestination: %v", err)
	}
	if dest != nil {
		t.Errorf("dest = %v, want nil (no BGPVRFInstance for this VPC on this node yet)", dest)
	}
}

func TestResolveEgressDestination_ComposesFullUSID(t *testing.T) {
	scheme := newEgressTestScheme(t)
	gw := testGateway(testEgressSID)
	vrfInst := testVRFInstance(testVPC, testNodeName, testVRFID)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw, vrfInst).Build()

	enabled := map[string]*bgpv1alpha1.NetworkEgressPolicy{
		testVPC: acceptedPolicy(testVPC),
	}
	dest, err := resolveEgressDestination(context.Background(), c, testNamespace, testNodeName, testVPC, enabled)
	if err != nil {
		t.Fatalf("resolveEgressDestination: %v", err)
	}
	if dest == nil {
		t.Fatal("dest = nil, want a resolved destination uSID")
	}
	// Locator (Block+Node-ID, top 8 bytes) must match egress_sid's own;
	// the low 12 bits (Argument) must carry this VPC's own VRFID.
	locator := net.ParseIP(testEgressSID).To16()
	got := *dest
	if got == nil || len(got) != 16 {
		t.Fatalf("dest = %v, want a 16-byte IPv6 address", got)
	}
	for i := range 8 {
		if got[i] != locator[i] {
			t.Fatalf("dest = %v, locator bytes don't match egress_sid %s", got, testEgressSID)
		}
	}
	arg := (uint16(got[8]&0x0F) << 8) | uint16(got[9])
	if arg != uint16(testVRFID) {
		t.Errorf("dest Argument = %#x, want %#x (this VPC's own VRFID)", arg, testVRFID)
	}
}

func TestResolveEgressDestination_VRFIDOutOfArgumentRangeErrors(t *testing.T) {
	scheme := newEgressTestScheme(t)
	gw := testGateway(testEgressSID)
	// 4096 (0x1000) overflows the 12-bit Argument field (max 0xFFF).
	vrfInst := testVRFInstance(testVPC, testNodeName, 4096)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw, vrfInst).Build()

	enabled := map[string]*bgpv1alpha1.NetworkEgressPolicy{
		testVPC: acceptedPolicy(testVPC),
	}
	_, err := resolveEgressDestination(context.Background(), c, testNamespace, testNodeName, testVPC, enabled)
	if err == nil {
		t.Error("resolveEgressDestination with an out-of-range VRFID: want an error, got nil")
	}
}

// --- Run, end-to-end against real kernel state --------------------------

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_NET_ADMIN) to create a test network namespace, " +
			"a real VRF, and install routes; re-run via sudo")
	}
}

// TestRun_InstallsThenRemovesDefaultRoute proves the full enable/disable
// lifecycle against a real kernel VRF: enabling egress installs a working
// ::/0 SEG6 encap route in the VRF's own table, and withdrawing enablement
// (deleting the NetworkEgressPolicy) removes it again on the next pass.
func TestRun_InstallsThenRemovesDefaultRoute(t *testing.T) {
	requireRoot(t)

	const (
		vpc       = "rtest"
		ifaceName = "egrtest0"
		ifaceAddr = "2001:db8:1::1/64"
		sidRoute  = "2001:db8:eeee::/64" // reachable via ifaceAddr's subnet
		sidGw     = "2001:db8:1::2"      // on-link next-hop
	)

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	defer func() { _ = nsObj.Close() }()

	var tableID uint32
	err = nsObj.Do(func(_ ns.NetNS) error {
		if addErr := vrf.Add(vpc); addErr != nil {
			return fmt.Errorf("vrf.Add: %w", addErr)
		}
		var tidErr error
		tableID, tidErr = vrf.TableID(vpc)
		if tidErr != nil {
			return fmt.Errorf("vrf.TableID: %w", tidErr)
		}

		dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: ifaceName}}
		if linkErr := netlink.LinkAdd(dummy); linkErr != nil {
			return fmt.Errorf("add dummy link: %w", linkErr)
		}
		if upErr := netlink.LinkSetUp(dummy); upErr != nil {
			return fmt.Errorf("set link up: %w", upErr)
		}
		addr, addrErr := netlink.ParseAddr(ifaceAddr)
		if addrErr != nil {
			return fmt.Errorf("parse addr: %w", addrErr)
		}
		if addrAddErr := netlink.AddrAdd(dummy, addr); addrAddErr != nil {
			return fmt.Errorf("add addr: %w", addrAddErr)
		}
		_, sidDst, cidrErr := net.ParseCIDR(sidRoute)
		if cidrErr != nil {
			return fmt.Errorf("parse SID route: %w", cidrErr)
		}
		route := &netlink.Route{LinkIndex: dummy.Attrs().Index, Dst: sidDst, Gw: net.ParseIP(sidGw)}
		if routeErr := netlink.RouteAdd(route); routeErr != nil {
			return fmt.Errorf("add route to egress_sid subnet: %w", routeErr)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	t.Cleanup(func() {
		_ = nsObj.Do(func(_ ns.NetNS) error { return vrf.Delete(vpc) })
	})

	scheme := newEgressTestScheme(t)
	gw := testGateway(testEgressSID)
	vrfInst := testVRFInstance(vpc, testNodeName, testVRFID)
	policy := acceptedPolicy(vpc)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw, vrfInst, policy).Build()

	// Enable: Run must install the ::/0 route.
	var result Result
	err = nsObj.Do(func(_ ns.NetNS) error {
		result = Run(context.Background(), c, testNamespace, testNodeName, testLogger{})
		return nil
	})
	if err != nil {
		t.Fatalf("Run (enable pass): %v", err)
	}
	if result.Errors != 0 {
		t.Fatalf("Run (enable pass) result = %+v, want 0 errors", result)
	}
	if result.RoutesInstalled != 1 {
		t.Fatalf("Run (enable pass) RoutesInstalled = %d, want 1", result.RoutesInstalled)
	}

	var installed bool
	err = nsObj.Do(func(_ ns.NetNS) error {
		routes, listErr := netlink.RouteListFiltered(
			netlink.FAMILY_V6, &netlink.Route{Table: int(tableID)}, netlink.RT_FILTER_TABLE)
		if listErr != nil {
			return listErr
		}
		for _, r := range routes {
			if r.Dst != nil && r.Dst.String() == "::/0" {
				installed = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("verify installed route: %v", err)
	}
	if !installed {
		t.Fatal("::/0 route was not installed in the VRF's table after the enable pass")
	}

	// Disable: delete the policy, then Run must remove the route.
	if delErr := c.Delete(context.Background(), policy); delErr != nil {
		t.Fatalf("delete NetworkEgressPolicy: %v", delErr)
	}
	err = nsObj.Do(func(_ ns.NetNS) error {
		result = Run(context.Background(), c, testNamespace, testNodeName, testLogger{})
		return nil
	})
	if err != nil {
		t.Fatalf("Run (disable pass): %v", err)
	}
	if result.Errors != 0 {
		t.Fatalf("Run (disable pass) result = %+v, want 0 errors", result)
	}
	if result.RoutesRemoved != 1 {
		t.Fatalf("Run (disable pass) RoutesRemoved = %d, want 1", result.RoutesRemoved)
	}

	var stillInstalled bool
	err = nsObj.Do(func(_ ns.NetNS) error {
		routes, listErr := netlink.RouteListFiltered(
			netlink.FAMILY_V6, &netlink.Route{Table: int(tableID)}, netlink.RT_FILTER_TABLE)
		if listErr != nil {
			return listErr
		}
		for _, r := range routes {
			if r.Dst != nil && r.Dst.String() == "::/0" {
				stillInstalled = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("verify route removal: %v", err)
	}
	if stillInstalled {
		t.Fatal("::/0 route is still present in the VRF's table after the disable pass")
	}
}
