// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.datum.net/galactic/internal/cni/crdnames"
	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	testVPC        = "abc"
	testAttachment = "def"
	testRouterName = "overlay-router"
	testRD65000_1  = "65000:1"
	testVPCHex1234 = "0000000004d2" // decimal 1234
	testNetns      = "/proc/1/ns/net"
)

var testScheme = func() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(bgpv1alpha1.AddToScheme(s))
	return s
}()

func fakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(testScheme).WithObjects(objs...).Build()
}

func mustParseCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse CIDR %q: %v", cidr, err)
	}
	return ipnet
}

// routerForNode builds a BGPRouter with spec.targetRef.name set to nodeName.
func routerForNode(name, nodeName, namespace string, asn int64) *bgpv1alpha1.BGPRouter {
	return &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{
				Kind: "Node",
				Name: nodeName,
			},
			LocalASN: asn,
			RouterID: "10.0.0.1",
			Roles:    []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
			AddressFamilies: []bgpv1alpha1.AddressFamily{
				{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			},
		},
	}
}

// vrfInstanceForRouter builds a BGPVRFInstance targeting routerName with the
// given VRFID (the allocated Argument), for allocateArgument's test fixtures.
func vrfInstanceForRouter(name, namespace, routerName string, vrfID int32) *bgpv1alpha1.BGPVRFInstance {
	return &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget: bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: routerName}},
			VRFID:        vrfID,
		},
	}
}

// ---- allocateArgument ------------------------------------------------------

func TestAllocateArgument(t *testing.T) {
	const (
		namespace  = "default"
		routerName = "router-a"
	)

	t.Run("no existing instances allocates the lowest value", func(t *testing.T) {
		k8s := fakeClient()
		got, err := allocateArgument(context.Background(), k8s, namespace, routerName, "vpc-att-1")
		if err != nil {
			t.Fatalf("allocateArgument: unexpected error: %v", err)
		}
		if got != int32(uformat.ArgumentMin) {
			t.Errorf("allocateArgument() = %d, want %d", got, uformat.ArgumentMin)
		}
	})

	t.Run("existing instance by name is reused idempotently", func(t *testing.T) {
		existing := vrfInstanceForRouter("vpc-att-1", namespace, routerName, 99)
		k8s := fakeClient(existing)
		got, err := allocateArgument(context.Background(), k8s, namespace, routerName, "vpc-att-1")
		if err != nil {
			t.Fatalf("allocateArgument: unexpected error: %v", err)
		}
		if got != 99 {
			t.Errorf("allocateArgument() = %d, want 99 (reused from existing BGPVRFInstance)", got)
		}
	})

	t.Run("skips values used by this router and ignores other routers", func(t *testing.T) {
		used1 := vrfInstanceForRouter("other-att-1", namespace, routerName, 1)
		used2 := vrfInstanceForRouter("other-att-2", namespace, routerName, 2)
		differentRouter := vrfInstanceForRouter("different-router-att", namespace, "other-router", 1)
		k8s := fakeClient(used1, used2, differentRouter)
		got, err := allocateArgument(context.Background(), k8s, namespace, routerName, "new-att")
		if err != nil {
			t.Fatalf("allocateArgument: unexpected error: %v", err)
		}
		if got != 3 {
			t.Errorf("allocateArgument() = %d, want 3 (lowest free, skipping 1 and 2)", got)
		}
	})

	t.Run("ignores instances in a different namespace", func(t *testing.T) {
		otherNamespace := vrfInstanceForRouter("vpc-att-1", "other-namespace", routerName, 1)
		k8s := fakeClient(otherNamespace)
		got, err := allocateArgument(context.Background(), k8s, namespace, routerName, "vpc-att-1")
		if err != nil {
			t.Fatalf("allocateArgument: unexpected error: %v", err)
		}
		if got != int32(uformat.ArgumentMin) {
			t.Errorf("allocateArgument() = %d, want %d (cross-namespace instance must not be reused or counted as used)",
				got, uformat.ArgumentMin)
		}
	})

	t.Run("exhausted Argument space returns an error", func(t *testing.T) {
		objs := make([]client.Object, 0, uformat.ArgumentMax)
		for i := int32(uformat.ArgumentMin); i <= int32(uformat.ArgumentMax); i++ {
			objs = append(objs, vrfInstanceForRouter(fmt.Sprintf("att-%d", i), namespace, routerName, i))
		}
		k8s := fakeClient(objs...)
		_, err := allocateArgument(context.Background(), k8s, namespace, routerName, "new-att")
		if err == nil {
			t.Fatal("allocateArgument: error = nil, want exhaustion error")
		}
		if !strings.Contains(err.Error(), "no free Argument") {
			t.Errorf("error %q does not contain %q", err, "no free Argument")
		}
	})
}

// ---- checkArgumentCollision -------------------------------------------------

func TestCheckArgumentCollision(t *testing.T) {
	const (
		namespace  = "default"
		routerName = "router-a"
		vrfID      = int32(42)
	)

	t.Run("no collision when no other instance shares the VRFID", func(t *testing.T) {
		other := vrfInstanceForRouter("other-att", namespace, routerName, vrfID+1)
		k8s := fakeClient(other)
		if err := checkArgumentCollision(context.Background(), k8s, namespace, routerName, "this-att", vrfID); err != nil {
			t.Errorf("checkArgumentCollision() = %v, want nil", err)
		}
	})

	t.Run("detects collision when the other name sorts before this one", func(t *testing.T) {
		colliding := vrfInstanceForRouter("aaa-att", namespace, routerName, vrfID)
		k8s := fakeClient(colliding)
		if err := checkArgumentCollision(context.Background(), k8s, namespace, routerName, "zzz-att", vrfID); err == nil {
			t.Error("checkArgumentCollision() = nil, want a collision error")
		}
	})

	t.Run("detects collision when the other name sorts after this one", func(t *testing.T) {
		colliding := vrfInstanceForRouter("zzz-att", namespace, routerName, vrfID)
		k8s := fakeClient(colliding)
		if err := checkArgumentCollision(context.Background(), k8s, namespace, routerName, "aaa-att", vrfID); err == nil {
			t.Error("checkArgumentCollision() = nil, want a collision error")
		}
	})

	t.Run("ignores a same-VRFID instance under a different router", func(t *testing.T) {
		differentRouter := vrfInstanceForRouter("other-router-att", namespace, "other-router", vrfID)
		k8s := fakeClient(differentRouter)
		if err := checkArgumentCollision(context.Background(), k8s, namespace, routerName, "this-att", vrfID); err != nil {
			t.Errorf("checkArgumentCollision() = %v, want nil", err)
		}
	})

	t.Run("ignores this instance's own entry", func(t *testing.T) {
		self := vrfInstanceForRouter("this-att", namespace, routerName, vrfID)
		k8s := fakeClient(self)
		if err := checkArgumentCollision(context.Background(), k8s, namespace, routerName, "this-att", vrfID); err != nil {
			t.Errorf("checkArgumentCollision() = %v, want nil", err)
		}
	})
}

// ---- egressKindForInterfaceType --------------------------------------------

func TestEgressKindForInterfaceType(t *testing.T) {
	tests := []struct {
		name    string
		iface   string
		want    uint32
		wantErr bool
	}{
		{name: "veth maps to EgressKindVeth", iface: ifaceTypeVeth, want: usidmap.EgressKindVeth},
		{name: "tap maps to EgressKindTap", iface: ifaceTypeTap, want: usidmap.EgressKindTap},
		{name: "empty type errors", iface: "", wantErr: true},
		{name: "unknown type errors", iface: "bogus", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := egressKindForInterfaceType(tt.iface)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("egressKindForInterfaceType(%q) error = nil, want error", tt.iface)
				}
				return
			}
			if err != nil {
				t.Fatalf("egressKindForInterfaceType(%q) unexpected error: %v", tt.iface, err)
			}
			if got != tt.want {
				t.Errorf("egressKindForInterfaceType(%q) = %d, want %d", tt.iface, got, tt.want)
			}
		})
	}
}

// ---- buildVRFInstanceSpec ---------------------------------------------------

func TestBuildVRFInstanceSpec(t *testing.T) {
	spec := buildVRFInstanceSpec(testRouterName, testRD65000_1, 1234)

	if spec.RouterRef == nil || spec.RouterRef.Name != testRouterName {
		t.Errorf("RouterRef = %+v, want Name %q", spec.RouterRef, testRouterName)
	}
	if spec.VRFID != 1234 {
		t.Errorf("VRFID = %d, want 1234", spec.VRFID)
	}
	if len(spec.ImportRouteTargets) != 1 || spec.ImportRouteTargets[0].Value != testRD65000_1 {
		t.Errorf("ImportRouteTargets = %+v, want [{%q}]", spec.ImportRouteTargets, testRD65000_1)
	}
	if len(spec.ExportRouteTargets) != 1 || spec.ExportRouteTargets[0].Value != testRD65000_1 {
		t.Errorf("ExportRouteTargets = %+v, want [{%q}]", spec.ExportRouteTargets, testRD65000_1)
	}
}

// ---- ipamAdvertisementPrefixes ----------------------------------------------

func TestIPAMAdvertisementPrefixesNil(t *testing.T) {
	prefixes, ipv6Subnet, ipv4Addr := ipamAdvertisementPrefixes(nil)
	if prefixes != nil {
		t.Errorf("prefixes = %v, want nil", prefixes)
	}
	if ipv6Subnet != "" || ipv4Addr != "" {
		t.Errorf("ipv6Subnet, ipv4Addr = %q, %q, want empty strings", ipv6Subnet, ipv4Addr)
	}
}

func TestIPAMAdvertisementPrefixesIPv4Only(t *testing.T) {
	res := &cniipam.IPAMResult{IPv4Address: net.ParseIP("10.128.0.5")}

	prefixes, ipv6Subnet, ipv4Addr := ipamAdvertisementPrefixes(res)

	if ipv6Subnet != "" {
		t.Errorf("ipv6Subnet = %q, want empty", ipv6Subnet)
	}
	if ipv4Addr != "10.128.0.5" {
		t.Errorf("ipv4Addr = %q, want 10.128.0.5", ipv4Addr)
	}
	if len(prefixes) != 1 || prefixes[0] != "10.128.0.5/32" {
		t.Errorf("prefixes = %v, want exactly [\"10.128.0.5/32\"] (no panic, no empty-prefixes case)", prefixes)
	}
}

func TestIPAMAdvertisementPrefixesDualStack(t *testing.T) {
	ipv6Subnet := mustParseCIDR(t, "fd00:10:ff01::1234/96")
	res := &cniipam.IPAMResult{IPv6Subnet: ipv6Subnet, IPv4Address: net.ParseIP("10.128.0.5")}

	prefixes, gotIPv6Subnet, gotIPv4Addr := ipamAdvertisementPrefixes(res)

	if gotIPv6Subnet != ipv6Subnet.String() {
		t.Errorf("ipv6Subnet = %q, want %q", gotIPv6Subnet, ipv6Subnet.String())
	}
	if gotIPv4Addr != "10.128.0.5" {
		t.Errorf("ipv4Addr = %q, want 10.128.0.5", gotIPv4Addr)
	}
	if len(prefixes) != 2 || prefixes[0] != ipv6Subnet.String() || prefixes[1] != "10.128.0.5/32" {
		t.Errorf("prefixes = %v, want [%q, \"10.128.0.5/32\"]", prefixes, ipv6Subnet.String())
	}
}

// ---- allAdvertisedPrefixes ---------------------------------------------------

func TestAllAdvertisedPrefixesEmpty(t *testing.T) {
	if got := allAdvertisedPrefixes(nil); got != nil {
		t.Errorf("prefixes = %v, want nil", got)
	}
	if got := allAdvertisedPrefixes(map[string]string{}); got != nil {
		t.Errorf("prefixes = %v, want nil", got)
	}
}

func TestAllAdvertisedPrefixesSingleContainer(t *testing.T) {
	const v6, v4 = "fd00:20:ff01::1234/96", "172.20.1.5"
	annotations := map[string]string{
		crdnames.NetNSKey("cid-a"):      testNetns,
		crdnames.SubnetKeyIPv6("cid-a"): v6,
		crdnames.SubnetKeyIPv4("cid-a"): v4,
	}

	got := allAdvertisedPrefixes(annotations)

	want := []string{v4 + "/32", v6}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prefixes = %v, want %v", got, want)
	}
}

// TestAllAdvertisedPrefixesMultipleContainers is the regression test for the
// bug this function fixes: a second container attaching under the same
// (vpc, vpcAttachment) — and thus sharing this BGPAdvertisement CRD — must
// not cause the first, still-live container's prefix to disappear from
// Spec.Prefixes. See allAdvertisedPrefixes's doc comment.
func TestAllAdvertisedPrefixesMultipleContainers(t *testing.T) {
	const aV4, bV6, bV4 = "172.20.1.5", "fd00:20:ff01::1234/96", "172.21.1.2"
	annotations := map[string]string{
		crdnames.NetNSKey("cid-a"):      testNetns,
		crdnames.SubnetKeyIPv4("cid-a"): aV4,
		crdnames.NetNSKey("cid-b"):      testNetns,
		crdnames.SubnetKeyIPv6("cid-b"): bV6,
		crdnames.SubnetKeyIPv4("cid-b"): bV4,
	}

	got := allAdvertisedPrefixes(annotations)

	want := []string{aV4 + "/32", bV4 + "/32", bV6}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prefixes = %v, want %v (a second container's annotations must not drop the first's prefix)", got, want)
	}
}

func TestAllAdvertisedPrefixesIgnoresOtherAnnotations(t *testing.T) {
	const v4 = "172.20.1.5"
	annotations := map[string]string{
		crdnames.NetNSKey("cid-a"):      testNetns,
		crdnames.SubnetKeyIPv4("cid-a"): v4,
		"some.other/annotation":         "should be ignored",
	}

	got := allAdvertisedPrefixes(annotations)

	want := []string{v4 + "/32"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prefixes = %v, want %v", got, want)
	}
}

// ---- buildAdvertisementSpec -------------------------------------------------

func TestBuildAdvertisementSpec(t *testing.T) {
	const podSubnet = "fd00:10:ff01::1234/80"
	spec := buildAdvertisementSpec(testRouterName, testRD65000_1, []string{podSubnet}, 1234)

	if spec.RouterRef.Name != testRouterName {
		t.Errorf("RouterRef.Name = %q, want %q", spec.RouterRef.Name, testRouterName)
	}
	if spec.AddressFamily.AFI != bgpv1alpha1.AFIL2VPN || spec.AddressFamily.SAFI != bgpv1alpha1.SAFIEVPN {
		t.Errorf("AddressFamily = %+v, want L2VPN/EVPN", spec.AddressFamily)
	}
	if len(spec.Prefixes) != 1 || string(spec.Prefixes[0]) != podSubnet {
		t.Errorf("Prefixes = %+v, want [%q]", spec.Prefixes, podSubnet)
	}
	if len(spec.Communities) != 1 || string(spec.Communities[0]) != testRD65000_1 {
		t.Errorf("Communities = %+v, want [%q]", spec.Communities, testRD65000_1)
	}
	if spec.VRFID == nil || *spec.VRFID != 1234 {
		t.Errorf("VRFID = %v, want pointer to 1234", spec.VRFID)
	}
	if spec.Function == nil || *spec.Function != bgpv1alpha1.SRv6FunctionEndDT46 {
		t.Errorf("Function = %v, want pointer to %q", spec.Function, bgpv1alpha1.SRv6FunctionEndDT46)
	}
}

func TestBuildAdvertisementSpecDualStack(t *testing.T) {
	const ipv6Prefix = "fd00:10:ff01::1234/96"
	const ipv4Prefix = "10.128.0.5/32"
	spec := buildAdvertisementSpec(testRouterName, testRD65000_1, []string{ipv6Prefix, ipv4Prefix}, 1234)

	if len(spec.Prefixes) != 2 {
		t.Fatalf("Prefixes = %+v, want 2 entries", spec.Prefixes)
	}
	if string(spec.Prefixes[0]) != ipv6Prefix {
		t.Errorf("Prefixes[0] = %q, want %q", spec.Prefixes[0], ipv6Prefix)
	}
	if string(spec.Prefixes[1]) != ipv4Prefix {
		t.Errorf("Prefixes[1] = %q, want %q", spec.Prefixes[1], ipv4Prefix)
	}
}

// ---- routeTarget ---------------------------------------------------------

func TestRouteTarget(t *testing.T) {
	tests := []struct {
		name     string
		asNumber int64
		vpcHex   string
		want     string
		wantErr  bool
	}{
		{name: "VPC value fits in 32 bits", asNumber: 65000, vpcHex: testVPCHex1234, want: "65000:1234"},
		{name: "upper bits beyond 32 stripped", asNumber: 65000, vpcHex: "000100000001", want: testRD65000_1},
		{name: "low 32 bits all set", asNumber: 65000, vpcHex: "0000ffffffff", want: "65000:4294967295"},
		{name: "different ASN", asNumber: 4200000000, vpcHex: testVPCHex1234, want: "4200000000:1234"},
		{name: "invalid hex string", vpcHex: "zzzzzz", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := routeTarget(tt.asNumber, tt.vpcHex)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("routeTarget(%d, %q) = %q, want %q", tt.asNumber, tt.vpcHex, got, tt.want)
			}
		})
	}
}

// ---- lookupBGPRouter -----------------------------------------------------

func TestLookupBGPRouter(t *testing.T) {
	ctx := context.Background()
	const (
		nodeName  = "node1"
		namespace = "default"
	)

	matchingRouter := routerForNode(testRouterName, nodeName, namespace, 65000)

	tests := []struct {
		name    string
		objects []client.Object
		wantErr string
		check   func(t *testing.T, cfg bgpConfig)
	}{
		{name: "no router for node", objects: nil, wantErr: "no BGPRouter found"},
		{
			name:    "single matching router returns correct config",
			objects: []client.Object{matchingRouter},
			check: func(t *testing.T, cfg bgpConfig) {
				t.Helper()
				if cfg.asNumber != 65000 {
					t.Errorf("asNumber = %d, want 65000", cfg.asNumber)
				}
				if cfg.routerName != testRouterName {
					t.Errorf("routerName = %q, want %q", cfg.routerName, testRouterName)
				}
			},
		},
		{
			name: "router with SRv6Locator and NodeID configured",
			objects: []client.Object{
				func() *bgpv1alpha1.BGPRouter {
					r := routerForNode("srv6-router", nodeName, namespace, 65000)
					r.Spec.SRv6Locator = "fd00:10::/48"
					r.Spec.NodeID = 7
					return r
				}(),
			},
			check: func(t *testing.T, cfg bgpConfig) {
				t.Helper()
				if cfg.srv6Locator != "fd00:10::/48" {
					t.Errorf("srv6Locator = %q, want %q", cfg.srv6Locator, "fd00:10::/48")
				}
				if cfg.nodeID != 7 {
					t.Errorf("nodeID = %d, want 7", cfg.nodeID)
				}
			},
		},
		{
			name:    "router in different namespace is ignored",
			objects: []client.Object{routerForNode("other-ns-router", nodeName, "other-ns", 65001)},
			wantErr: "no BGPRouter found",
		},
		{
			name: "non-matching node router is ignored",
			objects: []client.Object{
				routerForNode("other-node-router", "node2", namespace, 65001),
				matchingRouter,
			},
			check: func(t *testing.T, cfg bgpConfig) {
				t.Helper()
				if cfg.routerName != testRouterName {
					t.Errorf("routerName = %q, want %q", cfg.routerName, testRouterName)
				}
			},
		},
		{
			name: "ambiguous: two routers target same node",
			objects: []client.Object{
				routerForNode("router-a", nodeName, namespace, 65000),
				routerForNode("router-b", nodeName, namespace, 65001),
			},
			wantErr: "ambiguous",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8s := fakeClient(tt.objects...)

			cfg, err := lookupBGPRouter(ctx, k8s, nodeName, namespace)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

// ---- isTransientError ----------------------------------------------------

func TestIsTransientError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantTrans bool
	}{
		{"nil error is not transient", nil, false},
		{"context deadline exceeded is transient", context.DeadlineExceeded, true},
		{"context canceled is transient", context.Canceled, true},
		{"wrapped context deadline exceeded is transient", fmt.Errorf("k8s: %w", context.DeadlineExceeded), true},
		{"wrapped context canceled is transient", fmt.Errorf("k8s: %w", context.Canceled), true},
		{"generic error is not transient", errors.New("some error"), false},
		{"validation error is not transient", apierrors.NewBadRequest("bad request"), false},
		{
			"not found error is not transient",
			apierrors.NewNotFound(schema.GroupResource{Group: "network.datumapis.com", Resource: "bgpadvertisements"}, "test"),
			false,
		},
		{"503 service unavailable is transient", apierrors.NewServiceUnavailable("service unavailable"), true},
		{"429 too many requests is transient", apierrors.NewTooManyRequests("too many requests", 0), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTransientError(tt.err)
			if got != tt.wantTrans {
				t.Errorf("isTransientError(%v) = %v, want %v", tt.err, got, tt.wantTrans)
			}
		})
	}
}

// ---- retryK8sOps ---------------------------------------------------------

func TestRetryK8sOpsSucceedsImmediately(t *testing.T) {
	calls := 0
	err := retryK8sOps(100*time.Millisecond, func(ctx context.Context) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

func TestRetryK8sOpsRetriesOnTransientError(t *testing.T) {
	calls := 0
	err := retryK8sOps(2*time.Second, func(ctx context.Context) error {
		calls++
		if calls < 3 {
			return context.DeadlineExceeded
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 3 {
		t.Errorf("expected 3 calls (initial + 2 retries), got %d", calls)
	}
}

func TestRetryK8sOpsFailsAfterMaxRetries(t *testing.T) {
	calls := 0
	err := retryK8sOps(2*time.Second, func(ctx context.Context) error {
		calls++
		return context.DeadlineExceeded
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if calls != maxRetries+1 {
		t.Errorf("expected %d calls (initial + maxRetries), got %d", maxRetries+1, calls)
	}
}

func TestRetryK8sOpsNoRetryOnNonTransientError(t *testing.T) {
	calls := 0
	permanentErr := errors.New("validation failed")
	err := retryK8sOps(2*time.Second, func(ctx context.Context) error {
		calls++
		return permanentErr
	})
	if !errors.Is(err, permanentErr) {
		t.Fatalf("expected %v, got %v", permanentErr, err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call (no retry), got %d", calls)
	}
}

func TestRetryK8sOpsExhaustsDeadline(t *testing.T) {
	calls := 0
	err := retryK8sOps(1*time.Millisecond, func(ctx context.Context) error {
		calls++
		return apierrors.NewServiceUnavailable("unavailable")
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if calls != maxRetries+1 {
		t.Errorf("expected %d calls, got %d", maxRetries+1, calls)
	}
	if !strings.Contains(err.Error(), "unavailable") {
		t.Errorf("expected 'unavailable' in error, got %v", err)
	}
}
