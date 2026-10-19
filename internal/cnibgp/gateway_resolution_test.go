// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"context"
	"net/netip"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/controller"
	"go.datum.net/galactic/internal/gateway"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// recordingEngine is a controller.GatewayEngine that records the state the
// reconciler hands it.
type recordingEngine struct{ desired gateway.EngineState }

func (e *recordingEngine) Reconcile(_ context.Context, desired gateway.EngineState) (gateway.EngineStatus, error) {
	e.desired = desired
	status := gateway.EngineStatus{Healthy: true}
	for key := range desired.Rules {
		status.Rules = append(status.Rules, gateway.RuleStatus{Key: key, Applied: true})
	}
	return status, nil
}

func (*recordingEngine) DatapathGeneration() uint64 { return 0 }

func (*recordingEngine) ReconcileOrphans(context.Context, gateway.EngineState, uint64) error {
	return nil
}

func (*recordingEngine) Stop(context.Context) error { return nil }

// TestGatewayResolvesBackendPublishedByCNI pins the contract between the CNI
// and the gateway: the VPC identity in the CNI conflist and the
// VPCAttachment's status.vpc (which a NetworkService's spec.vpcRef is matched
// against) must be the same string. The BGPVRFInstance and BGPAdvertisement
// come from the CNI's real publish path, and the gateway's reconciler resolves
// a backend against those same objects. If the name the CNI writes for the
// tenant's BGPVRFInstance and the name the gateway derives for the same VPC
// drift apart, the tenant ownership check rejects the advertisement and the
// backend never reaches the engine.
func TestGatewayResolvesBackendPublishedByCNI(t *testing.T) {
	withoutDatapath(t)
	const (
		// A mixed-case base62 identity, so an encoding or case change on
		// either side changes the derived name.
		vpcID       = "7Qa"
		cniNode     = "compute-node-1"
		gatewayNode = "gw-a"
		namespace   = "tenant-ns"
		backendAddr = "fd00:40:ff01::100:5"
		backendPort = 8443
	)
	withNetNSExistsFn(t, func(path string) bool { return path == testNetns })

	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(bgpv1alpha1.AddToScheme(s))
	utilruntime.Must(cloudv1alpha1.AddToScheme(s))

	router := routerForNode(testRouterName, cniNode, namespace, 65000)
	gw := &bgpv1alpha1.NetworkGateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: gatewayNode},
		Spec: bgpv1alpha1.NetworkGatewaySpec{
			TargetRef: bgpv1alpha1.TargetRef{Kind: "Node", Name: gatewayNode},
		},
	}
	rule := &bgpv1alpha1.NetworkService{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "svc"},
		Spec: bgpv1alpha1.NetworkServiceSpec{
			VPCRef:          vpcID,
			VIPAddresses:    []string{"2001:db8:5::5"},
			Protocol:        bgpv1alpha1.NetworkServiceProtocolTCP,
			Port:            443,
			BackendSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "backend"}},
			BackendPort:     backendPort,
		},
	}
	meta.SetStatusCondition(&rule.Status.Conditions, metav1.Condition{
		Type: bgpv1alpha1.ConditionTypeAccepted, Status: metav1.ConditionTrue, Reason: "Registered",
	})
	attachment := &cloudv1alpha1.VPCAttachment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace, Name: testAttachment, Labels: map[string]string{"app": "backend"},
		},
		Spec: cloudv1alpha1.VPCAttachmentSpec{
			VPC: cloudv1alpha1.VPCRef{Name: vpcID},
			Interface: cloudv1alpha1.VPCAttachmentInterface{
				Name:      "eth0",
				Mode:      cloudv1alpha1.VPCAttachmentInterfaceModeNetns,
				Addresses: []cloudv1alpha1.IPAddress{backendAddr + "/96"},
			},
		},
		Status: cloudv1alpha1.VPCAttachmentStatus{VPC: vpcID, Node: cniNode},
	}

	k8s := fake.NewClientBuilder().WithScheme(s).
		WithIndex(&bgpv1alpha1.BGPRouter{}, controller.BGPRouterByTargetName, func(obj client.Object) []string {
			return []string{obj.(*bgpv1alpha1.BGPRouter).Spec.TargetRef.Name}
		}).
		WithStatusSubresource(&bgpv1alpha1.NetworkGateway{}, &bgpv1alpha1.NetworkService{}).
		WithObjects(router, gw, rule, attachment).Build()

	// The CNI publishes the tenant's BGP state, from the conflist's VPC.
	ipamResult := &cniipam.IPAMResult{IPv6Subnet: mustParseCIDR(t, "fd00:40:ff01::100:0/96")}
	cfg := publishConfig{vpc: vpcID, vpcAttachment: testAttachment, ifaceType: ifaceTypeVeth}
	args := &skel.CmdArgs{ContainerID: testContainerID, Netns: testNetns}
	if _, err := publishBGPState(args, cfg, cniNode, namespace, ipamResult, testVPCHex1234, k8s); err != nil {
		t.Fatalf("publishBGPState: %v", err)
	}

	// The router gets its SRv6 identity only now: with one at publish time the
	// CNI would also program the kernel datapath, which a unit test cannot.
	// The VRFID and the BGP objects published above do not depend on it.
	router.Spec.SRv6Locator = "2001:db8:ff01::/48"
	router.Spec.NodeID = 7
	if err := k8s.Update(context.Background(), router); err != nil {
		t.Fatalf("update BGPRouter: %v", err)
	}

	// The gateway resolves the backend against exactly those objects.
	engine := &recordingEngine{}
	r := &controller.NetworkGatewayReconciler{
		Client: k8s, APIReader: k8s, Scheme: s, Engine: engine, NodeName: gatewayNode,
	}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	dr, ok := engine.desired.Rules[namespace+"/svc"]
	if !ok {
		t.Fatal("rule not in desired state: the backend did not resolve against the BGP state the CNI published")
	}
	if len(dr.Backends) != 1 || dr.Backends[0].Address != netip.MustParseAddr(backendAddr) {
		t.Fatalf("desired backends = %+v, want only %s", dr.Backends, backendAddr)
	}

	vrf := publishedVRFInstance(t, k8s, namespace)
	fields, err := uformat.Decode(dr.Backends[0].USID)
	if err != nil {
		t.Fatalf("decode backend uSID %s: %v", dr.Backends[0].USID, err)
	}
	if int32(fields.Argument) != vrf.Spec.VRFID {
		t.Errorf("backend uSID VRFID = %d, want the tenant's published VRFID %d", fields.Argument, vrf.Spec.VRFID)
	}
}

// publishedVRFInstance returns the only BGPVRFInstance in namespace, which is
// the one the CNI published.
func publishedVRFInstance(t *testing.T, k8s client.Client, namespace string) *bgpv1alpha1.BGPVRFInstance {
	t.Helper()
	list := &bgpv1alpha1.BGPVRFInstanceList{}
	if err := k8s.List(context.Background(), list, client.InNamespace(namespace)); err != nil {
		t.Fatalf("list BGPVRFInstances: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("BGPVRFInstances = %d, want 1", len(list.Items))
	}
	return &list.Items[0]
}
