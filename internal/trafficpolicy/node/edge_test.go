// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
)

const (
	providerNS   = "edge-provider"
	edgeProvider = "connect"
	edgeSvc      = "connect-vpc"
	edgeAtt      = "att-edge"
)

func edgeServiceFor() *galacticv1alpha1.EdgeService {
	return &galacticv1alpha1.EdgeService{
		ObjectMeta: metav1.ObjectMeta{Name: edgeSvc, Namespace: testNS},
		Spec: galacticv1alpha1.EdgeServiceSpec{
			ProviderRef:  galacticv1alpha1.EdgeProviderReference{Name: edgeProvider},
			VPCRef:       galacticv1alpha1.EdgeVPCReference{Name: testVPC, UID: "8d4a7c4e-1f0e-4f35-9d3c-6a3c1e2f0a11"},
			Capabilities: []string{"SocketAccess"},
		},
	}
}

func edgeAttachmentFor(svc *galacticv1alpha1.EdgeService, provider string) *galacticv1alpha1.EdgeAttachment {
	return &galacticv1alpha1.EdgeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: edgeAtt, Namespace: providerNS},
		Spec: galacticv1alpha1.EdgeAttachmentSpec{
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: provider},
			ServiceRef: galacticv1alpha1.EdgeServiceReference{
				Namespace: svc.Namespace, Name: svc.Name, UID: string(svc.UID),
			},
			InstanceRef:     galacticv1alpha1.EdgeInstanceReference{Name: "inst"},
			PodUID:          "0c0f5a52-58a8-4b4e-9d43-0e0c0f5a5258",
			ContractVersion: "v1alpha1",
			Capabilities:    []galacticv1alpha1.EdgeCapability{{Name: "SocketAccess", Version: "v1"}},
		},
	}
}

func admitted() []metav1.Condition {
	return []metav1.Condition{{
		Type: galacticv1alpha1.EdgeAttachmentAdmitted, Status: metav1.ConditionTrue, Reason: "Admitted",
		LastTransitionTime: metav1.Now(),
	}}
}

// TestEdgeService checks which service, if any, an edge attachment's link
// takes its policy from.
func TestEdgeService(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(galacticv1alpha1.AddToScheme(scheme))
	svc := edgeServiceFor()
	svc.UID = "svc-uid"
	deleting := edgeServiceFor()
	deleting.Name, deleting.UID = "deleting", "deleting-uid"
	deleting.Finalizers = []string{"test"}
	deleting.DeletionTimestamp = ptr.To(metav1.Now())
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(svc, deleting).Build()
	r := &Reconciler{Client: c}

	for _, tc := range []struct {
		name    string
		mutate  func(*galacticv1alpha1.EdgeAttachment)
		refused string
	}{
		{name: "admitted", mutate: func(*galacticv1alpha1.EdgeAttachment) {}},
		{name: "not admitted", refused: "not admitted", mutate: func(a *galacticv1alpha1.EdgeAttachment) {
			a.Status.Conditions = nil
		}},
		{name: "missing service", refused: "does not exist", mutate: func(a *galacticv1alpha1.EdgeAttachment) {
			a.Spec.ServiceRef.Name = "gone"
		}},
		{name: "replaced service", refused: "was replaced", mutate: func(a *galacticv1alpha1.EdgeAttachment) {
			a.Spec.ServiceRef.UID = "older-uid"
		}},
		{name: "service being deleted", refused: "being deleted", mutate: func(a *galacticv1alpha1.EdgeAttachment) {
			a.Spec.ServiceRef.Name, a.Spec.ServiceRef.UID = deleting.Name, string(deleting.UID)
		}},
		{name: "another provider", refused: "another provider", mutate: func(a *galacticv1alpha1.EdgeAttachment) {
			a.Spec.ProviderRef.Name = "other"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			att := edgeAttachmentFor(svc, edgeProvider)
			att.Status.Conditions = admitted()
			tc.mutate(att)
			got, refused, err := r.edgeService(context.Background(), att)
			if err != nil {
				t.Fatal(err)
			}
			if tc.refused == "" {
				if got == nil || refused != "" {
					t.Fatalf("edgeService = %v, %q; want the service", got, refused)
				}
				return
			}
			if got != nil || !strings.Contains(refused, tc.refused) {
				t.Fatalf("edgeService = %v, %q; want no service because %q", got, refused, tc.refused)
			}
		})
	}
}

// TestEdgeReconciler runs the EdgeAttachment controller in a manager against
// a real API server and the real datapath maps: its link takes the policy
// its EdgeService names, resolved in the service's namespace, and follows
// every change to the service and the policy without a resync.
func TestEdgeReconciler(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// The fixture's VPCAttachment names the same link; only the edge
	// attachment may hold it here.
	if err := f.c.Delete(ctx, &cloudv1alpha1.VPCAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: testAtt, Namespace: testNS},
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: providerNS}}); err != nil {
		t.Fatal(err)
	}
	web := f.applyPolicy(t, webPolicy, "["+httpRule+"]")
	// A policy in the provider's own namespace, under the name the service
	// references for ingress, that would admit everything.
	open := &galacticv1alpha1.TrafficPolicy{ObjectMeta: metav1.ObjectMeta{Name: "open", Namespace: providerNS}}
	open.Spec.Rules = []galacticv1alpha1.TrafficRule{{Name: "all", Action: galacticv1alpha1.ActionAllow}}
	if err := f.c.Create(ctx, open); err != nil {
		t.Fatal(err)
	}
	svc := edgeServiceFor()
	if err := f.c.Create(ctx, svc); err != nil {
		t.Fatal(err)
	}
	att := edgeAttachmentFor(svc, edgeProvider)
	if err := f.c.Create(ctx, att); err != nil {
		t.Fatal(err)
	}
	att.Status = galacticv1alpha1.EdgeAttachmentStatus{
		NodeName: testNode, VPC: "vpcA", Address: "fd00:10::7", HostLink: f.link, Conditions: admitted(),
	}
	if err := f.c.Status().Update(ctx, att); err != nil {
		t.Fatal(err)
	}

	r := f.reconciler()
	f.run(t, r)
	builtin := PolicyUIDBytes(galacticv1alpha1.DefaultPolicyUID)

	t.Run("NoPolicyDeniesBothDirections", func(t *testing.T) {
		for _, dir := range []uint32{tpmap.DirIngress, tpmap.DirEgress} {
			f.eventually(t, "the built-in default", func() bool {
				snap, ok := f.snapshot(t, dir)
				return ok && snap.Token == f.token && snap.PolicyUID == builtin
			})
		}
	})

	t.Run("ServiceSelectsPolicy", func(t *testing.T) {
		f.setEdgePolicy(t, svc, &galacticv1alpha1.TrafficPolicyBindingSpec{
			EgressPolicyRef: &galacticv1alpha1.LocalPolicyReference{Name: webPolicy},
		})
		f.eventually(t, "egress on web", func() bool {
			snap, ok := f.snapshot(t, tpmap.DirEgress)
			return ok && uuid.UUID(snap.PolicyUID).String() == string(web.UID) && snap.Generation == web.Generation
		})
		if snap, ok := f.snapshot(t, tpmap.DirIngress); !ok || snap.PolicyUID != builtin {
			t.Fatalf("ingress = %+v, %v; want the built-in default", snap, ok)
		}
	})

	t.Run("PolicyResolvesOnlyInServiceNamespace", func(t *testing.T) {
		f.setEdgePolicy(t, svc, &galacticv1alpha1.TrafficPolicyBindingSpec{
			IngressPolicyRef: &galacticv1alpha1.LocalPolicyReference{Name: "open"},
			EgressPolicyRef:  &galacticv1alpha1.LocalPolicyReference{Name: webPolicy},
		})
		f.eventually(t, "ingress unbound", func() bool {
			_, ok := f.snapshot(t, tpmap.DirIngress)
			return !ok
		})
		f.consistently(t, "ingress stays unbound", func() bool {
			_, ok := f.snapshot(t, tpmap.DirIngress)
			return !ok
		})
	})

	t.Run("PolicyUpdateReachesActiveAttachment", func(t *testing.T) {
		web = f.applyPolicy(t, webPolicy, "["+dnsRule+","+httpRule+"]")
		f.eventually(t, "egress on web's new generation", func() bool {
			snap, ok := f.snapshot(t, tpmap.DirEgress)
			return ok && snap.Generation == web.Generation
		})
	})

	t.Run("Metrics", func(t *testing.T) {
		reg := prometheus.NewPedanticRegistry()
		reg.MustRegister(r)
		families, err := reg.Gather()
		if err != nil {
			t.Fatal(err)
		}
		if !hasSeries(families, "galactic_cni_traffic_policy_rule_hits_total", map[string]string{
			interfaceLabelNames[0]: providerNS, interfaceLabelNames[1]: testVPC, labelAttachment: edgeAtt,
			interfaceLabelNames[3]: f.link, labelDirection: directionNames[tpmap.DirEgress], "policy": webPolicy,
		}) {
			t.Error("no rule hit series for the edge attachment's web policy")
		}
	})

	t.Run("ReplacedServiceDeniesEverything", func(t *testing.T) {
		if err := f.c.Delete(ctx, svc); err != nil {
			t.Fatal(err)
		}
		f.eventually(t, "both directions unbound after the service was deleted", f.unbound)
		again := edgeServiceFor()
		again.Spec.TrafficPolicy = &galacticv1alpha1.TrafficPolicyBindingSpec{
			IngressPolicyRef: &galacticv1alpha1.LocalPolicyReference{Name: webPolicy},
			EgressPolicyRef:  &galacticv1alpha1.LocalPolicyReference{Name: webPolicy},
		}
		if err := f.c.Create(ctx, again); err != nil {
			t.Fatal(err)
		}
		f.consistently(t, "a recreated service grants the old attachment nothing", f.unbound)
	})

	t.Run("AttachmentLeavesNode", func(t *testing.T) {
		var cur galacticv1alpha1.EdgeAttachment
		if err := f.c.Get(ctx, client.ObjectKeyFromObject(att), &cur); err != nil {
			t.Fatal(err)
		}
		cur.Status.NodeName = "node-c"
		if err := f.c.Status().Update(ctx, &cur); err != nil {
			t.Fatal(err)
		}
		f.eventually(t, "the attachment forgotten", func() bool {
			r.mu.Lock()
			defer r.mu.Unlock()
			_, ok := r.ifaces[subject{edge: true, NamespacedName: client.ObjectKeyFromObject(att)}]
			return !ok
		})
	})
}

// run starts r's controllers in a manager on f's API server.
func (f *fixture) run(t *testing.T, r *Reconciler) {
	t.Helper()
	scheme := runtime.NewScheme()
	utilruntime.Must(galacticv1alpha1.AddToScheme(scheme))
	utilruntime.Must(cloudv1alpha1.AddToScheme(scheme))
	mgr, err := ctrl.NewManager(f.cfg, ctrl.Options{
		Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"},
		Controller: config.Controller{SkipNameValidation: ptr.To(true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	r.Client = mgr.GetClient()
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("manager: %v", err)
		}
	})
}

func (f *fixture) setEdgePolicy(t *testing.T, svc *galacticv1alpha1.EdgeService,
	spec *galacticv1alpha1.TrafficPolicyBindingSpec,
) {
	t.Helper()
	ctx := context.Background()
	var cur galacticv1alpha1.EdgeService
	if err := f.c.Get(ctx, client.ObjectKeyFromObject(svc), &cur); err != nil {
		t.Fatal(err)
	}
	cur.Spec.TrafficPolicy = spec
	if err := f.c.Update(ctx, &cur); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) unbound() bool {
	for _, dir := range []uint32{tpmap.DirIngress, tpmap.DirEgress} {
		if _, ok, err := f.maps.ReadSnapshot(f.ifindex, dir); err != nil || ok {
			return false
		}
	}
	return true
}

// edgeWait bounds how long the controllers take to follow a change.
const edgeWait = 10 * time.Second

func (f *fixture) eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(edgeWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// consistently fails if cond stops holding within a second, long enough
// for the controllers to have acted on the change before it.
func (f *fixture) consistently(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if !cond() {
			t.Fatalf("%s: no longer holds", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
