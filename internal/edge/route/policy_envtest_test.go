// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package route

import (
	"context"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/admission"
)

const nodeNameExtra = "authentication.kubernetes.io/node-name"

// as is a client for user whose token carries extra, holding only the
// permissions RBAC grants it.
func (f *fixture) as(user string, extra map[string][]string) client.Client {
	f.t.Helper()
	cfg := rest.CopyConfig(f.cfg)
	cfg.Impersonate = rest.ImpersonationConfig{
		UserName: user, Extra: extra,
		Groups: []string{"system:serviceaccounts", "system:authenticated"},
	}
	c, err := client.New(cfg, client.Options{Scheme: f.scheme})
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

func (f *fixture) providerPod(h *podHolder) client.Client {
	return f.as("system:serviceaccount:"+providerNS+":"+provider, map[string][]string{
		admission.PodUIDExtra: {string(h.pod.UID)},
		nodeNameExtra:         {h.pod.Spec.NodeName},
	})
}

func (f *fixture) nodeAgent(node string) client.Client {
	return f.as("system:serviceaccount:galactic-system:galactic-edge", map[string][]string{nodeNameExtra: {node}})
}

// bindProvider binds the provider policy and role as galactic-controller
// does for an approved provider, and waits until the binding is enforced.
func (f *fixture) bindProvider(probe *podHolder) {
	f.t.Helper()
	deny := admissionregistrationv1.DenyAction
	f.create(&admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "galactic-edge-provider-test"},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName:        "galactic-edge-provider",
			ParamRef:          &admissionregistrationv1.ParamRef{Name: provider, ParameterNotFoundAction: &deny},
			ValidationActions: []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny},
		},
	})
	f.create(&rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "galactic-edge-provider-test", Namespace: providerNS},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "galactic-edge-provider"},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: providerNS, Name: provider}},
	})
	c := f.providerPod(probe)
	deadline := time.Now().Add(20 * time.Second)
	for n := 0; ; n++ {
		rt := routeObject("probe", "fd00:10:0:f:ff::/80", string(f.vpc.UID))
		rt.Name += string(rune('a' + n%26))
		rt.Spec.Claim = &galacticv1alpha1.EdgeRouteClaim{Attachment: "x", HolderPodUID: "someone-else",
			HolderInstance: "x", InstanceEpoch: 1, Epoch: 1}
		if err := c.Create(context.Background(), rt); err != nil {
			return
		}
		_ = f.admin.Delete(context.Background(), rt)
		if time.Now().After(deadline) {
			f.t.Fatal("provider policy binding not enforced")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func routeObject(name, prefix, vpcUID string) *galacticv1alpha1.EdgeRoute {
	return &galacticv1alpha1.EdgeRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: providerNS},
		Spec: galacticv1alpha1.EdgeRouteSpec{ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: provider},
			VPCUID: vpcUID, Prefix: prefix, Incarnation: "inc-" + name},
	}
}

// TestRoutePolicies checks what each identity may write: a provider pod its
// own lease and its own claims, taking another pod's claim only with a new
// epoch and never releasing or deleting it; galactic-edge only the
// closedEpoch of routes accepted on its own node, never lowered or past the
// accepted epoch.
func TestRoutePolicies(t *testing.T) {
	f := startAPI(t)
	ctx := context.Background()
	a, b := f.newHolder("a", nodeA, "fd00:10:0:e::1"), f.newHolder("b", nodeB, "fd00:10:0:e::2")
	f.bindProvider(a)
	podA, podB := f.providerPod(a), f.providerPod(b)
	claimOf := func(h *podHolder, epoch int64) *galacticv1alpha1.EdgeRouteClaim {
		return &galacticv1alpha1.EdgeRouteClaim{Attachment: h.att.Name, HolderPodUID: string(h.pod.UID),
			HolderInstance: h.inst.Name, InstanceEpoch: 1, Epoch: epoch}
	}
	expect := func(what string, ok bool, err error) {
		t.Helper()
		if ok && err != nil {
			t.Errorf("%s refused: %v", what, err)
		}
		if !ok && err == nil {
			t.Errorf("%s allowed", what)
		}
	}

	// Leases.
	var inst galacticv1alpha1.EdgeInstance
	get := func(c client.Client, obj client.Object) {
		t.Helper()
		if err := c.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
			t.Fatal(err)
		}
	}
	inst = *a.inst
	get(podA, &inst)
	inst.Status.Lease.Sequence++
	expect("a pod renewing its own lease", true, podA.Status().Update(ctx, &inst))
	get(podB, &inst)
	inst.Status.Lease.Sequence++
	expect("a pod writing another pod's lease", false, podB.Status().Update(ctx, &inst))

	// Claims.
	foreign := routeObject("foreign", prefixA, string(f.vpc.UID))
	foreign.Spec.Claim = claimOf(b, 1)
	expect("a pod creating a route claimed for another pod", false, podA.Create(ctx, foreign))
	rt := routeObject("r", prefixA, string(f.vpc.UID))
	rt.Spec.Claim = claimOf(a, 1)
	expect("a pod creating a route claimed for itself", true, podA.Create(ctx, rt))

	get(podB, rt)
	rt.Spec.Claim.Released = true
	expect("a pod releasing another pod's claim", false, podB.Update(ctx, rt))
	get(podB, rt)
	expect("a pod deleting another pod's claimed route", false, podB.Delete(ctx, rt))
	get(podB, rt)
	rt.Spec.Claim = claimOf(b, 2)
	rt.Spec.Claim.Released = true
	expect("a pod taking a claim over already released", false, podB.Update(ctx, rt))
	get(podB, rt)
	rt.Spec.Claim = claimOf(b, 2)
	expect("a pod taking another pod's claim over at the next epoch", true, podB.Update(ctx, rt))
	get(podA, rt)
	rt.Spec.Claim = claimOf(a, 2)
	expect("the former holder rewriting the claim at the taker's epoch", false, podA.Update(ctx, rt))

	// Route status: core accepts, the node records closing.
	get(podB, rt)
	rt.Status.ClosedEpoch = 1
	expect("a provider writing route status", false, podB.Status().Update(ctx, rt))
	get(f.admin, rt)
	rt.Status.Accepted = &galacticv1alpha1.EdgeRouteHolder{Epoch: 2, Attachment: b.att.Name,
		AttachmentUID: string(b.att.UID), Instance: b.inst.Name, InstanceIncarnation: b.incarnation, InstanceEpoch: 1,
		Node: nodeB, VPCNamespace: tenantNS}
	if err := f.admin.Status().Update(ctx, rt); err != nil {
		t.Fatal(err)
	}
	// galactic-edge patches, with the route's resourceVersion as precondition.
	patch := func(c client.Client, mutate func(*galacticv1alpha1.EdgeRoute)) error {
		get(c, rt)
		before := rt.DeepCopy()
		mutate(rt)
		return c.Status().Patch(ctx, rt, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{}))
	}
	closeAt := func(c client.Client, epoch int64) error {
		return patch(c, func(r *galacticv1alpha1.EdgeRoute) { r.Status.ClosedEpoch = epoch })
	}
	expect("galactic-edge on another node recording closed", false, closeAt(f.nodeAgent(nodeA), 2))
	expect("galactic-edge recording past the accepted epoch", false, closeAt(f.nodeAgent(nodeB), 3))
	expect("galactic-edge recording its own node's route closed", true, closeAt(f.nodeAgent(nodeB), 2))
	expect("galactic-edge lowering closedEpoch", false, closeAt(f.nodeAgent(nodeB), 1))
	moveHolder := func(r *galacticv1alpha1.EdgeRoute) { r.Status.Accepted.Epoch = 1 }
	expect("galactic-edge changing the accepted holder", false, patch(f.nodeAgent(nodeB), moveHolder))
}
