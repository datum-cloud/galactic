// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachment

import (
	"context"
	"fmt"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/admission"
	edgeprovider "go.datum.net/galactic/internal/edge/provider"
)

// nodeNameExtra is the user-info extra key carrying a bound token's Node.
const nodeNameExtra = "authentication.kubernetes.io/node-name"

// as is a client for user whose token carries extra. It is also in
// system:masters, so only the Galactic Edge policies can refuse it.
func (f *fixture) as(user string, extra map[string][]string) client.Client {
	f.t.Helper()
	cfg := rest.CopyConfig(f.cfg)
	cfg.Impersonate = rest.ImpersonationConfig{
		UserName: user, Groups: []string{"system:masters", authenticated}, Extra: extra,
	}
	c, err := client.New(cfg, client.Options{Scheme: f.scheme})
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

func (f *fixture) providerPod(podUID, node string) client.Client {
	return f.as("system:serviceaccount:"+providerNS+":"+providerSA, map[string][]string{
		admission.PodUIDExtra: {podUID},
		nodeNameExtra:         {node},
	})
}

func (f *fixture) nodeAgent(node string) client.Client {
	return f.as("system:serviceaccount:galactic-system:galactic-edge", map[string][]string{
		nodeNameExtra: {node},
	})
}

// waitPolicyBound waits until the provider's policy binding refuses c's
// attachment for pod, which belongs to another pod, as the API server
// starts enforcing a new binding a moment after it is created.
func (f *fixture) waitPolicyBound(c client.Client, svc *galacticv1alpha1.EdgeService, pod *corev1.Pod) {
	f.t.Helper()
	n := 0
	eventually(f.t, "provider policy binding enforced", func() bool {
		n++
		a := attachmentFor(fmt.Sprintf("probe-%d", n), svc, pod)
		if err := c.Create(context.Background(), a); err != nil {
			return true
		}
		_ = f.admin.Delete(context.Background(), a)
		return false
	})
}

// TestPolicies checks that a provider pod writes only its own instance,
// attachments and Ready condition, and galactic-edge only its own node's
// conditions and device names.
func TestPolicies(t *testing.T) {
	f := startAPI(t)
	f.startBindings()
	ctx := context.Background()
	svc := f.service("svc-a", poolA, 30)
	p1, p2 := f.pod("p1"), f.pod("p2")
	pod1 := f.providerPod(string(p1.UID), edgeNode)
	pod2 := f.providerPod(string(p2.UID), edgeNode)
	f.waitPolicyBound(pod1, svc, p2)

	stranger := f.as("system:serviceaccount:"+providerNS+":stranger", map[string][]string{
		admission.PodUIDExtra: {string(p1.UID)},
		nodeNameExtra:         {edgeNode},
	})
	if err := stranger.Create(ctx, attachmentFor("stranger", svc, p1)); err == nil {
		t.Error("a ServiceAccount the provider does not list created its attachment")
	}
	unbound := attachmentFor("unbound", svc, p1)
	unbound.Spec.ProviderRef.Name = "not-registered"
	if err := pod1.Create(ctx, unbound); err == nil {
		t.Error("a provider's pod created an object naming another provider")
	}
	if err := pod1.Create(ctx, attachmentFor("own", svc, p1)); err != nil {
		t.Fatalf("a pod could not create its own attachment: %v", err)
	}
	elsewhere := &galacticv1alpha1.EdgeInstance{
		ObjectMeta: metav1.ObjectMeta{Name: edgeprovider.InstanceName(string(p1.UID)), Namespace: providerNS},
		Spec: galacticv1alpha1.EdgeInstanceSpec{
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: providerSA},
			PodName:     "p1", PodUID: string(p1.UID), NodeName: "edge-2", BootID: "boot",
		},
	}
	if err := pod1.Create(ctx, elsewhere); err == nil {
		t.Error("a pod created an instance for another node")
	}

	// Core's view: admitted and allocated on edgeNode.
	a := f.get("own")
	a.Status.NodeName, a.Status.VPC, a.Status.Address = edgeNode, vpcID, "fd00:10:0:e::1"
	meta.SetStatusCondition(&a.Status.Conditions, metav1.Condition{
		Type: galacticv1alpha1.EdgeAttachmentAdmitted, Status: metav1.ConditionTrue, Reason: ReasonAdmitted,
	})
	if err := f.admin.Status().Update(ctx, a); err != nil {
		t.Fatal(err)
	}

	type write struct {
		name   string
		c      client.Client
		mutate func(*galacticv1alpha1.EdgeAttachment)
		allow  bool
	}
	condition := func(typ string) func(*galacticv1alpha1.EdgeAttachment) {
		return func(a *galacticv1alpha1.EdgeAttachment) {
			meta.SetStatusCondition(&a.Status.Conditions, metav1.Condition{
				Type: typ, Status: metav1.ConditionTrue, Reason: "Test",
			})
		}
	}
	if err := pod2.Delete(ctx, f.get("own")); err == nil {
		t.Fatal("a pod deleted another pod's attachment")
	}
	for _, w := range []write{
		{"provider sets Ready", pod1, condition(galacticv1alpha1.EdgeAttachmentReady), true},
		{"provider sets Admitted", pod1, func(a *galacticv1alpha1.EdgeAttachment) {
			meta.SetStatusCondition(&a.Status.Conditions, metav1.Condition{
				Type: galacticv1alpha1.EdgeAttachmentAdmitted, Status: metav1.ConditionFalse, Reason: "Test",
			})
		}, false},
		{"provider sets Programmed", pod1, condition(galacticv1alpha1.EdgeAttachmentProgrammed), false},
		{"provider changes address", pod1, func(a *galacticv1alpha1.EdgeAttachment) {
			a.Status.Address = "fd00:10:0:e::9"
		}, false},
		{"provider names a device", pod1, func(a *galacticv1alpha1.EdgeAttachment) { a.Status.HostLink = "x" }, false},
		{"another pod sets Ready", pod2, condition(galacticv1alpha1.EdgeAttachmentReady), false},
		{"node sets Programmed", f.nodeAgent(edgeNode), func(a *galacticv1alpha1.EdgeAttachment) {
			condition(galacticv1alpha1.EdgeAttachmentProgrammed)(a)
			a.Status.HostLink, a.Status.PodVRF = "Eabc", "gvabc"
		}, true},
		{"node sets Released", f.nodeAgent(edgeNode), condition(galacticv1alpha1.EdgeAttachmentReleased), true},
		{"node clears Ready", f.nodeAgent(edgeNode), func(a *galacticv1alpha1.EdgeAttachment) {
			meta.SetStatusCondition(&a.Status.Conditions, metav1.Condition{
				Type: galacticv1alpha1.EdgeAttachmentReady, Status: metav1.ConditionFalse, Reason: "Node",
			})
		}, false},
		{"node changes address", f.nodeAgent(edgeNode), func(a *galacticv1alpha1.EdgeAttachment) {
			a.Status.Address = "fd00:10:0:e::9"
		}, false},
		{"another node sets Programmed", f.nodeAgent("edge-2"), func(a *galacticv1alpha1.EdgeAttachment) {
			meta.SetStatusCondition(&a.Status.Conditions, metav1.Condition{
				Type: galacticv1alpha1.EdgeAttachmentProgrammed, Status: metav1.ConditionFalse, Reason: "Other",
			})
		}, false},
	} {
		t.Run(w.name, func(t *testing.T) {
			a := f.get("own")
			w.mutate(a)
			err := w.c.Status().Update(ctx, a)
			if w.allow && err != nil {
				t.Errorf("refused: %v", err)
			}
			if !w.allow && err == nil {
				t.Error("allowed")
			}
		})
	}
	if err := pod1.Delete(ctx, f.get("own")); err != nil {
		t.Errorf("a pod could not delete its own attachment: %v", err)
	}
	// Kubernetes' own controllers delete a provider's objects when their
	// namespace goes.
	f.create(attachmentFor("namespace-teardown", svc, p2))
	nsController := f.as("system:serviceaccount:kube-system:namespace-controller", nil)
	if err := nsController.Delete(ctx, f.get("namespace-teardown")); err != nil {
		t.Errorf("the namespace controller could not delete a provider's attachment: %v", err)
	}
}

// TestProviderBindings checks the RBAC and policy bindings core keeps per
// provider, with no group that bypasses RBAC: an approved provider's listed
// ServiceAccount writes its own objects, an unlisted one cannot, and
// withdrawing approval removes the access.
func TestProviderBindings(t *testing.T) {
	f := startAPI(t)
	f.startBindings()
	ctx := context.Background()
	svc := f.service("svc-a", poolA, 30)
	p1 := f.pod("p1")
	asSA := func(name string) client.Client {
		cfg := rest.CopyConfig(f.cfg)
		cfg.Impersonate = rest.ImpersonationConfig{
			UserName: "system:serviceaccount:" + providerNS + ":" + name,
			Groups:   []string{"system:serviceaccounts", "system:serviceaccounts:" + providerNS, authenticated},
			Extra: map[string][]string{
				admission.PodUIDExtra: {string(p1.UID)},
				nodeNameExtra:         {edgeNode},
			},
		}
		c, err := client.New(cfg, client.Options{Scheme: f.scheme})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	provider, other := asSA(providerSA), asSA("stranger")
	f.waitPolicyBound(f.providerPod(string(p1.UID), edgeNode), svc, f.pod("p2"))

	var rb rbacv1.RoleBinding
	if err := f.admin.Get(ctx, client.ObjectKey{Namespace: providerNS, Name: bindingName(providerSA)}, &rb); err != nil {
		t.Fatalf("no RoleBinding for the approved provider: %v", err)
	}
	if len(rb.Subjects) != 1 || rb.Subjects[0].Name != providerSA || rb.RoleRef.Name != ProviderClusterRole {
		t.Errorf("RoleBinding %+v", rb)
	}
	n := 0
	created := func(c client.Client) bool {
		n++
		return c.Create(ctx, attachmentFor(fmt.Sprintf("a-%d", n), svc, p1)) == nil
	}
	eventually(t, "provider writes its own attachment", func() bool { return created(provider) })
	if created(other) {
		t.Error("an unlisted ServiceAccount wrote an attachment")
	}

	var p galacticv1alpha1.EdgeProvider
	if err := f.admin.Get(ctx, client.ObjectKey{Name: providerSA}, &p); err != nil {
		t.Fatal(err)
	}
	p.Status.Approved = false
	if err := f.admin.Status().Update(ctx, &p); err != nil {
		t.Fatal(err)
	}
	eventually(t, "bindings removed", func() bool {
		var vapb admissionregistrationv1.ValidatingAdmissionPolicyBinding
		err1 := f.admin.Get(ctx, client.ObjectKey{Name: bindingName(providerSA)}, &vapb)
		err2 := f.admin.Get(ctx, client.ObjectKeyFromObject(&rb), &rbacv1.RoleBinding{})
		return apierrors.IsNotFound(err1) && apierrors.IsNotFound(err2)
	})
	eventually(t, "unapproved provider refused", func() bool { return !created(provider) })

	// galactic-controller binds only the provider role, even with RBAC out
	// of the way.
	controller := f.as("system:serviceaccount:galactic-system:galactic-controller", nil)
	escalate := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "escalate", Namespace: providerNS},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: providerNS, Name: providerSA}},
	}
	if err := controller.Create(ctx, escalate); err == nil {
		t.Error("galactic-controller bound another role")
	}

	// Deleting an approved provider withdraws its bindings before it goes.
	if err := f.admin.Get(ctx, client.ObjectKey{Name: providerSA}, &p); err != nil {
		t.Fatal(err)
	}
	p.Status.Approved = true
	if err := f.admin.Status().Update(ctx, &p); err != nil {
		t.Fatal(err)
	}
	eventually(t, "bindings restored", func() bool {
		return f.admin.Get(ctx, client.ObjectKeyFromObject(&rb), &rbacv1.RoleBinding{}) == nil
	})
	if err := f.admin.Delete(ctx, &p); err != nil {
		t.Fatal(err)
	}
	eventually(t, "provider and its bindings gone", func() bool {
		var vapb admissionregistrationv1.ValidatingAdmissionPolicyBinding
		err1 := f.admin.Get(ctx, client.ObjectKey{Name: bindingName(providerSA)}, &vapb)
		err2 := f.admin.Get(ctx, client.ObjectKeyFromObject(&rb), &rbacv1.RoleBinding{})
		err3 := f.admin.Get(ctx, client.ObjectKey{Name: providerSA}, &galacticv1alpha1.EdgeProvider{})
		return apierrors.IsNotFound(err1) && apierrors.IsNotFound(err2) && apierrors.IsNotFound(err3)
	})
}
