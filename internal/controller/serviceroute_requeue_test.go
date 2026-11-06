// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

const (
	requeueNS    = "tenant"
	requeueGuest = "guest"
	requeueAPI   = "api"
	requeueDNSA  = "rq-dns-a"
	requeueDNSB  = "rq-dns-b"
	requeueVPCA  = "rq-vpc-a"
	requeueVPCB  = "rq-vpc-b"
	requeueRole  = "role"
	requeueApp   = "app"
)

func requeuePolicy(name, endpoint string, selector map[string]string,
	vpc *networkv1alpha1.ServiceRouteVPCReference,
) *networkv1alpha1.ServiceRoutePolicy {
	return &networkv1alpha1.ServiceRoutePolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: requeueNS, Name: name},
		Spec: networkv1alpha1.ServiceRoutePolicySpec{
			ServiceRef:         networkv1alpha1.ServiceEndpointReference{Name: endpoint},
			AttachmentSelector: metav1.LabelSelector{MatchLabels: selector},
			ConsumerVPCRef:     vpc,
		},
	}
}

func requeueEndpoint(name string, selector map[string]string,
	ref *networkv1alpha1.ServiceEndpointAttachmentReference,
) *networkv1alpha1.ServiceEndpoint {
	e := &networkv1alpha1.ServiceEndpoint{ObjectMeta: metav1.ObjectMeta{Namespace: requeueNS, Name: name}}
	if ref != nil {
		e.Spec.AttachmentRef = ref
	} else {
		e.Spec.AttachmentSelector = &metav1.LabelSelector{MatchLabels: selector}
	}
	return e
}

func requeueAttachment(name, vpc string, l map[string]string) *cloudv1alpha1.VPCAttachment {
	a := &cloudv1alpha1.VPCAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: requeueNS, Name: name, Labels: l}}
	a.Spec.VPC.Name = vpc
	return a
}

func newRequeueReconciler(t *testing.T, objs ...client.Object) *ServiceRoutePolicyReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	utilruntime.Must(networkv1alpha1.AddToScheme(scheme))
	utilruntime.Must(cloudv1alpha1.AddToScheme(scheme))
	return &ServiceRoutePolicyReconciler{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build(),
	}
}

func requestNames(reqs []ctrl.Request) []string {
	names := make([]string, 0, len(reqs))
	for _, r := range reqs {
		names = append(names, r.Name)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// requeueObjects is a small cell: a DNS policy whose consumers are every
// guest in vpc-a, served by a selector endpoint; a policy for vpc-b only; and
// a policy whose endpoint names its one producer.
func requeueObjects() []client.Object {
	return []client.Object{
		requeuePolicy(requeueDNSA, "dns", map[string]string{requeueRole: requeueGuest},
			&networkv1alpha1.ServiceRouteVPCReference{Name: requeueVPCA, UID: "a"}),
		requeuePolicy(requeueDNSB, "dns", map[string]string{requeueRole: requeueGuest},
			&networkv1alpha1.ServiceRouteVPCReference{Name: requeueVPCB, UID: "b"}),
		requeuePolicy("db", "db", map[string]string{requeueApp: requeueAPI}, nil),
		requeueEndpoint("dns", map[string]string{requeueRole: "dns-member"}, nil),
		requeueEndpoint("db", nil, &networkv1alpha1.ServiceEndpointAttachmentReference{
			Namespace: requeueNS, Name: "db-0",
		}),
	}
}

func TestAttachmentPoliciesRequeuesOnlyPoliciesThatSelectIt(t *testing.T) {
	r := newRequeueReconciler(t, requeueObjects()...)
	ctx := context.Background()
	for _, tc := range []struct {
		name       string
		attachment *cloudv1alpha1.VPCAttachment
		want       []string
	}{
		{"guest in vpc-a", requeueAttachment("guest-1", requeueVPCA,
			map[string]string{requeueRole: requeueGuest}), []string{requeueDNSA}},
		{"guest in vpc-b", requeueAttachment("guest-2", requeueVPCB,
			map[string]string{requeueRole: requeueGuest}), []string{requeueDNSB}},
		{"DNS member, a producer for both", requeueAttachment("member-0", "infra",
			map[string]string{requeueRole: "dns-member"}), []string{requeueDNSA, requeueDNSB}},
		{"producer named by attachmentRef", requeueAttachment("db-0", "infra", nil), []string{"db"}},
		{"consumer of the policy without a VPC reference", requeueAttachment("api-0", "vpc-c",
			map[string]string{requeueApp: requeueAPI}), []string{"db"}},
		{"unrelated attachment", requeueAttachment("other", requeueVPCA, map[string]string{requeueRole: "batch"}), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := requestNames(r.attachmentPolicies(ctx, tc.attachment))
			if !slices.Equal(got, tc.want) {
				t.Fatalf("requeued %v, want %v", got, tc.want)
			}
		})
	}
}

// An update requeues the policy the attachment left as well as the one it
// joined, so the old policy withdraws its route.
func TestAttachmentEventRequeuesOldAndNewSelectors(t *testing.T) {
	r := newRequeueReconciler(t, requeueObjects()...)
	old := requeueAttachment("guest-1", requeueVPCA, map[string]string{requeueRole: requeueGuest})
	moved := requeueAttachment("guest-1", requeueVPCA, map[string]string{requeueApp: requeueAPI})
	q := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer q.ShutDown()

	r.attachmentEventPolicies().Update(context.Background(), event.UpdateEvent{ObjectOld: old, ObjectNew: moved}, q)

	var got []string
	for q.Len() > 0 {
		req, _ := q.Get()
		got = append(got, req.Name)
		q.Done(req)
	}
	slices.Sort(got)
	if want := []string{"db", requeueDNSA}; !slices.Equal(got, want) {
		t.Fatalf("requeued %v, want %v", got, want)
	}
}

// A policy whose endpoint is missing, or whose selector does not parse, is
// requeued for any attachment event so its reconcile can report it.
func TestAttachmentPoliciesKeepsPoliciesItCannotJudge(t *testing.T) {
	broken := requeuePolicy("broken", "dns", nil, nil)
	broken.Spec.AttachmentSelector = metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key: "role", Operator: "NotAnOperator",
	}}}
	orphan := requeuePolicy("orphan", "missing", map[string]string{requeueRole: requeueGuest}, nil)
	r := newRequeueReconciler(t, append(requeueObjects(), broken, orphan)...)

	got := requestNames(r.attachmentPolicies(context.Background(),
		requeueAttachment("other", requeueVPCA, map[string]string{requeueRole: "batch"})))
	if want := []string{"broken", "orphan"}; !slices.Equal(got, want) {
		t.Fatalf("requeued %v, want %v", got, want)
	}
}

func TestEndpointAndReportEventsRequeueTheirPolicies(t *testing.T) {
	r := newRequeueReconciler(t, requeueObjects()...)
	ctx := context.Background()
	db := requeueEndpoint("db", nil,
		&networkv1alpha1.ServiceEndpointAttachmentReference{Namespace: requeueNS, Name: "db-0"})
	if got, want := requestNames(r.endpointPolicies(ctx, db)), []string{"db"}; !slices.Equal(got, want) {
		t.Fatalf("endpoint db requeued %v, want %v", got, want)
	}
	report := &networkv1alpha1.ServiceEndpointProducerReport{
		ObjectMeta: metav1.ObjectMeta{Namespace: requeueNS, Name: "dns-node-a"},
		Spec:       networkv1alpha1.ServiceEndpointProducerReportSpec{EndpointName: "dns", Node: "rq-node"},
	}
	got, want := requestNames(r.endpointPolicies(ctx, report)), []string{requeueDNSA, requeueDNSB}
	if !slices.Equal(got, want) {
		t.Fatalf("report for dns requeued %v, want %v", got, want)
	}
	other := &networkv1alpha1.ServiceEndpoint{ObjectMeta: metav1.ObjectMeta{Namespace: "rq-other-ns", Name: "dns"}}
	if got := r.endpointPolicies(ctx, other); len(got) != 0 {
		t.Fatalf("an endpoint in another namespace requeued %v", requestNames(got))
	}
}

func TestVPCEventRequeuesPoliciesThatReferenceIt(t *testing.T) {
	r := newRequeueReconciler(t, requeueObjects()...)
	vpc := &cloudv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: requeueNS, Name: requeueVPCB}}
	got, want := requestNames(r.vpcPolicies(context.Background(), vpc)), []string{requeueDNSB}
	if !slices.Equal(got, want) {
		t.Fatalf("requeued %v, want %v", got, want)
	}
}
