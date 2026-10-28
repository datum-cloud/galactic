// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package diag_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/attachment"
	"go.datum.net/galactic/internal/edge/diag"
	"go.datum.net/galactic/internal/edge/diag/diagtest"
)

// secret stands in for credential material an object might carry beside
// the fields diagnostics read: annotations, labels and free-form messages.
const secret = "Bearer eyJhbGciOiJSUzI1NiJ9.c2VjcmV0"

const (
	prefixConflict = "PrefixConflict"
	other          = "Other"
	providerLabel  = "edge_provider"
	alpha          = "alpha"
	beta           = "beta"
)

func cond(t string, status metav1.ConditionStatus, reason string) metav1.Condition {
	return metav1.Condition{Type: t, Status: status, Reason: reason, Message: "with " + secret}
}

func TestNoteKeepsCorrelation(t *testing.T) {
	c := diag.Correlation{Provider: "p", Service: "tenant/svc", ServiceUID: "s-uid", ServiceGeneration: 3,
		Attachment: "edge/a", AttachmentUID: "a-uid", PodUID: "pod-uid", Node: "n1", Route: "edge/r",
		Prefix: "fd00::/64", Epoch: 7}
	want := "provider=p service=tenant/svc serviceUID=s-uid serviceGeneration=3 attachment=edge/a " +
		"attachmentUID=a-uid podUID=pod-uid node=n1 route=edge/r prefix=fd00::/64 epoch=7"
	if got := c.String(); got != want {
		t.Fatalf("correlation %q, want %q", got, want)
	}
	note := diag.Note(strings.Repeat("x", 2000), c)
	if len(note) > 1024 {
		t.Fatalf("note is %d bytes, over an Event's 1024", len(note))
	}
	if !strings.HasSuffix(note, " | "+want) {
		t.Fatalf("shortened note lost its correlation: %q", note)
	}
	if got := diag.Note("refused", diag.Correlation{}); got != "refused" {
		t.Fatalf("note without correlation %q", got)
	}
}

func TestReasonLabel(t *testing.T) {
	for in, want := range map[string]string{
		prefixConflict: prefixConflict, "Waiting_For,x:y": "Waiting_For,x:y",
		"has space": other, "": other, secret: other, strings.Repeat("a", 65): other,
	} {
		if got := diag.Reason(in); got != want {
			t.Errorf("Reason(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEnteredFailure(t *testing.T) {
	conds := []metav1.Condition{cond("Admitted", metav1.ConditionFalse, "UnknownProvider")}
	switch {
	case diag.EnteredFailure(conds, "Admitted", "UnknownProvider"):
		t.Error("a retry of the same failure counted as a transition")
	case !diag.EnteredFailure(conds, "Admitted", "ProviderNotApproved"):
		t.Error("a new reason not counted as a transition")
	case !diag.EnteredFailure(conds, "Programmed", "ProvisionFailed"):
		t.Error("a first failure not counted as a transition")
	case !diag.EnteredFailure([]metav1.Condition{cond("Admitted", metav1.ConditionTrue, "Admitted")},
		"Admitted", "GrantRevoked"):
		t.Error("True to False not counted as a transition")
	}
}

func TestRecorderFailureAndGateClosed(t *testing.T) {
	rec, events, reg := diagtest.New("core")
	att := attachmentObj("a", "p", "pod-a")
	rec.Failure(att, diag.StageAdmission, "UnknownProvider", "provider p is not registered", diag.ForAttachment(att))
	rec.GateClosed(att, diag.CauseExpired, "closed", diag.ForAttachment(att))
	rec.CleanupFailed()
	got := events.Events()
	if len(got) != 2 {
		t.Fatalf("events %+v, want 2", got)
	}
	e := got[0]
	if e.Type != "Warning" || e.Action != "Admission" || e.Reason != "UnknownProvider" || e.Name != "a" {
		t.Fatalf("failure event %+v", e)
	}
	corr := e.Correlation()
	for k, v := range map[string]string{"provider": "p", "attachment": "edge/a", "attachmentUID": "uid-a",
		"podUID": "pod-a", "service": "tenant/svc", "serviceUID": "svc-uid", "node": "n1"} {
		if corr[k] != v {
			t.Errorf("correlation %s=%q, want %q (%q)", k, corr[k], v, e.Note)
		}
	}
	if got[1].Action != "Ownership" || got[1].Reason != diag.CauseExpired {
		t.Fatalf("gate event %+v", got[1])
	}
	if err := testutil.GatherAndCompare(reg, openTestdata(t, "recorder.prom")); err != nil {
		t.Fatal(err)
	}
	// A nil Recorder is valid and does nothing.
	var none *diag.Recorder
	none.Failure(att, diag.StageAdmission, "x", "y", diag.Correlation{})
	none.GateClosed(att, diag.CauseExpired, "y", diag.Correlation{})
	none.CleanupFailed()
}

func attachmentObj(name, provider, pod string, conds ...metav1.Condition) *galacticv1alpha1.EdgeAttachment {
	return &galacticv1alpha1.EdgeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "edge", UID: types.UID("uid-" + name),
			Annotations: map[string]string{"token": secret}, Labels: map[string]string{"auth": "s3cr3t"}},
		Spec: galacticv1alpha1.EdgeAttachmentSpec{
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: provider},
			ServiceRef:  galacticv1alpha1.EdgeServiceReference{Namespace: "tenant", Name: "svc", UID: "svc-uid"},
			InstanceRef: galacticv1alpha1.EdgeInstanceReference{Name: "inst-" + name},
			PodUID:      pod, ContractVersion: "v1alpha1",
			Capabilities: []galacticv1alpha1.EdgeCapability{{Name: "SocketAccess", Version: "v1"}},
		},
		Status: galacticv1alpha1.EdgeAttachmentStatus{Conditions: conds, NodeName: "n1"},
	}
}

func TestAttachmentState(t *testing.T) {
	T, F := metav1.ConditionTrue, metav1.ConditionFalse
	const (
		adm, alloc, prog, ready, drain = galacticv1alpha1.EdgeAttachmentAdmitted,
			galacticv1alpha1.EdgeAttachmentAllocated, galacticv1alpha1.EdgeAttachmentProgrammed,
			galacticv1alpha1.EdgeAttachmentReady, galacticv1alpha1.EdgeAttachmentDraining
	)
	deleting := attachmentObj("d", "p", "pod", cond(galacticv1alpha1.EdgeAttachmentReleased, F, "Pending"))
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	for _, tc := range []struct {
		name          string
		att           *galacticv1alpha1.EdgeAttachment
		state, reason string
	}{
		{"new", attachmentObj("a", "p", "pod"), diag.StateAdmission, diag.ReasonPending},
		{"refused", attachmentObj("a", "p", "pod", cond(adm, F, "VPCNotGranted")), diag.StateAdmission, "VPCNotGranted"},
		{"exhausted", attachmentObj("a", "p", "pod", cond(alloc, F, "PoolExhausted")), diag.StateAllocation, "PoolExhausted"},
		{"admitted", attachmentObj("a", "p", "pod", cond(adm, T, "Admitted")), diag.StateAllocation, diag.ReasonPending},
		{"allocated", attachmentObj("a", "p", "pod", cond(adm, T, "A"), cond(alloc, T, "A")),
			diag.StateProgramming, diag.ReasonPending},
		{"unprogrammed", attachmentObj("a", "p", "pod", cond(adm, T, "A"), cond(alloc, T, "A"),
			cond(prog, F, "NamespaceUnavailable")), diag.StateProgramming, "NamespaceUnavailable"},
		{"provider reason ignored", attachmentObj("a", "p", "pod", cond(adm, T, "A"), cond(alloc, T, "A"),
			cond(prog, T, "P"), cond(ready, F, "AnythingTheProviderSays")), diag.StateReady, diag.ReasonNotReady},
		{"active", attachmentObj("a", "p", "pod", cond(adm, T, "A"), cond(alloc, T, "A"), cond(prog, T, "P"),
			cond(ready, T, "R")), diag.StateActive, ""},
		{"draining", attachmentObj("a", "p", "pod", cond(adm, F, "GrantRevoked"), cond(drain, T, "GrantRevoked")),
			diag.StateDraining, "GrantRevoked"},
		{"releasing", deleting, diag.StateReleasing, "Pending"},
	} {
		if state, reason := diag.AttachmentState(tc.att); state != tc.state || reason != tc.reason {
			t.Errorf("%s: state %s/%s, want %s/%s", tc.name, state, reason, tc.state, tc.reason)
		}
	}
}

func routeObj(name, provider, prefix string, claim *galacticv1alpha1.EdgeRouteClaim,
	acc *galacticv1alpha1.EdgeRouteHolder, conds ...metav1.Condition) *galacticv1alpha1.EdgeRoute {
	return &galacticv1alpha1.EdgeRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "edge", Annotations: map[string]string{"token": secret}},
		Spec: galacticv1alpha1.EdgeRouteSpec{ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: provider},
			VPCUID: "vpc", Prefix: prefix, Incarnation: "i", Claim: claim},
		Status: galacticv1alpha1.EdgeRouteStatus{Accepted: acc, Conditions: conds},
	}
}

func TestRouteState(t *testing.T) {
	T, F := metav1.ConditionTrue, metav1.ConditionFalse
	claim := func(epoch int64, released bool) *galacticv1alpha1.EdgeRouteClaim {
		return &galacticv1alpha1.EdgeRouteClaim{Attachment: "a", HolderInstance: "i", Epoch: epoch, Released: released}
	}
	acc := &galacticv1alpha1.EdgeRouteHolder{Epoch: 1, Attachment: "a", AttachmentUID: "uid-a", Node: "n1"}
	for _, tc := range []struct {
		name          string
		rt            *galacticv1alpha1.EdgeRoute
		state, reason string
	}{
		{"unclaimed", routeObj("r", "p", "fd00::/64", nil, nil), diag.RouteUnclaimed, ""},
		{"waiting", routeObj("r", "p", "fd00::/64", claim(1, false), nil,
			cond(galacticv1alpha1.EdgeRouteClaimed, F, "WaitingForFencing")), diag.RoutePending, "WaitingForFencing"},
		{"accepted", routeObj("r", "p", "fd00::/64", claim(1, false), acc,
			cond(galacticv1alpha1.EdgeRouteAccepted, T, "Accepted"),
			cond(galacticv1alpha1.EdgeRoutePublished, F, "AwaitingRouter")), diag.RouteAccepted, "AwaitingRouter"},
		{"published", routeObj("r", "p", "fd00::/64", claim(1, false), acc,
			cond(galacticv1alpha1.EdgeRouteAccepted, T, "Accepted"),
			cond(galacticv1alpha1.EdgeRoutePublished, T, "Published")), diag.RoutePublished, ""},
		{"revoked", routeObj("r", "p", "fd00::/64", claim(1, false), acc,
			cond(galacticv1alpha1.EdgeRouteAccepted, F, "Revoked")), diag.RouteRevoked, "Revoked"},
		{"released", routeObj("r", "p", "fd00::/64", claim(1, true), acc,
			cond(galacticv1alpha1.EdgeRouteAccepted, T, "Accepted")), diag.RouteReleased, ""},
		{"takeover pending", routeObj("r", "p", "fd00::/64", claim(2, false), acc,
			cond(galacticv1alpha1.EdgeRouteAccepted, F, "Revoked"),
			cond(galacticv1alpha1.EdgeRouteClaimed, F, prefixConflict)), diag.RoutePending, prefixConflict},
	} {
		if state, reason := diag.RouteState(tc.rt); state != tc.state || reason != tc.reason {
			t.Errorf("%s: state %s/%s, want %s/%s", tc.name, state, reason, tc.state, tc.reason)
		}
	}
}

// TestStateCollectorBoundsCardinality exports many attachments and routes,
// each with its own name, UID, pod and prefix, and checks that the series
// count follows the providers, states and reasons, not the objects; that a
// provider not approved shares the "unknown" series; and that no label value
// carries an object's identity or anything a credential could be in.
func TestStateCollectorBoundsCardinality(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := galacticv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	const n = 400
	objs := make([]client.Object, 0, 3+2*n+1)
	for _, p := range []struct {
		name     string
		approved bool
	}{{alpha, true}, {beta, true}, {"rogue", false}} {
		objs = append(objs, &galacticv1alpha1.EdgeProvider{ObjectMeta: metav1.ObjectMeta{Name: p.name},
			Status: galacticv1alpha1.EdgeProviderStatus{Approved: p.approved}})
	}
	T, F := metav1.ConditionTrue, metav1.ConditionFalse
	shapes := [][]metav1.Condition{
		nil,
		{cond(galacticv1alpha1.EdgeAttachmentAdmitted, F, "VPCNotGranted")},
		{cond(galacticv1alpha1.EdgeAttachmentAdmitted, T, "A"), cond(galacticv1alpha1.EdgeAttachmentAllocated, T, "A"),
			cond(galacticv1alpha1.EdgeAttachmentProgrammed, F, "ProvisionFailed")},
		{cond(galacticv1alpha1.EdgeAttachmentAdmitted, T, "A"), cond(galacticv1alpha1.EdgeAttachmentAllocated, T, "A"),
			cond(galacticv1alpha1.EdgeAttachmentProgrammed, T, "P"), cond(galacticv1alpha1.EdgeAttachmentReady, T, "R")},
	}
	providers := []string{alpha, beta, "rogue", "never-registered"}
	identities := make([]string, 0, 4*n)
	for i := range n {
		name, pod := fmt.Sprintf("att-%d", i), fmt.Sprintf("pod-%d", i)
		prefix := fmt.Sprintf("fd00:%x::/64", i)
		p := providers[i%len(providers)]
		objs = append(objs, attachmentObj(name, p, pod, shapes[(i/len(providers))%len(shapes)]...),
			routeObj(fmt.Sprintf("route-%d", i), p, prefix, nil, nil))
		identities = append(identities, name, "uid-"+name, pod, prefix)
	}
	objs = append(objs, &galacticv1alpha1.EdgeService{
		ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "tenant", Annotations: map[string]string{"t": secret}},
		Spec:       galacticv1alpha1.EdgeServiceSpec{ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: alpha}},
		Status: galacticv1alpha1.EdgeServiceStatus{Conditions: []metav1.Condition{
			cond(diag.ServiceTrafficPolicy, F, "PolicyNotFound")}},
	})
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	reg := prometheus.NewRegistry()
	reg.MustRegister(&diag.StateCollector{Reader: reader})
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	series := map[string][]*dto.Metric{}
	for _, f := range families {
		series[f.GetName()] = f.GetMetric()
	}
	// Three provider label values (alpha, beta, unknown) times four
	// attachment shapes, however many attachments.
	if got := len(series["galactic_edge_foundation_attachments"]); got != 12 {
		t.Errorf("%d attachment series for %d attachments, want 12", got, n)
	}
	if got := len(series["galactic_edge_foundation_routes"]); got != 3 {
		t.Errorf("%d route series for %d routes, want 3", got, n)
	}
	var total float64
	for _, m := range series["galactic_edge_foundation_attachments"] {
		total += m.GetGauge().GetValue()
	}
	if total != n {
		t.Errorf("attachment series sum to %v, want %d", total, n)
	}
	if v := series["galactic_edge_foundation_state_collect_errors"]; len(v) != 1 || v[0].GetGauge().GetValue() != 0 {
		t.Errorf("collect errors %v", v)
	}
	allowed := map[string]bool{alpha: true, beta: true, "unknown": true}
	for name, ms := range series {
		for _, m := range ms {
			for _, l := range m.GetLabel() {
				v := l.GetValue()
				if l.GetName() == providerLabel && !allowed[v] {
					t.Errorf("%s provider label %q is not an approved provider or unknown", name, v)
				}
				for _, id := range append(identities, secret, "s3cr3t") {
					if strings.Contains(v, id) {
						t.Errorf("%s label %s=%q carries %q", name, l.GetName(), v, id)
					}
				}
			}
		}
	}
	unresolved := map[string]string{providerLabel: alpha, "policy": "Unresolved", "reason": "PolicyNotFound"}
	if !hasSeries(series["galactic_edge_foundation_services"], unresolved) {
		t.Errorf("unresolved service policy not exported: %v", series["galactic_edge_foundation_services"])
	}
}

func hasSeries(ms []*dto.Metric, want map[string]string) bool {
	for _, m := range ms {
		got := map[string]string{}
		for _, l := range m.GetLabel() {
			got[l.GetName()] = l.GetValue()
		}
		match := true
		for k, v := range want {
			match = match && got[k] == v
		}
		if match {
			return true
		}
	}
	return false
}

// TestCorrelationExcludesCredentials: an Event's correlation is built only
// from the identifying fields it names, so credential material an object
// carries in its annotations or labels never reaches a note.
func TestCorrelationExcludesCredentials(t *testing.T) {
	att := attachmentObj("a", "p", "pod-a")
	rt := routeObj("r", "p", "fd00::/64", &galacticv1alpha1.EdgeRouteClaim{Epoch: 2}, nil)
	for _, c := range []diag.Correlation{diag.ForAttachment(att), diag.ForRoute(rt)} {
		note := diag.Note("refused", c)
		if strings.Contains(note, secret) || strings.Contains(note, "s3cr3t") {
			t.Fatalf("note %q carries credential material", note)
		}
	}
	if got := diag.ForRoute(rt).Epoch; got != 2 {
		t.Fatalf("unaccepted route's correlation epoch %d, want its claim's 2", got)
	}
}

// TestServiceConditionName pins diag's copy of the EdgeService policy
// condition type to the one core writes.
func TestServiceConditionName(t *testing.T) {
	if diag.ServiceTrafficPolicy != attachment.ConditionServiceTrafficPolicy {
		t.Fatalf("diag reads %q, core writes %q", diag.ServiceTrafficPolicy, attachment.ConditionServiceTrafficPolicy)
	}
}

// openTestdata opens testdata/name, closed with the test.
func openTestdata(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}
