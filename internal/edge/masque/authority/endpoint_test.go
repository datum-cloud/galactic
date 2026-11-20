package authority

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/connectip"
	"go.datum.net/galactic/internal/edge/masque/endpoints"
)

func scopedEndpoint() *galacticv1alpha1.MASQUEEndpoint {
	return &galacticv1alpha1.MASQUEEndpoint{ObjectMeta: metav1.ObjectMeta{Name: "endpoint", Namespace: testNS},
		Spec: galacticv1alpha1.MASQUEEndpointSpec{Cell: testCell, Hostname: "gateway.example.com",
			Provider: testProvider,
			Metro:    "metro", Revision: 1, Enabled: true,
			CertificateRef: galacticv1alpha1.MASQUEEndpointCertificateReference{
				Name: "tls", Revision: strings.Repeat("a", 64)}}}
}

func TestEndpointGrantIsolationAndReactivation(t *testing.T) {
	ledger, ref := fakeLedgers(t)
	grants := Grants(ledger)
	endpoint := scopedEndpoint()
	ctx := context.Background()
	if err := grants.Client.Create(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	fence := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name: endpoints.FenceName(endpoint.Spec.Hostname), Namespace: testNS}}
	writeFence := func(revoked int64) {
		t.Helper()
		encoded, err := json.Marshal(endpoints.Fence{Name: endpoint.Name, ObjectUID: string(endpoint.UID),
			Spec: endpoint.Spec, RevokedRevision: revoked})
		if err != nil {
			t.Fatal(err)
		}
		fence.Data = map[string]string{"fence.json": string(encoded)}
		if fence.ResourceVersion == "" {
			err = grants.Client.Create(ctx, fence)
		} else {
			err = grants.Client.Update(ctx, fence)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	writeFence(0)
	issued, err := grants.Create(ctx, CreateRequest{VPC: ref, Cell: testCell,

		Lifetime:    time.Hour,
		EndpointRef: &galacticv1alpha1.MASQUEEndpointReference{Namespace: endpoint.Namespace, Name: endpoint.Name}})
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := readRecord(ctx, grants.Client, testNS, issued.Connector)
	if err != nil {
		t.Fatal(err)
	}
	authority := &Authority{Client: grants.Client, Namespace: testNS, Provider: testProvider, Cell: testCell}
	if err := authority.endpoint(ctx, record); err != nil {
		t.Fatal(err)
	}
	const otherIdentity = "other"
	for _, mutate := range []func(*galacticv1alpha1.MASQUEEndpointReference){
		func(scope *galacticv1alpha1.MASQUEEndpointReference) { scope.Name = otherIdentity },
		func(scope *galacticv1alpha1.MASQUEEndpointReference) { scope.Namespace = otherIdentity },
	} {
		copied := *record
		scope := *record.EndpointRef
		mutate(&scope)
		copied.EndpointRef = &scope
		if !errors.Is(authority.endpoint(ctx, &copied), connectip.ErrForbidden) {
			t.Fatal("scope substitution allowed")
		}
		if sameEndpoint(record.EndpointRef, &scope) {
			t.Fatal("request scope substitution allowed")
		}
	}
	if sameEndpoint(record.EndpointRef, nil) || sameEndpoint(nil, record.EndpointRef) {
		t.Fatal("legacy/managed replay allowed")
	}
	endpoint.Spec.Revision = 2
	endpoint.Spec.Enabled = false
	if err := grants.Client.Update(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	writeFence(2)
	if !errors.Is(authority.endpoint(ctx, record), connectip.ErrForbidden) {
		t.Fatal("disabled endpoint allowed")
	}
	if _, err := grants.Rotate(ctx, issued.Connector, time.Hour); err == nil {
		t.Fatal("disabled endpoint allowed credential rotation")
	}
	endpoint.Spec.Revision = 3
	endpoint.Spec.Enabled = true
	if err := grants.Client.Update(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	writeFence(2)
	if !errors.Is(authority.endpoint(ctx, record), connectip.ErrForbidden) {
		t.Fatal("reactivation resurrected revoked credential")
	}
	if _, err := grants.Rotate(ctx, issued.Connector, time.Hour); err == nil {
		t.Fatal("rotation resurrected revoked endpoint grant")
	}
	if err := grants.Retire(ctx, issued.Connector); err != nil {
		t.Fatal(err)
	}
	if len(grants.entries(t)) != 1 {
		t.Fatal("retire discarded allocation tombstone")
	}
}
