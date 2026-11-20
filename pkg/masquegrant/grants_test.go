package masquegrant

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

func TestConfiguredServicesShareAPIWithoutSharingGrants(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := cloudv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := galacticv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	vpc := &cloudv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "vpc", UID: "vpc-incarnation"},
		Spec: cloudv1alpha1.VPCSpec{Networks: []cloudv1alpha1.Network{"fd20:a1b:2c3d::/48"}}}
	cellClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpc).Build()
	ref := VPCRef{Namespace: vpc.Namespace, Name: vpc.Name}
	ledgers := NewLedgers(cellClient, "masque-system")
	for index, cell := range []string{"first", "second"} {
		connectors := []string{"fd20:a1b:2c3d:10:1::/80", "fd20:a1b:2c3d:10:3::/80"}[index]
		pools := []string{"fd20:a1b:2c3d:10:2::/80", "fd20:a1b:2c3d:10:4::/80"}[index]
		if err := ledgers.Init(t.Context(), ref, cell,
			netip.MustParsePrefix(connectors), netip.MustParsePrefix(pools)); err != nil {
			t.Fatal(err)
		}
	}
	first, second := New(cellClient, "masque-system", "first"), New(cellClient, "masque-system", "second")
	issued, err := first.Create(t.Context(), CreateRequest{VPC: ref, Lifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for _, foreign := range []Grants{second, New(cellClient, "masque-system", "")} {
		if _, err := foreign.Rotate(t.Context(), issued.Connector, time.Hour); err == nil {
			t.Fatal("foreign service rotated grant")
		}
		if err := foreign.Disable(t.Context(), issued.Connector); err == nil {
			t.Fatal("foreign service disabled grant")
		}
		if err := foreign.Retire(t.Context(), issued.Connector); err == nil {
			t.Fatal("foreign service retired grant")
		}
	}
	if _, err := second.Create(t.Context(), CreateRequest{VPC: ref, Lifetime: time.Hour}); err != nil {
		t.Fatal(err)
	}
	rotated, err := first.Rotate(t.Context(), issued.Connector, time.Hour)
	if err != nil || rotated.Revision != 2 || rotated.Prefix != issued.Prefix {
		t.Fatalf("owner grant changed by foreign service: %+v %v", rotated, err)
	}
}

func TestNamedFacade(t *testing.T) {
	for _, reference := range []any{VPCRef{}, EndpointRef{}} {
		referenceType := reflect.TypeOf(reference)
		if referenceType.NumField() != 2 {
			t.Fatalf("%s must expose only namespace and name", referenceType)
		}
		for _, name := range []string{"Namespace", "Name"} {
			field, found := referenceType.FieldByName(name)
			if !found || field.Type.Kind() != reflect.String {
				t.Fatalf("%s missing string %s", referenceType, name)
			}
		}
	}
	requestType := reflect.TypeOf(CreateRequest{})
	for _, name := range []string{"Cell", "Endpoint", "NetworkUID", "BindingUID", "NetworkRef", "BindingRef"} {
		if _, found := requestType.FieldByName(name); found {
			t.Fatalf("facade exposes unresolvable identity %s", name)
		}
	}
	if selector := (VPCRef{Namespace: "tenant", Name: "vpc"}).Selector(); selector != "tenant/vpc" {
		t.Fatal(selector)
	}
}
