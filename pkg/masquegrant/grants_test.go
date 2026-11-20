package masquegrant

import (
	"reflect"
	"testing"
)

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
	for _, name := range []string{"Endpoint", "NetworkUID", "BindingUID", "NetworkRef", "BindingRef"} {
		if _, found := requestType.FieldByName(name); found {
			t.Fatalf("facade exposes unresolvable identity %s", name)
		}
	}
	if selector := (VPCRef{Namespace: "tenant", Name: "vpc"}).Selector(); selector != "tenant/vpc" {
		t.Fatal(selector)
	}
}
