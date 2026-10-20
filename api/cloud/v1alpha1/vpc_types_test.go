package v1alpha1

import (
	"encoding/json"
	"testing"
)

func TestVPCStatusOmitsIdentifierUntilAllocated(t *testing.T) {
	status := VPCStatus{ObservedGeneration: 1}
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if _, present := fields["vpc"]; present {
		t.Fatalf("unallocated VPC status included vpc: %s", data)
	}

	status.VPC = "2lkCCM"
	data, err = json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["vpc"] != "2lkCCM" {
		t.Fatalf("allocated VPC status omitted identifier: %s", data)
	}
}
