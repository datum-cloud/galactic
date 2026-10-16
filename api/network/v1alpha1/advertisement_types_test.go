package v1alpha1

import (
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ptr[T any](v T) *T { return &v }

func newTestAdvertisement() *BGPAdvertisement {
	return &BGPAdvertisement{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "galactic.datumapis.com/v1alpha1",
			Kind:       "BGPAdvertisement",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "test-adv"},
		Spec: BGPAdvertisementSpec{
			RouterRef:     RouterRef{Name: "test-router"},
			AddressFamily: AddressFamily{AFI: AFIIPv6, SAFI: SAFIUnicast},
			Prefixes:      []Prefix{"2001:db8::/48"},
		},
	}
}

// TestBGPAdvertisementDeepCopy verifies DeepCopy produces an independent copy.
func TestBGPAdvertisementDeepCopy(t *testing.T) {
	orig := newTestAdvertisement()
	orig.Spec.Communities = []Community{"65000:100"}
	orig.Spec.LocalPreference = ptr(int32(200))

	dup := orig.DeepCopy()

	dup.Spec.RouterRef.Name = "other-router"
	dup.Spec.Communities[0] = "65001:999"
	*dup.Spec.LocalPreference = 999

	if orig.Spec.RouterRef.Name != "test-router" {
		t.Errorf("RouterRef mutated: got %q", orig.Spec.RouterRef.Name)
	}
	if orig.Spec.Communities[0] != "65000:100" {
		t.Errorf("Communities[0] mutated: got %q", orig.Spec.Communities[0])
	}
	if *orig.Spec.LocalPreference != 200 {
		t.Errorf("LocalPreference mutated: got %d", *orig.Spec.LocalPreference)
	}
}

// TestBGPAdvertisementDeepCopyNil verifies DeepCopy on nil returns nil.
func TestBGPAdvertisementDeepCopyNil(t *testing.T) {
	var a *BGPAdvertisement
	if a.DeepCopy() != nil {
		t.Error("DeepCopy on nil should return nil")
	}
}

// TestBGPAdvertisementJSONRoundTrip verifies JSON serialisation round-trips correctly.
func TestBGPAdvertisementJSONRoundTrip(t *testing.T) {
	orig := newTestAdvertisement()
	orig.Spec.Prefixes = []Prefix{"2001:db8::/48", "10.0.0.0/8"}
	orig.Spec.Communities = []Community{"65000:100"}
	orig.Spec.LocalPreference = ptr(int32(100))

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPAdvertisement
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Spec.RouterRef.Name != orig.Spec.RouterRef.Name {
		t.Errorf("RouterRef: got %q, want %q", got.Spec.RouterRef.Name, orig.Spec.RouterRef.Name)
	}
	if len(got.Spec.Prefixes) != 2 {
		t.Fatalf("Prefixes len: got %d, want 2", len(got.Spec.Prefixes))
	}
	if got.Spec.Prefixes[0] != "2001:db8::/48" {
		t.Errorf("Prefixes[0]: got %q, want 2001:db8::/48", got.Spec.Prefixes[0])
	}
	if got.Spec.Prefixes[1] != "10.0.0.0/8" {
		t.Errorf("Prefixes[1]: got %q, want 10.0.0.0/8", got.Spec.Prefixes[1])
	}
	if got.Spec.Communities[0] != "65000:100" {
		t.Errorf("Communities[0]: got %q, want 65000:100", got.Spec.Communities[0])
	}
	if got.Spec.LocalPreference == nil || *got.Spec.LocalPreference != 100 {
		t.Errorf("LocalPreference: got %v, want 100", got.Spec.LocalPreference)
	}
}

// TestBGPAdvertisementRedistributeJSONRoundTrip verifies redistribution sources
// serialise and deserialise correctly.
func TestBGPAdvertisementRedistributeJSONRoundTrip(t *testing.T) {
	orig := &BGPAdvertisement{
		TypeMeta:   metav1.TypeMeta{APIVersion: "galactic.datumapis.com/v1alpha1", Kind: "BGPAdvertisement"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-redistribute"},
		Spec: BGPAdvertisementSpec{
			RouterRef:     RouterRef{Name: "test-router"},
			AddressFamily: AddressFamily{AFI: AFIIPv4, SAFI: SAFIUnicast},
			Redistribute: []RedistributeSource{
				RedistributeSourceStatic,
				RedistributeSourceConnected,
			},
		},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPAdvertisement
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(got.Spec.Redistribute) != 2 {
		t.Fatalf("Redistribute len: got %d, want 2", len(got.Spec.Redistribute))
	}
	if got.Spec.Redistribute[0] != RedistributeSourceStatic {
		t.Errorf("Redistribute[0]: got %q, want %q", got.Spec.Redistribute[0], RedistributeSourceStatic)
	}
	if got.Spec.Redistribute[1] != RedistributeSourceConnected {
		t.Errorf("Redistribute[1]: got %q, want %q", got.Spec.Redistribute[1], RedistributeSourceConnected)
	}
}

// TestBGPAdvertisementOriginateFromJSONRoundTrip verifies originateFrom serialises correctly.
func TestBGPAdvertisementOriginateFromJSONRoundTrip(t *testing.T) {
	orig := &BGPAdvertisement{
		TypeMeta:   metav1.TypeMeta{APIVersion: "galactic.datumapis.com/v1alpha1", Kind: "BGPAdvertisement"},
		ObjectMeta: metav1.ObjectMeta{Name: "test-originate"},
		Spec: BGPAdvertisementSpec{
			RouterRef:     RouterRef{Name: "test-router"},
			AddressFamily: AddressFamily{AFI: AFIIPv6, SAFI: SAFIUnicast},
			OriginateFrom: &AdvertisementOriginateFrom{
				Type:          OriginateTypeInterface,
				InterfaceName: ptr("lo"),
			},
		},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPAdvertisement
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Spec.OriginateFrom == nil {
		t.Fatal("OriginateFrom is nil after round-trip")
	}
	if got.Spec.OriginateFrom.Type != OriginateTypeInterface {
		t.Errorf("OriginateFrom.Type: got %q, want %q", got.Spec.OriginateFrom.Type, OriginateTypeInterface)
	}
	if got.Spec.OriginateFrom.InterfaceName == nil || *got.Spec.OriginateFrom.InterfaceName != "lo" {
		t.Errorf("OriginateFrom.InterfaceName: got %v, want lo", got.Spec.OriginateFrom.InterfaceName)
	}
}

// TestBGPAdvertisementPolicyRefJSONRoundTrip verifies policyRef serialises correctly.
func TestBGPAdvertisementPolicyRefJSONRoundTrip(t *testing.T) {
	orig := newTestAdvertisement()
	orig.Spec.PolicyRef = &AdvertisementPolicyRef{Name: "export-filter"}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPAdvertisement
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Spec.PolicyRef == nil {
		t.Fatal("PolicyRef is nil after round-trip")
	}
	if got.Spec.PolicyRef.Name != "export-filter" {
		t.Errorf("PolicyRef.Name: got %q, want export-filter", got.Spec.PolicyRef.Name)
	}
}

// TestBGPAdvertisementDeepCopyWithAllFields verifies DeepCopy correctly
// handles all pointer and slice fields.
func TestBGPAdvertisementDeepCopyWithAllFields(t *testing.T) {
	orig := &BGPAdvertisement{
		TypeMeta:   metav1.TypeMeta{APIVersion: "galactic.datumapis.com/v1alpha1", Kind: "BGPAdvertisement"},
		ObjectMeta: metav1.ObjectMeta{Name: "full-adv"},
		Spec: BGPAdvertisementSpec{
			RouterRef:     RouterRef{Name: "test-router"},
			AddressFamily: AddressFamily{AFI: AFIIPv6, SAFI: SAFIUnicast},
			Prefixes:      []Prefix{"2001:db8::/48"},
			Redistribute:  []RedistributeSource{RedistributeSourceKernel},
			OriginateFrom: &AdvertisementOriginateFrom{
				Type:          OriginateTypeInterface,
				InterfaceName: ptr("eth0"),
			},
			PolicyRef:       &AdvertisementPolicyRef{Name: "my-policy"},
			Communities:     []Community{"65000:99"},
			LocalPreference: ptr(int32(50)),
		},
	}

	dup := orig.DeepCopy()

	// Mutate dup — original must be unaffected.
	dup.Spec.Prefixes[0] = "10.0.0.0/8"
	dup.Spec.Redistribute[0] = RedistributeSourceStatic
	dup.Spec.OriginateFrom.Type = OriginateTypeKernel
	*dup.Spec.OriginateFrom.InterfaceName = "eth1"
	dup.Spec.PolicyRef.Name = "other-policy"
	dup.Spec.Communities[0] = "99999:99"
	*dup.Spec.LocalPreference = 999

	if orig.Spec.Prefixes[0] != "2001:db8::/48" {
		t.Errorf("Prefixes[0] mutated: got %q", orig.Spec.Prefixes[0])
	}
	if orig.Spec.Redistribute[0] != RedistributeSourceKernel {
		t.Errorf("Redistribute[0] mutated: got %q", orig.Spec.Redistribute[0])
	}
	if orig.Spec.OriginateFrom.Type != OriginateTypeInterface {
		t.Errorf("OriginateFrom.Type mutated: got %q", orig.Spec.OriginateFrom.Type)
	}
	if *orig.Spec.OriginateFrom.InterfaceName != "eth0" {
		t.Errorf("OriginateFrom.InterfaceName mutated: got %q", *orig.Spec.OriginateFrom.InterfaceName)
	}
	if orig.Spec.PolicyRef.Name != "my-policy" {
		t.Errorf("PolicyRef.Name mutated: got %q", orig.Spec.PolicyRef.Name)
	}
	if orig.Spec.Communities[0] != "65000:99" {
		t.Errorf("Communities[0] mutated: got %q", orig.Spec.Communities[0])
	}
	if *orig.Spec.LocalPreference != 50 {
		t.Errorf("LocalPreference mutated: got %d", *orig.Spec.LocalPreference)
	}
}

// TestBGPAdvertisementListDeepCopy verifies BGPAdvertisementList.DeepCopy
// produces independent copies of each item.
func TestBGPAdvertisementListDeepCopy(t *testing.T) {
	list := &BGPAdvertisementList{
		Items: []BGPAdvertisement{*newTestAdvertisement()},
	}
	copied := list.DeepCopy()
	copied.Items[0].Spec.RouterRef.Name = "mutated"

	if list.Items[0].Spec.RouterRef.Name != "test-router" {
		t.Errorf("original list item mutated via copy")
	}
}

// TestBGPAdvertisementSRv6JSONRoundTrip verifies VRFID and Function serialise
// and deserialise correctly.
func TestBGPAdvertisementSRv6JSONRoundTrip(t *testing.T) {
	orig := newTestAdvertisement()
	orig.Spec.VRFID = ptr(int32(100))
	orig.Spec.Function = ptr(SRv6FunctionEndDT6)

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPAdvertisement
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Spec.VRFID == nil || *got.Spec.VRFID != 100 {
		t.Errorf("VRFID: got %v, want 100", got.Spec.VRFID)
	}
	if got.Spec.Function == nil || *got.Spec.Function != SRv6FunctionEndDT6 {
		t.Errorf("Function: got %v, want %q", got.Spec.Function, SRv6FunctionEndDT6)
	}
}

// TestBGPAdvertisementSRv6FieldNames verifies the JSON keys are "vrfID" and "function".
func TestBGPAdvertisementSRv6FieldNames(t *testing.T) {
	orig := newTestAdvertisement()
	orig.Spec.VRFID = ptr(int32(100))
	orig.Spec.Function = ptr(SRv6FunctionEndDT46)

	data, err := json.Marshal(orig.Spec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if raw, ok := m["vrfID"]; !ok || raw != float64(100) {
		t.Errorf("unexpected vrfID value: %v", raw)
	}
	if raw, ok := m["function"]; !ok || raw != "End.DT46" {
		t.Errorf("unexpected function value: %v", raw)
	}
}

// TestBGPAdvertisementSRv6OmitEmpty verifies that VRFID and Function are
// omitted from JSON output when unset.
func TestBGPAdvertisementSRv6OmitEmpty(t *testing.T) {
	orig := newTestAdvertisement()

	data, err := json.Marshal(orig.Spec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if _, ok := m["vrfID"]; ok {
		t.Error("expected \"vrfID\" key to be absent when empty")
	}
	if _, ok := m["function"]; ok {
		t.Error("expected \"function\" key to be absent when empty")
	}
}

// TestBGPAdvertisementSRv6DeepCopy verifies DeepCopy isolates VRFID and Function.
func TestBGPAdvertisementSRv6DeepCopy(t *testing.T) {
	orig := newTestAdvertisement()
	orig.Spec.VRFID = ptr(int32(100))
	orig.Spec.Function = ptr(SRv6FunctionEndDT4)

	dup := orig.DeepCopy()
	*dup.Spec.VRFID = 999
	*dup.Spec.Function = SRv6FunctionEndDT6

	if *orig.Spec.VRFID != 100 {
		t.Errorf("VRFID mutated: got %d", *orig.Spec.VRFID)
	}
	if *orig.Spec.Function != SRv6FunctionEndDT4 {
		t.Errorf("Function mutated: got %q", *orig.Spec.Function)
	}
}

// TestSRv6FunctionConstants verifies enum values match expected strings.
func TestSRv6FunctionConstants(t *testing.T) {
	cases := []struct {
		fn   SRv6Function
		want string
	}{
		{SRv6FunctionEndDT4, "End.DT4"},
		{SRv6FunctionEndDT6, "End.DT6"},
		{SRv6FunctionEndDT46, "End.DT46"},
	}
	for _, tt := range cases {
		if string(tt.fn) != tt.want {
			t.Errorf("SRv6Function %q: got %q, want %q", tt.fn, string(tt.fn), tt.want)
		}
	}
}

// TestRedistributeSourceConstants verifies enum values match expected strings.
func TestRedistributeSourceConstants(t *testing.T) {
	cases := []struct {
		src  RedistributeSource
		want string
	}{
		{RedistributeSourceStatic, "static"},
		{RedistributeSourceConnected, "connected"},
		{RedistributeSourceKernel, "kernel"},
	}
	for _, tt := range cases {
		if string(tt.src) != tt.want {
			t.Errorf("RedistributeSource %q: got %q, want %q", tt.src, string(tt.src), tt.want)
		}
	}
}

// TestOriginateTypeConstants verifies originate type enum values.
func TestOriginateTypeConstants(t *testing.T) {
	cases := []struct {
		typ  AdvertisementOriginateType
		want string
	}{
		{OriginateTypeInterface, "interface"},
		{OriginateTypeKernel, "kernel"},
	}
	for _, tt := range cases {
		if string(tt.typ) != tt.want {
			t.Errorf("AdvertisementOriginateType %q: got %q, want %q", tt.typ, string(tt.typ), tt.want)
		}
	}
}
