package v1alpha1

import (
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newTestPolicy() *BGPPolicy {
	lp := int32(100)
	return &BGPPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "galactic.datumapis.com/v1alpha1",
			Kind:       "BGPPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy"},
		Spec: BGPPolicySpec{
			RouterTarget: RouterTarget{
				RouterRef: &RouterRef{Name: "test-router"},
			},
			Direction: BGPPolicyDirectionImport,
			Terms: []BGPPolicyTerm{
				{
					Sequence: 10,
					Match: BGPPolicyMatch{
						AddressFamilies: []AddressFamily{
							{AFI: AFIIPv6, SAFI: SAFIUnicast},
						},
					},
					Action: BGPPolicyActionPermit,
					Set: &BGPPolicySetActions{
						LocalPreference: &lp,
					},
				},
				{
					Sequence: 9999,
					Match:    BGPPolicyMatch{Any: true},
					Action:   BGPPolicyActionDeny,
				},
			},
		},
	}
}

// TestBGPPolicyDirectionConstants verifies the direction enum values.
func TestBGPPolicyDirectionConstants(t *testing.T) {
	if BGPPolicyDirectionImport != "import" {
		t.Errorf("BGPPolicyDirectionImport = %q, want %q", BGPPolicyDirectionImport, "import")
	}
	if BGPPolicyDirectionExport != "export" {
		t.Errorf("BGPPolicyDirectionExport = %q, want %q", BGPPolicyDirectionExport, "export")
	}
}

// TestBGPPolicyActionConstants verifies the action enum values.
func TestBGPPolicyActionConstants(t *testing.T) {
	if BGPPolicyActionPermit != "permit" {
		t.Errorf("BGPPolicyActionPermit = %q, want %q", BGPPolicyActionPermit, "permit")
	}
	if BGPPolicyActionDeny != "deny" {
		t.Errorf("BGPPolicyActionDeny = %q, want %q", BGPPolicyActionDeny, "deny")
	}
}

// TestBGPOriginConstants verifies the BGP origin enum values.
func TestBGPOriginConstants(t *testing.T) {
	if BGPOriginIGP != "igp" {
		t.Errorf("BGPOriginIGP = %q, want %q", BGPOriginIGP, "igp")
	}
	if BGPOriginEGP != "egp" {
		t.Errorf("BGPOriginEGP = %q, want %q", BGPOriginEGP, "egp")
	}
	if BGPOriginIncomplete != "incomplete" {
		t.Errorf("BGPOriginIncomplete = %q, want %q", BGPOriginIncomplete, "incomplete")
	}
}

// TestASPathMatchTypeConstants verifies the match type enum values.
func TestASPathMatchTypeConstants(t *testing.T) {
	if ASPathMatchFull != "full" {
		t.Errorf("ASPathMatchFull = %q, want %q", ASPathMatchFull, "full")
	}
	if ASPathMatchContains != "contains" {
		t.Errorf("ASPathMatchContains = %q, want %q", ASPathMatchContains, "contains")
	}
}

// TestEVPNRouteTypeConstants verifies the EVPN route type enum values.
func TestEVPNRouteTypeConstants(t *testing.T) {
	tests := []struct {
		val  EVPNRouteType
		want string
	}{
		{EVPNRouteTypeInclusiveMulticastEthernetTag, "inclusiveMulticastEthernetTag"},
		{EVPNRouteTypeMACIPAdvertisement, "macIPAdvertisement"},
		{EVPNRouteTypeIPPrefixAdvertisement, "iPPrefixAdvertisement"},
		{EVPNRouteTypeStickyMACAddress, "stickyMACAddress"},
		{EVPNRouteTypeIPv6PrefixAdvertisement, "iPv6PrefixAdvertisement"},
	}
	for _, tt := range tests {
		if string(tt.val) != tt.want {
			t.Errorf("EVPNRouteType %q = %q, want %q", tt.val, string(tt.val), tt.want)
		}
	}
}

// TestBGPPolicyDeepCopy verifies that DeepCopy produces an independent copy.
func TestBGPPolicyDeepCopy(t *testing.T) {
	orig := newTestPolicy()
	dup := orig.DeepCopy()

	dup.Spec.Direction = BGPPolicyDirectionExport
	dup.Spec.Terms[0].Sequence = 99

	if orig.Spec.Direction != BGPPolicyDirectionImport {
		t.Errorf("Direction mutated: got %q, want %q", orig.Spec.Direction, BGPPolicyDirectionImport)
	}
	if orig.Spec.Terms[0].Sequence != 10 {
		t.Errorf("Term sequence mutated: got %d, want 10", orig.Spec.Terms[0].Sequence)
	}
}

// TestBGPPolicyDeepCopyNil verifies DeepCopy on a nil pointer returns nil.
func TestBGPPolicyDeepCopyNil(t *testing.T) {
	var p *BGPPolicy
	if p.DeepCopy() != nil {
		t.Error("DeepCopy on nil pointer should return nil")
	}
}

// TestBGPPolicyListDeepCopy verifies that BGPPolicyList.DeepCopy produces
// independent copies of each item.
func TestBGPPolicyListDeepCopy(t *testing.T) {
	list := &BGPPolicyList{
		Items: []BGPPolicy{*newTestPolicy()},
	}
	copied := list.DeepCopy()
	copied.Items[0].Spec.Direction = BGPPolicyDirectionExport

	if list.Items[0].Spec.Direction != BGPPolicyDirectionImport {
		t.Errorf("original list item direction mutated via copy")
	}
}

// TestBGPPolicyJSONRoundTrip verifies that the struct serialises and
// deserialises through JSON without data loss.
func TestBGPPolicyJSONRoundTrip(t *testing.T) {
	orig := newTestPolicy()

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPPolicy
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Spec.Direction != orig.Spec.Direction {
		t.Errorf("Direction: got %q, want %q", got.Spec.Direction, orig.Spec.Direction)
	}
	if len(got.Spec.Terms) != len(orig.Spec.Terms) {
		t.Errorf("Terms count: got %d, want %d", len(got.Spec.Terms), len(orig.Spec.Terms))
	}
	if got.Spec.Terms[0].Sequence != 10 {
		t.Errorf("Term[0].Sequence: got %d, want 10", got.Spec.Terms[0].Sequence)
	}
	if got.Spec.Terms[0].Action != BGPPolicyActionPermit {
		t.Errorf("Term[0].Action: got %q, want %q", got.Spec.Terms[0].Action, BGPPolicyActionPermit)
	}
}

// TestBGPPolicyMatchFieldNamesJSON verifies that match field JSON keys are correct.
func TestBGPPolicyMatchFieldNamesJSON(t *testing.T) {
	vni := uint32(10100)
	lp := int32(150)
	med := int32(50)
	mac := "aa:bb:cc:dd:ee:ff"
	prefix := "10.0.0.0/24"

	match := BGPPolicyMatch{
		PrefixList: []string{"10.0.0.0/8"},
		ASPathFilter: &ASPathFilter{
			Pattern:   "^65000",
			MatchType: ASPathMatchContains,
		},
		CommunityMatch:  []string{"65000:100"},
		EVPNRouteType:   []EVPNRouteType{EVPNRouteTypeMACIPAdvertisement},
		VNI:             &vni,
		MACAddress:      &mac,
		IPPrefix:        &prefix,
		LocalPreference: &lp,
		MED:             &med,
	}

	data, err := json.Marshal(match)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	expectedKeys := []string{
		"prefixList", "asPathFilter", "communityMatch", "evpnRouteType",
		"vni", "macAddress", "ipPrefix", "localPreference", "med",
	}
	for _, key := range expectedKeys {
		if _, ok := m[key]; !ok {
			t.Errorf("expected JSON key %q not found in match", key)
		}
	}
}

// TestBGPPolicySetActionsFieldNamesJSON verifies that set action field JSON keys are correct.
func TestBGPPolicySetActionsFieldNamesJSON(t *testing.T) {
	self := true
	metric := int32(100)
	color := int32(42)
	origin := BGPOriginIGP
	prepend := uint32(2)
	asn := int64(65000)

	set := BGPPolicySetActions{
		Origin: &origin,
		AsPath: &AsPathSet{
			Prepend: &prepend,
			ASN:     &asn,
		},
		NextHop: &NextHopSet{
			Self: &self,
		},
		ExtCommunities: &ExtendedCommunitySet{
			Add:    []string{"65000:100"},
			Remove: []string{"65000:200"},
		},
		Metric: &metric,
		Color:  &color,
	}

	data, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	expectedKeys := []string{
		"origin", "asPath", "nextHop", "extCommunities",
		"metric", "color",
	}
	for _, key := range expectedKeys {
		if _, ok := m[key]; !ok {
			t.Errorf("expected JSON key %q not found in set actions", key)
		}
	}
}

// TestBGPPolicyMatchDeepCopy verifies deep copy isolation for all new match fields.
func TestBGPPolicyMatchDeepCopy(t *testing.T) {
	vni := uint32(10100)
	lp := int32(150)
	med := int32(50)
	mac := "aa:bb:cc:dd:ee:ff"
	prefix := "10.0.0.0/24"

	orig := &BGPPolicyTerm{
		Sequence: 10,
		Match: BGPPolicyMatch{
			PrefixList: []string{"10.0.0.0/8", "192.168.0.0/16"},
			ASPathFilter: &ASPathFilter{
				Pattern:   "^65000",
				MatchType: ASPathMatchContains,
			},
			CommunityMatch:  []string{"65000:100"},
			EVPNRouteType:   []EVPNRouteType{EVPNRouteTypeMACIPAdvertisement},
			VNI:             &vni,
			MACAddress:      &mac,
			IPPrefix:        &prefix,
			LocalPreference: &lp,
			MED:             &med,
		},
		Action: BGPPolicyActionPermit,
	}

	dup := orig.DeepCopy()

	// Mutate the duplicate and ensure original is unaffected.
	dup.Match.PrefixList[0] = "172.16.0.0/12"
	dup.Match.CommunityMatch[0] = "65001:999"
	dup.Match.EVPNRouteType[0] = EVPNRouteTypeStickyMACAddress
	newVNI := uint32(9999)
	dup.Match.VNI = &newVNI

	if orig.Match.PrefixList[0] != "10.0.0.0/8" {
		t.Errorf("PrefixList[0] mutated: got %q", orig.Match.PrefixList[0])
	}
	if orig.Match.CommunityMatch[0] != "65000:100" {
		t.Errorf("CommunityMatch[0] mutated: got %q", orig.Match.CommunityMatch[0])
	}
	if orig.Match.EVPNRouteType[0] != EVPNRouteTypeMACIPAdvertisement {
		t.Errorf("EVPNRouteType[0] mutated: got %q", orig.Match.EVPNRouteType[0])
	}
	if *orig.Match.VNI != 10100 {
		t.Errorf("VNI mutated: got %d", *orig.Match.VNI)
	}
}

// TestBGPPolicySetActionsDeepCopy verifies deep copy isolation for all new set action fields.
func TestBGPPolicySetActionsDeepCopy(t *testing.T) {
	self := true
	metric := int32(100)
	color := int32(42)
	origin := BGPOriginIGP
	prepend := uint32(2)
	asn := int64(65000)

	orig := &BGPPolicySetActions{
		Origin: &origin,
		AsPath: &AsPathSet{
			Prepend: &prepend,
			ASN:     &asn,
		},
		NextHop: &NextHopSet{
			Self: &self,
		},
		ExtCommunities: &ExtendedCommunitySet{
			Add:    []string{"65000:100"},
			Remove: []string{"65000:200"},
		},
		Metric: &metric,
		Color:  &color,
	}

	dup := orig.DeepCopy()

	// Mutate duplicate and verify original unchanged.
	*dup.Metric = 999
	*dup.Color = 999
	dup.ExtCommunities.Add[0] = "99999:99999"

	if *orig.Metric != 100 {
		t.Errorf("Metric mutated: got %d", *orig.Metric)
	}
	if *orig.Color != 42 {
		t.Errorf("Color mutated: got %d", *orig.Color)
	}
	if orig.ExtCommunities.Add[0] != "65000:100" {
		t.Errorf("ExtCommunities.Add[0] mutated: got %q", orig.ExtCommunities.Add[0])
	}
}

// TestASPathSetDeepCopy verifies deep copy for AsPathSet, including the Replace list.
func TestASPathSetDeepCopy(t *testing.T) {
	orig := &AsPathSet{
		Replace: []int64{65000, 65001, 65002},
	}
	dup := orig.DeepCopy()
	dup.Replace[0] = 99999

	if orig.Replace[0] != 65000 {
		t.Errorf("Replace[0] mutated via copy: got %d", orig.Replace[0])
	}
}

// TestBGPPolicyMatchJSONRoundTrip verifies the full match struct round-trips cleanly.
func TestBGPPolicyMatchJSONRoundTrip(t *testing.T) {
	vni := uint32(10100)
	mac := "aa:bb:cc:dd:ee:ff"
	prefix := "2001:db8::/32"

	orig := BGPPolicyMatch{
		AddressFamilies: []AddressFamily{{AFI: AFIL2VPN, SAFI: SAFIEVPN}},
		PrefixList:      []string{"10.0.0.0/8"},
		EVPNRouteType:   []EVPNRouteType{EVPNRouteTypeMACIPAdvertisement, EVPNRouteTypeIPPrefixAdvertisement},
		VNI:             &vni,
		MACAddress:      &mac,
		IPPrefix:        &prefix,
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPPolicyMatch
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(got.EVPNRouteType) != 2 {
		t.Errorf("EVPNRouteType count: got %d, want 2", len(got.EVPNRouteType))
	}
	if got.EVPNRouteType[0] != EVPNRouteTypeMACIPAdvertisement {
		t.Errorf("EVPNRouteType[0]: got %q, want %q", got.EVPNRouteType[0], EVPNRouteTypeMACIPAdvertisement)
	}
	if *got.VNI != vni {
		t.Errorf("VNI: got %d, want %d", *got.VNI, vni)
	}
	if *got.MACAddress != mac {
		t.Errorf("MACAddress: got %q, want %q", *got.MACAddress, mac)
	}
	if *got.IPPrefix != prefix {
		t.Errorf("IPPrefix: got %q, want %q", *got.IPPrefix, prefix)
	}
}

// TestBGPPolicySetActionsJSONRoundTrip verifies the full set actions struct round-trips cleanly.
func TestBGPPolicySetActionsJSONRoundTrip(t *testing.T) {
	self := false
	addr := "2001:db8::1"
	metric := int32(200)
	color := int32(10)
	origin := BGPOriginEGP
	prepend := uint32(3)
	asn := int64(65000)

	orig := BGPPolicySetActions{
		Origin: &origin,
		AsPath: &AsPathSet{
			Prepend: &prepend,
			ASN:     &asn,
		},
		NextHop: &NextHopSet{
			Self:    &self,
			Address: &addr,
		},
		ExtCommunities: &ExtendedCommunitySet{
			Add:    []string{"65000:100", "65000:200"},
			Remove: []string{"65000:999"},
		},
		Metric: &metric,
		Color:  &color,
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got BGPPolicySetActions
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if *got.Origin != origin {
		t.Errorf("Origin: got %q, want %q", *got.Origin, origin)
	}
	if *got.AsPath.Prepend != prepend {
		t.Errorf("AsPath.Prepend: got %d, want %d", *got.AsPath.Prepend, prepend)
	}
	if *got.AsPath.ASN != asn {
		t.Errorf("AsPath.ASN: got %d, want %d", *got.AsPath.ASN, asn)
	}
	if *got.Metric != metric {
		t.Errorf("Metric: got %d, want %d", *got.Metric, metric)
	}
	if *got.Color != color {
		t.Errorf("Color: got %d, want %d", *got.Color, color)
	}
	if len(got.ExtCommunities.Add) != 2 {
		t.Errorf("ExtCommunities.Add count: got %d, want 2", len(got.ExtCommunities.Add))
	}
	if len(got.ExtCommunities.Remove) != 1 {
		t.Errorf("ExtCommunities.Remove count: got %d, want 1", len(got.ExtCommunities.Remove))
	}
}

// TestAsPathSetReplaceJSONRoundTrip verifies that Replace (not Prepend) round-trips.
func TestAsPathSetReplaceJSONRoundTrip(t *testing.T) {
	orig := AsPathSet{
		Replace: []int64{65000, 65001, 65002},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got AsPathSet
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(got.Replace) != 3 {
		t.Errorf("Replace count: got %d, want 3", len(got.Replace))
	}
	if got.Replace[2] != 65002 {
		t.Errorf("Replace[2]: got %d, want 65002", got.Replace[2])
	}
}

// TestASPathFilterJSONRoundTrip verifies ASPathFilter round-trips cleanly.
func TestASPathFilterJSONRoundTrip(t *testing.T) {
	orig := ASPathFilter{
		Pattern:   "^(65000|65001)$",
		MatchType: ASPathMatchFull,
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if _, ok := m["pattern"]; !ok {
		t.Error("expected JSON key \"pattern\" not found")
	}
	if _, ok := m["matchType"]; !ok {
		t.Error("expected JSON key \"matchType\" not found")
	}

	var got ASPathFilter
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal into struct: %v", err)
	}
	if got.Pattern != orig.Pattern {
		t.Errorf("Pattern: got %q, want %q", got.Pattern, orig.Pattern)
	}
	if got.MatchType != ASPathMatchFull {
		t.Errorf("MatchType: got %q, want %q", got.MatchType, ASPathMatchFull)
	}
}

// TestExtendedCommunitySetDeepCopy verifies deep copy isolation.
func TestExtendedCommunitySetDeepCopy(t *testing.T) {
	orig := &ExtendedCommunitySet{
		Add:    []string{"65000:100", "65000:200"},
		Remove: []string{"65000:999"},
	}
	dup := orig.DeepCopy()
	dup.Add[0] = "mutated"

	if orig.Add[0] != "65000:100" {
		t.Errorf("Add[0] mutated via copy: got %q", orig.Add[0])
	}
}
