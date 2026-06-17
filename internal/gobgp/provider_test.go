package gobgp

import (
	"context"
	"testing"

	api "github.com/osrg/gobgp/v4/api"
	providerv1alpha1 "go.miloapis.com/cosmos/api/proto/bgp/provider/v1alpha1"
)

const safiUnicastCaps = "Unicast"

func newTestProvider() *ProviderServer {
	return NewProviderServer(New(Config{}))
}

func TestCapabilities_AddressFamily(t *testing.T) {
	p := newTestProvider()
	resp, err := p.Capabilities(context.Background(), &providerv1alpha1.CapabilitiesRequest{})
	if err != nil {
		t.Fatalf("Capabilities() error = %v", err)
	}
	caps := resp.GetCapabilities()
	if caps == nil {
		t.Fatal("Capabilities() returned nil CapabilitySet")
	}
	afs := caps.GetAddressFamilies()
	if len(afs) != 1 {
		t.Fatalf("len(AddressFamilies) = %d, want 1", len(afs))
	}
	af := afs[0]
	if got := af.GetAfi(); got != afiL2VPN {
		t.Errorf("AFI = %q, want %q", got, afiL2VPN)
	}
	if got := af.GetSafi(); got != safiEVPN {
		t.Errorf("SAFI = %q, want %q", got, safiEVPN)
	}
}

func TestCapabilities_NoUnicast(t *testing.T) {
	p := newTestProvider()
	resp, err := p.Capabilities(context.Background(), &providerv1alpha1.CapabilitiesRequest{})
	if err != nil {
		t.Fatalf("Capabilities() error = %v", err)
	}
	for _, af := range resp.GetCapabilities().GetAddressFamilies() {
		if af.GetSafi() == safiUnicastCaps {
			t.Errorf("unexpected Unicast AF advertised: AFI=%s SAFI=%s", af.GetAfi(), af.GetSafi())
		}
	}
}

func TestCapabilities_Features(t *testing.T) {
	p := newTestProvider()
	resp, err := p.Capabilities(context.Background(), &providerv1alpha1.CapabilitiesRequest{})
	if err != nil {
		t.Fatalf("Capabilities() error = %v", err)
	}
	caps := resp.GetCapabilities()
	if caps.GetRouteReflection() {
		t.Error("RouteReflection should be false")
	}
	if caps.GetBfd() {
		t.Error("BFD should be false")
	}
}

func TestCapabilities_DoesNotRequireLiveBGP(t *testing.T) {
	// Capabilities must return a valid response without a running GoBGP instance.
	p := NewProviderServer(New(Config{})) // server never started
	_, err := p.Capabilities(context.Background(), &providerv1alpha1.CapabilitiesRequest{})
	if err != nil {
		t.Errorf("Capabilities() should not require a live server, got error: %v", err)
	}
}

func TestFamilyFromSpec_L2VPN_EVPN(t *testing.T) {
	af := &providerv1alpha1.AddressFamily{Afi: afiL2VPN, Safi: safiEVPN}
	f := familyFromSpec(af)
	if f.Afi != api.Family_AFI_L2VPN {
		t.Errorf("Afi = %v, want AFI_L2VPN", f.Afi)
	}
	if f.Safi != api.Family_SAFI_EVPN {
		t.Errorf("Safi = %v, want SAFI_EVPN", f.Safi)
	}
}

func TestFamilyFromSpec_IPv4_Unicast(t *testing.T) {
	af := &providerv1alpha1.AddressFamily{Afi: "IPv4", Safi: safiUnicastCaps}
	f := familyFromSpec(af)
	if f.Afi != api.Family_AFI_IP {
		t.Errorf("Afi = %v, want AFI_IP", f.Afi)
	}
	if f.Safi != api.Family_SAFI_UNICAST {
		t.Errorf("Safi = %v, want SAFI_UNICAST", f.Safi)
	}
}

func TestFamilyFromSpec_IPv6_Unicast(t *testing.T) {
	af := &providerv1alpha1.AddressFamily{Afi: "IPv6", Safi: safiUnicastCaps}
	f := familyFromSpec(af)
	if f.Afi != api.Family_AFI_IP6 {
		t.Errorf("Afi = %v, want AFI_IP6", f.Afi)
	}
	if f.Safi != api.Family_SAFI_UNICAST {
		t.Errorf("Safi = %v, want SAFI_UNICAST", f.Safi)
	}
}

func TestFamilyFromSpec_Unknown(t *testing.T) {
	af := &providerv1alpha1.AddressFamily{Afi: "bogus", Safi: "bogus"}
	f := familyFromSpec(af)
	if f.Afi != api.Family_AFI_UNSPECIFIED {
		t.Errorf("Afi = %v, want AFI_UNSPECIFIED for unrecognised input", f.Afi)
	}
	if f.Safi != api.Family_SAFI_UNSPECIFIED {
		t.Errorf("Safi = %v, want SAFI_UNSPECIFIED for unrecognised input", f.Safi)
	}
}
