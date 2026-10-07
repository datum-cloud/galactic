// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachreg

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"testing"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// testNAT64Prefix is the NAT64 prefix the egress route tests configure.
const (
	testNAT64Prefix = "64:ff9b::/96"
	defaultPrefix   = "::/0"
)

func TestEgressKindForInterfaceType(t *testing.T) {
	tests := []struct {
		name    string
		iface   string
		want    uint32
		wantErr bool
	}{
		{name: "VethMapsToEgressKindVeth", iface: InterfaceTypeVeth, want: usidmap.EgressKindVeth},
		{name: "TapMapsToEgressKindTap", iface: InterfaceTypeTap, want: usidmap.EgressKindTap},
		{name: "EmptyTypeErrors", iface: "", wantErr: true},
		{name: "UnknownTypeErrors", iface: "bogus", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EgressKindForInterfaceType(tt.iface)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EgressKindForInterfaceType(%q) error = %v, wantErr %v", tt.iface, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("EgressKindForInterfaceType(%q) = %d, want %d", tt.iface, got, tt.want)
			}
		})
	}
}

func TestInterfaceTypeForLink(t *testing.T) {
	tests := []struct {
		name   string
		link   netlink.Link
		want   string
		wantOK bool
	}{
		{name: "Tuntap", link: &netlink.Tuntap{}, want: InterfaceTypeTap, wantOK: true},
		{name: "Veth", link: &netlink.Veth{}, want: InterfaceTypeVeth, wantOK: true},
		{name: "Dummy", link: &netlink.Dummy{}, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := InterfaceTypeForLink(tt.link)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("InterfaceTypeForLink(%s) = %q, %v; want %q, %v", tt.link.Type(), got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestHostPrefix(t *testing.T) {
	tests := []struct {
		name string
		ip   net.IP
		want string
	}{
		{name: "IPv6", ip: net.ParseIP("fd20:30::1"), want: "fd20:30::1/128"},
		{name: "IPv4SixteenByte", ip: net.ParseIP("172.21.1.1"), want: "172.21.1.1/32"},
		{name: "IPv4FourByte", ip: net.ParseIP("172.21.1.1").To4(), want: "172.21.1.1/32"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HostPrefix(tt.ip); got != tt.want {
				t.Errorf("HostPrefix(%v) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestDecodeVPCIdentifiers_IgnoresZeroPadding(t *testing.T) {
	vpc, att, err := DecodeVPCIdentifiers("jU", "abc")
	if err != nil {
		t.Fatalf("DecodeVPCIdentifiers(jU, abc) error = %v", err)
	}
	paddedVPC, paddedAtt, err := DecodeVPCIdentifiers("0000000jU", "abc")
	if err != nil {
		t.Fatalf("DecodeVPCIdentifiers(0000000jU, abc) error = %v", err)
	}
	if vpc != paddedVPC || att != paddedAtt {
		t.Errorf("padded decode = (%d, %d), unpadded = (%d, %d); want equal", paddedVPC, paddedAtt, vpc, att)
	}
}

// TestInstallEgressRoutes_NoShardIsANoop covers the zero EgressConfig, which
// must install nothing and never open a pinned map.
func TestInstallEgressRoutes_NoShardIsANoop(t *testing.T) {
	if err := installEgressRoutes("/nonexistent/galactic-pin-dir", 1, 0x005, EgressConfig{}); err != nil {
		t.Errorf("installEgressRoutes with no shard = %v, want nil", err)
	}
}

// TestShardSIDsForTenant_WritesTheArgument guards against every tenant VRF on
// a node encapsulating toward a byte-identical shard SID, which would let two
// same-node tenants with overlapping ULAs share a connection row.
func TestShardSIDsForTenant_WritesTheArgument(t *testing.T) {
	sids, err := config.ParseEgressShardSIDs("2001:db8:ff01:9:e001::,2001:db8:ff02:9:e001::")
	if err != nil {
		t.Fatalf("config.ParseEgressShardSIDs() error = %v, want nil", err)
	}

	got, err := ShardSIDsForTenant(sids, 0x2a5)
	if err != nil {
		t.Fatalf("ShardSIDsForTenant() error = %v, want nil", err)
	}

	want := []string{"2001:db8:ff01:9:e2a5::", "2001:db8:ff02:9:e2a5::"}
	if len(got) != len(want) {
		t.Fatalf("ShardSIDsForTenant() = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Errorf("ShardSIDsForTenant()[%d] = %v, want %s", i, got[i], w)
		}
	}
}

// TestShardSIDsForTenant_DistinctPerTenant: two VRFIDs on one node must not
// produce the same destination.
func TestShardSIDsForTenant_DistinctPerTenant(t *testing.T) {
	sids, err := config.ParseEgressShardSIDs("2001:db8:ff01:9:e001::")
	if err != nil {
		t.Fatalf("config.ParseEgressShardSIDs() error = %v, want nil", err)
	}

	a, err := ShardSIDsForTenant(sids, 0x001)
	if err != nil {
		t.Fatalf("ShardSIDsForTenant(0x001) error = %v, want nil", err)
	}
	b, err := ShardSIDsForTenant(sids, 0x002)
	if err != nil {
		t.Fatalf("ShardSIDsForTenant(0x002) error = %v, want nil", err)
	}
	if a[0].Equal(b[0]) {
		t.Errorf("VRFIDs 0x001 and 0x002 both encapsulate toward %v; they must differ", a[0])
	}
}

// TestShardSIDsForTenant_OverwritesAConfiguredArgument: an operator-supplied
// Argument identifies no tenant, so it is replaced rather than honoured.
func TestShardSIDsForTenant_OverwritesAConfiguredArgument(t *testing.T) {
	sids, err := config.ParseEgressShardSIDs("2001:db8:ff01:9:efff::")
	if err != nil {
		t.Fatalf("config.ParseEgressShardSIDs() error = %v, want nil", err)
	}

	got, err := ShardSIDsForTenant(sids, 0x007)
	if err != nil {
		t.Fatalf("ShardSIDsForTenant() error = %v, want nil", err)
	}
	if want := "2001:db8:ff01:9:e007::"; got[0].String() != want {
		t.Errorf("ShardSIDsForTenant() = %v, want %s", got[0], want)
	}
}

// TestShardSIDsForTenant_PreservesBlockNodeIDAndFunction guards the fields the
// Argument rewrite must leave alone.
func TestShardSIDsForTenant_PreservesBlockNodeIDAndFunction(t *testing.T) {
	sids, err := config.ParseEgressShardSIDs("2001:db8:ff01:9:e001::")
	if err != nil {
		t.Fatalf("config.ParseEgressShardSIDs() error = %v, want nil", err)
	}

	got, err := ShardSIDsForTenant(sids, 0x123)
	if err != nil {
		t.Fatalf("ShardSIDsForTenant() error = %v, want nil", err)
	}
	addr, ok := netip.AddrFromSlice(got[0].To16())
	if !ok {
		t.Fatalf("ShardSIDsForTenant() returned %v, which is not a 16-byte address", got[0])
	}
	fields, err := uformat.Decode(addr)
	if err != nil {
		t.Fatalf("uformat.Decode(%v) error = %v, want nil", addr, err)
	}
	if fields.Block != 0x2001_0db8_ff01 {
		t.Errorf("Block = %#x, want %#x", fields.Block, 0x2001_0db8_ff01)
	}
	if fields.NodeID != 9 {
		t.Errorf("NodeID = %d, want 9", fields.NodeID)
	}
	if fields.Function != uformat.FunctionEndDT46 {
		t.Errorf("Function = %#x, want %#x", fields.Function, uformat.FunctionEndDT46)
	}
	if fields.Argument != 0x123 {
		t.Errorf("Argument = %#x, want %#x", fields.Argument, 0x123)
	}
}

// TestShardSIDsForTenant_RejectsAMalformedSID covers entries that parse as IP
// addresses but are not uSIDs.
func TestShardSIDsForTenant_RejectsAMalformedSID(t *testing.T) {
	for _, raw := range []string{
		"2001:db8:ff01:9:e001::1", // non-zero padding: not a uFMT 48+16 address
		"192.0.2.1",               // IPv4: not an SRv6 SID at all
	} {
		sids, err := config.ParseEgressShardSIDs(raw)
		if err != nil {
			t.Fatalf("config.ParseEgressShardSIDs(%q) error = %v, want nil", raw, err)
		}
		if _, err := ShardSIDsForTenant(sids, 0x005); err == nil {
			t.Errorf("ShardSIDsForTenant(%q) error = nil, want an error", raw)
		}
	}
}

// routeCall is one egressPrefixRouteAddFn invocation a test recorded.
type routeCall struct {
	table  uint32
	prefix string
	sids   []net.IP
}

// recordRouteAdds replaces egressPrefixRouteAddFn for one test with a recorder
// that returns failWith for every call, and returns the recorded calls.
func recordRouteAdds(t *testing.T, failWith error) *[]routeCall {
	t.Helper()
	original := egressPrefixRouteAddFn
	t.Cleanup(func() { egressPrefixRouteAddFn = original })
	calls := &[]routeCall{}
	egressPrefixRouteAddFn = func(
		_ *egressroutemap.EgressRouteTable, table uint32, prefix *net.IPNet, sids []net.IP,
	) error {
		*calls = append(*calls, routeCall{table, prefix.String(), sids})
		return failWith
	}
	return calls
}

func TestInstallEgressRoutesIn_DefaultThenOneRoutePerNAT64Prefix(t *testing.T) {
	calls := recordRouteAdds(t, nil)
	sids := []net.IP{net.ParseIP("2001:db8:ff01:9:e2a5::")}

	n, err := installEgressRoutesIn(nil, 7, sids, "2001:db8:64::/96, 64:ff9b::/96", nil)
	if err != nil {
		t.Fatalf("installEgressRoutesIn() = %v, want nil", err)
	}
	want := []string{defaultPrefix, "2001:db8:64::/96", testNAT64Prefix}
	if n != len(want) || len(*calls) != len(want) {
		t.Fatalf("installed %d routes (%+v), want %d", n, *calls, len(want))
	}
	for i, w := range want {
		c := (*calls)[i]
		if c.table != 7 || c.prefix != w || !reflect.DeepEqual(c.sids, sids) {
			t.Errorf("route %d = %+v, want table 7, prefix %s, SIDs %v", i, c, w, sids)
		}
	}

	*calls = nil
	if n, err := installEgressRoutesIn(nil, 7, sids, "", nil); err != nil || n != 1 || len(*calls) != 1 {
		t.Errorf("unset NAT64 list: n = %d, err = %v, routes = %+v; want only ::/0", n, err, *calls)
	}

	*calls = nil
	if _, err := installEgressRoutesIn(nil, 7, sids, "64:ff9b::/96,64:ff9b::/64", nil); err == nil {
		t.Error("installEgressRoutesIn() = nil with a non-/96 NAT64 entry, want an error")
	}
	if len(*calls) != 1 || (*calls)[0].prefix != defaultPrefix {
		t.Errorf("invalid NAT64 list installed %+v, want only the ::/0 route before the error", *calls)
	}
}

func TestInstallEgressRoutesIn_SkipsExistingPrefixes(t *testing.T) {
	calls := recordRouteAdds(t, nil)
	sids := []net.IP{net.ParseIP("2001:db8:ff01:9:e2a5::")}

	exists := func(prefix *net.IPNet) (bool, error) { return prefix.String() == defaultPrefix, nil }
	n, err := installEgressRoutesIn(nil, 7, sids, testNAT64Prefix, exists)
	if err != nil {
		t.Fatalf("installEgressRoutesIn() = %v, want nil", err)
	}
	if n != 1 || len(*calls) != 1 || (*calls)[0].prefix != testNAT64Prefix {
		t.Errorf("n = %d, routes = %+v; want only the missing NAT64 route", n, *calls)
	}
}

func TestInstallEgressRoutesIn_StopsAtFirstFailure(t *testing.T) {
	wantErr := errors.New("no shard resolvable")
	calls := recordRouteAdds(t, wantErr)

	n, err := installEgressRoutesIn(nil, 7, []net.IP{net.ParseIP("2001:db8:ff01:9:e2a5::")}, testNAT64Prefix, nil)
	if !errors.Is(err, wantErr) {
		t.Errorf("installEgressRoutesIn() = %v, want %v", err, wantErr)
	}
	if n != 0 || len(*calls) != 1 {
		t.Errorf("n = %d, routes = %+v; want one failed ::/0 attempt", n, *calls)
	}
}

// requireRoot skips the test unless running as root: pinned eBPF maps need
// CAP_BPF and a bpffs mount.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN/CAP_BPF); re-run via sudo")
	}
}

// TestRegisterEgressKind_UnpinnedMapIsNotFatal covers an ADD that runs after
// install-cni replaced this binary but before the datapath reloaded and pinned
// the map. Failing it would block Instances from starting during an upgrade.
func TestRegisterEgressKind_UnpinnedMapIsNotFatal(t *testing.T) {
	requireRoot(t)
	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-attachreg-test-unpinned-%d", os.Getpid())
	if err := registerEgressKind(pinDir, 42, usidmap.EgressKindTap); err != nil {
		t.Errorf("registerEgressKind with no pinned map = %v, want nil", err)
	}
}
