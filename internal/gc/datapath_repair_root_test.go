// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/cni/veth"
	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/hostgw"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/vrf"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// rebuiltMaps are the pinned maps RepairAttachmentDatapath rebuilds.
var rebuiltMaps = []string{
	prog.UsidMapVrfTable,
	prog.UsidMapLocatorTable,
	prog.UsidMapFunctionTable,
	prog.UsidMapVpcAttributionTable,
	prog.UsidMapIfindexVrfTable,
	prog.UsidMapIfindexEgressKindTable,
	prog.UsidMapTenantGwTable,
	prog.UsidMapEgressRouteTable,
	prog.UsidMapNodeSrcAddrTable,
	prog.UsidMapPublicUplinkTable,
}

// rootAttachment is one attachment the root test creates and registers
// through the CNI ADD-side helpers.
type rootAttachment struct {
	vpc, vpcAttachment string
	ifaceType          string
	vrfID              int32
	ipam               *cniipam.IPAMResult
}

// localEgressPrefixes mirrors cnibgp's own derivation of an ADD's local
// prefixes from its IPAM result, which this package cannot import.
func (a rootAttachment) localEgressPrefixes() []string {
	if a.ipam == nil {
		return nil
	}
	var prefixes []string
	if a.ipam.IPv6Subnet != nil {
		prefixes = append(prefixes, a.ipam.IPv6Subnet.String())
	}
	if a.ipam.IPv4Address != nil {
		prefixes = append(prefixes, a.ipam.IPv4Address.String()+"/32")
	}
	if a.ipam.IPv6Gateway != nil {
		prefixes = append(prefixes, attachreg.HostPrefix(a.ipam.IPv6Gateway))
	}
	if a.ipam.IPv4Gateway != nil {
		prefixes = append(prefixes, attachreg.HostPrefix(a.ipam.IPv4Gateway))
	}
	return prefixes
}

// advertisement returns the BGPAdvertisement galactic-bgp's ADD publishes for
// a on nodeName: the guest prefixes of its IPAM result, or the no-addressing
// annotation when it has none.
func (a rootAttachment) advertisement(nodeName string) *bgpv1alpha1.BGPAdvertisement {
	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:      crdnames.BGPAdvertisementName(a.vpc, a.vpcAttachment, nodeName),
			Namespace: repairNamespace,
		},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{RouterRef: bgpv1alpha1.RouterRef{Name: repairRouter}},
	}
	if a.ipam == nil {
		adv.Annotations = map[string]string{crdnames.AnnotationNoAddressing: crdnames.AnnotationNoAddressingValue}
		return adv
	}
	if a.ipam.IPv6Subnet != nil {
		adv.Spec.Prefixes = append(adv.Spec.Prefixes, bgpv1alpha1.Prefix(a.ipam.IPv6Subnet.String()))
	}
	if a.ipam.IPv4Address != nil {
		adv.Spec.Prefixes = append(adv.Spec.Prefixes, bgpv1alpha1.Prefix(a.ipam.IPv4Address.String()+"/32"))
	}
	return adv
}

func (a rootAttachment) gateways() *attachreg.Gateways {
	if a.ipam == nil {
		return nil
	}
	return &attachreg.Gateways{IPv6: a.ipam.IPv6Gateway, IPv4: a.ipam.IPv4Gateway}
}

// snapshotMaps returns every rebuilt map's rows as hex key to hex value,
// with the Generation stamp and datapath counters cleared, which a rebuilt
// row carries afresh and which say nothing about what the row routes.
func snapshotMaps(t *testing.T, pinDir string) map[string]map[string]string {
	t.Helper()
	out := map[string]map[string]string{}
	for _, name := range rebuiltMaps {
		m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
		if err != nil {
			t.Fatalf("open pinned %s: %v", name, err)
		}
		rows := map[string]string{}
		var key, value []byte
		it := m.Iterate()
		for it.Next(&key, &value) {
			rows[hex.EncodeToString(key)] = hex.EncodeToString(normalizeRow(name, value))
		}
		if err := it.Err(); err != nil {
			t.Fatalf("iterate %s: %v", name, err)
		}
		_ = m.Close()
		out[name] = rows
	}
	return out
}

// normalizeRow clears the bytes of value that are a write stamp or a packet
// counter rather than routing state.
func normalizeRow(mapName string, value []byte) []byte {
	v := append([]byte(nil), value...)
	switch mapName {
	case prog.UsidMapVrfTable:
		// vrf_table_id and egress_kind are the first 8 bytes; the rest are
		// counters and the generation.
		clear(v[8:])
	case prog.UsidMapLocatorTable:
		clear(v)
	case prog.UsidMapVpcAttributionTable:
		// vpc, vpc_attachment and padding, then the generation.
		clear(v[16:])
	}
	return v
}

// emptyMaps leaves every rebuilt map pinned but empty, the state a recreated
// map is left in.
func emptyMaps(t *testing.T, pinDir string) {
	t.Helper()
	for _, name := range rebuiltMaps {
		m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
		if err != nil {
			t.Fatalf("open pinned %s: %v", name, err)
		}
		if m.Type() == ebpf.Array {
			zero := make([]byte, m.ValueSize())
			if err := m.Put(uint32(0), zero); err != nil {
				t.Fatalf("clear %s: %v", name, err)
			}
			_ = m.Close()
			continue
		}
		var keys [][]byte
		var key, value []byte
		it := m.Iterate()
		for it.Next(&key, &value) {
			keys = append(keys, append([]byte(nil), key...))
		}
		for _, k := range keys {
			if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("delete from %s: %v", name, err)
			}
		}
		_ = m.Close()
	}
}

// setUpUplink gives the current namespace an SRv6 uplink with a resolved
// neighbor and a route covering the egress shard's whole locator, so shard
// routes and public_uplink_table both resolve.
func setUpUplink(name, shardLocator string) error {
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
	if err := netlink.LinkAdd(dummy); err != nil {
		return fmt.Errorf("add uplink: %w", err)
	}
	if err := netlink.LinkSetUp(dummy); err != nil {
		return fmt.Errorf("set uplink up: %w", err)
	}
	gw := net.ParseIP("fe80::1")
	if err := netlink.NeighAdd(&netlink.Neigh{
		LinkIndex: dummy.Attrs().Index, Family: netlink.FAMILY_V6, State: netlink.NUD_PERMANENT,
		IP: gw, HardwareAddr: net.HardwareAddr{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
	}); err != nil {
		return fmt.Errorf("add uplink neighbor: %w", err)
	}
	_, dst, err := net.ParseCIDR(shardLocator)
	if err != nil {
		return err
	}
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: dummy.Attrs().Index, Dst: dst, Gw: gw}); err != nil {
		return fmt.Errorf("add shard route: %w", err)
	}
	return nil
}

// createAttachment creates a's VRF, host interface, and host gateway
// addressing the way the master plugin does.
func createAttachment(a rootAttachment) error {
	if err := vrf.Add(a.vpc); err != nil {
		return fmt.Errorf("vrf.Add(%s): %w", a.vpc, err)
	}
	switch a.ifaceType {
	case attachreg.InterfaceTypeTap:
		if _, err := tap.Add(a.vpc, a.vpcAttachment, "owner", 1500); err != nil {
			return fmt.Errorf("tap.Add: %w", err)
		}
	default:
		if _, err := veth.Add(a.vpc, a.vpcAttachment, "owner", 1500); err != nil {
			return fmt.Errorf("veth.Add: %w", err)
		}
	}
	if err := hostgw.ConfigureHostGateway(a.vpc, a.vpcAttachment, a.ipam, nil); err != nil {
		return fmt.Errorf("ConfigureHostGateway: %w", err)
	}
	return nil
}

// registerAttachment registers a through the CNI ADD-side helpers, as
// galactic-bgp does.
func registerAttachment(a rootAttachment, node attachreg.Node, pinDir string, egress attachreg.EgressConfig) error {
	registered, err := attachreg.RegisterDatapath(pinDir, attachreg.Registration{
		Node:          node,
		VPC:           a.vpc,
		VPCAttachment: a.vpcAttachment,
		InterfaceType: a.ifaceType,
		Argument:      uint16(a.vrfID),
		LocalPrefixes: a.localEgressPrefixes(),
		Egress:        egress,
	})
	if err != nil || !registered {
		return fmt.Errorf("RegisterDatapath(%s/%s) = %v, %w; want registered", a.vpc, a.vpcAttachment, registered, err)
	}
	attachreg.RegisterTenantGateway(pinDir, a.vpc, a.vpcAttachment, a.gateways())
	return nil
}

// TestRepairAttachmentDatapath_RebuildsWhatADDWrote registers attachments
// through the real CNI ADD-side helpers, empties every map they wrote, and
// requires one repair pass to put back the rows ADD wrote.
//
// The VPC holding a veth and a tap attachment shares one vrf_table and one
// vpc_attribution_table row, which ADD leaves holding whichever attachment
// registered last, and the repair writes from the lower host ifindex. In
// ReverseOrder the last ADD is the lower ifindex, so every row matches
// exactly. In NaturalOrder it is not, and those two rows must instead hold
// the lower-ifindex attachment's values while every other row matches.
func TestRepairAttachmentDatapath_RebuildsWhatADDWrote(t *testing.T) {
	requireRoot(t)
	t.Run("ReverseOrder", func(t *testing.T) { rebuildsWhatADDWrote(t, true) })
	t.Run("NaturalOrder", func(t *testing.T) { rebuildsWhatADDWrote(t, false) })
}

// sharedVRFKey is the vrf_table and vpc_attribution_table key, in the raw byte
// form snapshotMaps reports, of the (Block, Argument) the fixture's veth and
// tap attachments share.
func sharedVRFKey(t *testing.T, argument uint16) string {
	t.Helper()
	key, err := uformat.NewVRFKey(testBlock(t), argument)
	if err != nil {
		t.Fatalf("NewVRFKey: %v", err)
	}
	return hex.EncodeToString(binary.NativeEndian.AppendUint64(nil, uint64(key)))
}

func rebuildsWhatADDWrote(t *testing.T, reverse bool) {
	const (
		nodeName     = "repair-node"
		uplinkName   = "rpup0"
		shardSID     = "2001:db8:ff01:9:e001::"
		shardLocator = "2001:db8:ff01:9::/64"
	)
	node := attachreg.Node{Locator: testLocator, NodeID: 5}
	egress := attachreg.EgressConfig{ShardSIDs: shardSID, NAT64Prefix: "64:ff9b::/96"}
	attachments := []rootAttachment{
		{vpc: "jU", vpcAttachment: "abc", ifaceType: attachreg.InterfaceTypeVeth, vrfID: 0x21, ipam: &cniipam.IPAMResult{
			IPv6Subnet:  mustCIDR(t, "fd20:30:ff01::/96"),
			IPv6Gateway: net.ParseIP("fd20:30::1"),
			IPv4Address: net.ParseIP("10.1.0.5"),
			IPv4Gateway: net.ParseIP("172.21.1.1"),
		}},
		{vpc: "jU", vpcAttachment: "def", ifaceType: attachreg.InterfaceTypeTap, vrfID: 0x21, ipam: &cniipam.IPAMResult{
			IPv6Subnet:  mustCIDR(t, "fd20:30:ff02::/96"),
			IPv6Gateway: net.ParseIP("fd20:30::1"),
			IPv4Address: net.ParseIP("10.1.0.6"),
			IPv4Gateway: net.ParseIP("172.21.1.129"),
		}},
		{vpc: "kV", vpcAttachment: "ghi", ifaceType: attachreg.InterfaceTypeTap, vrfID: 0x22},
		// A static address with no gateway: the kernel has no route for it,
		// so only its BGPAdvertisement records the guest prefixes (#806).
		{vpc: "mW", vpcAttachment: "pq", ifaceType: attachreg.InterfaceTypeVeth, vrfID: 0x23, ipam: &cniipam.IPAMResult{
			IPv6Subnet:  mustCIDR(t, "fd20:31:ff03::/96"),
			IPv4Address: net.ParseIP("10.1.0.7"),
		}},
	}

	objects := make([]client.Object, 0, 1+3+len(attachments))
	objects = append(objects, &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: repairRouter, Namespace: repairNamespace},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{Kind: targetKindNode, Name: nodeName}, LocalASN: 65000,
			SRv6Locator: node.Locator, NodeID: node.NodeID,
		},
	})
	for _, vpc := range []struct {
		name string
		id   int32
	}{{"jU", 0x21}, {"kV", 0x22}, {"mW", 0x23}} {
		objects = append(objects, &bgpv1alpha1.BGPVRFInstance{
			ObjectMeta: metav1.ObjectMeta{Name: crdnames.BGPVRFInstanceName(vpc.name, nodeName), Namespace: repairNamespace},
			Spec: bgpv1alpha1.BGPVRFInstanceSpec{
				RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: repairRouter}},
				VRFID:              vpc.id,
				ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTarget}},
				ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTarget}},
			},
		})
	}
	for _, a := range attachments {
		objects = append(objects, a.advertisement(nodeName))
	}
	k8s := fake.NewClientBuilder().WithScheme(gcTestScheme(t)).WithObjects(objects...).Build()

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-repair-test-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	objs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatalf("attach.Load: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	t.Setenv(config.EnvCNIEBPFInterfaces, uplinkName)
	attach.InvalidateUplinkIndexes()
	t.Cleanup(attach.InvalidateUplinkIndexes)

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })

	// Everything that reads or writes links runs inside the namespace; the
	// pinned maps are global, so the snapshots run outside it, on the test
	// goroutine.
	err = nsObj.Do(func(ns.NetNS) error {
		if err := setUpUplink(uplinkName, shardLocator); err != nil {
			return err
		}
		for _, a := range attachments {
			if err := createAttachment(a); err != nil {
				return err
			}
		}
		order := slices.Clone(attachments)
		if reverse {
			slices.Reverse(order)
		}
		for _, a := range order {
			if err := registerAttachment(a, node, pinDir, egress); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("register attachments: %v", err)
	}

	want := snapshotMaps(t, pinDir)
	for _, name := range rebuiltMaps {
		if len(want[name]) == 0 {
			t.Fatalf("ADD wrote no %s rows; the fixture does not exercise it", name)
		}
	}
	emptyMaps(t, pinDir)

	repair := func() (DatapathRepairResult, error) {
		var result DatapathRepairResult
		err := nsObj.Do(func(ns.NetNS) error {
			var err error
			result, err = RepairAttachmentDatapath(context.Background(), k8s, DatapathRepairConfig{
				Namespace: repairNamespace, NodeName: nodeName, PinDir: pinDir, Egress: egress,
			})
			return err
		})
		return result, err
	}

	result, err := repair()
	if err != nil {
		t.Fatalf("RepairAttachmentDatapath: %v", err)
	}
	if result.UplinkErr != nil {
		t.Errorf("public uplink not rebuilt: %v", result.UplinkErr)
	}
	if result.Attachments != len(attachments) {
		t.Errorf("repair examined %d attachments, want %d", result.Attachments, len(attachments))
	}

	got := snapshotMaps(t, pinDir)
	if !reverse {
		checkSharedRowsFromLowestIfindex(t, pinDir, attachments[0])
		shared := sharedVRFKey(t, uint16(attachments[0].vrfID))
		for _, name := range []string{prog.UsidMapVrfTable, prog.UsidMapVpcAttributionTable} {
			if _, ok := got[name][shared]; !ok {
				t.Errorf("%s after repair has no row for the shared key", name)
			}
			delete(got[name], shared)
			delete(want[name], shared)
		}
	}
	for _, name := range rebuiltMaps {
		if !maps.Equal(got[name], want[name]) {
			t.Errorf("%s after repair:\n got %v\nwant %v", name, got[name], want[name])
		}
	}

	again, err := repair()
	if err != nil || again.Rebuilt.Total() != 0 {
		t.Errorf("second pass rebuilt %+v err %v, want nothing", again.Rebuilt, err)
	}
}

// checkSharedRowsFromLowestIfindex fails t unless the shared vrf_table and
// vpc_attribution_table rows hold lowest's values, lowest being the
// attachment created first and so given the lower host ifindex.
func checkSharedRowsFromLowestIfindex(t *testing.T, pinDir string, lowest rootAttachment) {
	t.Helper()
	reg, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		t.Fatalf("OpenPinnedRegistry: %v", err)
	}
	defer func() { _ = closer.Close() }()
	block, argument := testBlock(t), uint16(lowest.vrfID)

	wantKind, err := attachreg.EgressKindForInterfaceType(lowest.ifaceType)
	if err != nil {
		t.Fatalf("EgressKindForInterfaceType: %v", err)
	}
	if e, ok, err := reg.VRF.Get(block, argument); err != nil || !ok || e.EgressKind != wantKind {
		t.Errorf("shared vrf_table row = %+v ok %v err %v, want egress kind %d from the lowest ifindex",
			e, ok, err, wantKind)
	}
	wantVPC, wantAtt, err := attachreg.DecodeVPCIdentifiers(lowest.vpc, lowest.vpcAttachment)
	if err != nil {
		t.Fatalf("DecodeVPCIdentifiers: %v", err)
	}
	if e, ok, err := reg.VPCAttribution.Get(block, argument); err != nil || !ok ||
		e.VPC != wantVPC || e.VPCAttachment != wantAtt {
		t.Errorf("shared vpc_attribution_table row = %+v ok %v err %v, want attachment %s",
			e, ok, err, lowest.vpcAttachment)
	}
}
