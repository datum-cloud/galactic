// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

const (
	rolloutUplink = "rollout-uplink"
	dnsPrimary    = "fd53::53"
	dnsSecondary  = "fd53::54"
)

func TestCompatibleStartupPreservesDNSAuthorization(t *testing.T) {
	requireRoot(t)
	pin := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-compatible-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(pin) })
	t.Setenv(config.EnvCNIEBPFInterfaces, rolloutUplink)
	network, err := ns.TempNetNS()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = network.Close() }()
	if err := network.Do(func(_ ns.NetNS) error {
		for _, link := range []netlink.Link{
			&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: rolloutUplink}},
			&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "consumer0"}, PeerName: "consumer0p"},
			&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "producer0"}, PeerName: "producer0p"},
		} {
			if err := netlink.LinkAdd(link); err != nil {
				return err
			}
			if err := netlink.LinkSetUp(link); err != nil {
				return err
			}
		}
		old, _, err := Start(pin)
		if err != nil {
			return err
		}
		defer func() { _ = old.Close() }()
		var gate prog.UsidServicePolicyStateValue
		if err := old.ServicePolicyStateTable.Lookup(uint32(0), &gate); err != nil {
			return err
		}
		if gate.Enabled != 0 {
			t.Fatal("cold start enabled unauthorised policy")
		}
		consumer, err := netlink.LinkByName("consumer0")
		if err != nil {
			return err
		}
		producer, err := netlink.LinkByName("producer0")
		if err != nil {
			return err
		}
		ci, pi := uint32(consumer.Attrs().Index), uint32(producer.Attrs().Index)
		for _, link := range []netlink.Link{consumer, producer} {
			if err := AttachEgressWithIdentity(old.UsidServiceEgress, old.UsidEgress, old.AttachmentIdentityTable,
				uint32(link.Attrs().Index), link.Attrs().Name); err != nil {
				return err
			}
		}
		var ct, pt uint64
		if err := old.AttachmentIdentityTable.Lookup(ci, &ct); err != nil {
			return err
		}
		if err := old.AttachmentIdentityTable.Lookup(pi, &pt); err != nil {
			return err
		}
		seedDNSAuthorization(t, old, ci, pi, ct, pt)
		assertDNSVerdict(t, old.UsidServiceEgress, ci, 7)
		current, _, err := Start(pin)
		if err != nil {
			return err
		}
		defer func() { _ = current.Close() }()
		if progID(t, old.UsidServiceEgress) == progID(t, current.UsidServiceEgress) {
			t.Fatal("test did not replace program")
		}
		if err := current.ServicePolicyStateTable.Lookup(uint32(0), &gate); err != nil {
			return err
		}
		if gate.Enabled != 1 {
			t.Fatal("compatible startup disabled live policy")
		}
		for index, want := range map[uint32]uint64{ci: ct, pi: pt} {
			var got uint64
			if err := current.AttachmentIdentityTable.Lookup(index, &got); err != nil {
				return err
			}
			if got != want {
				t.Fatalf("ifindex %d token changed from %d to %d", index, want, got)
			}
		}
		assertDNSVerdict(t, current.UsidServiceEgress, ci, 7)
		// Preserving the gate must not bypass explicit revocation.
		for _, address := range []string{dnsPrimary, dnsSecondary} {
			if err := current.ServiceAccessTable.Delete(dnsAccessKey(ci, address)); err != nil {
				return err
			}
		}
		assertDNSVerdict(t, current.UsidServiceEgress, ci, 2)
		assertMissingIdentityFailsClosed(t, pin, current, ci, ct)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// assertDNSVerdict executes both DNS requests in the real kernel classifier.
func assertDNSVerdict(t *testing.T, program *ebpf.Program, ifindex, want uint32) {
	t.Helper()
	for _, address := range []string{dnsPrimary, dnsSecondary} {
		packet := make([]byte, 14+40+8+12)
		binary.BigEndian.PutUint16(packet[12:14], 0x86dd)
		packet[14] = 0x60
		binary.BigEndian.PutUint16(packet[18:20], 20)
		packet[20], packet[21] = 17, 64
		src, dst := netip.MustParseAddr("fd20::2").As16(), netip.MustParseAddr(address).As16()
		copy(packet[22:38], src[:])
		copy(packet[38:54], dst[:])
		binary.BigEndian.PutUint16(packet[54:56], 49152)
		binary.BigEndian.PutUint16(packet[56:58], 53)
		binary.BigEndian.PutUint16(packet[58:60], 20)
		context := make([]byte, 192)
		binary.NativeEndian.PutUint32(context[36:40], ifindex)
		binary.NativeEndian.PutUint32(context[40:44], ifindex)
		got, err := program.Run(&ebpf.RunOptions{Data: packet, Context: context})
		if err != nil || got != want {
			t.Fatalf("%s verdict = %d, error = %v; want %d", address, got, err, want)
		}
	}
}

func TestIncompleteChainsCannotPreserveIdentity(t *testing.T) {
	service := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{Priority: filterPriorityFn(), Handle: netlink.MakeHandle(0, 1)},
		Name:        serviceEgressFilterName,
	}
	legacy := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{Priority: filterPriorityFn() + 1, Handle: netlink.MakeHandle(0, 2)},
		Name:        egressFilterName,
	}
	wrongSlot := *service
	wrongSlot.Handle = netlink.MakeHandle(0, 3)
	for _, tc := range []struct {
		name    string
		filters []netlink.Filter
	}{
		{"Missing", nil}, {"ServiceOnly", []netlink.Filter{service}},
		{"LegacyOnly", []netlink.Filter{legacy}}, {"DuplicateService", []netlink.Filter{service, service, legacy}},
		{"DuplicateLegacy", []netlink.Filter{service, legacy, legacy}}, {"WrongSlot", []netlink.Filter{&wrongSlot, legacy}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keep, err := canPreserveEgressIdentity(tc.filters, nil, nil, nil)
			if err != nil || keep {
				t.Fatalf("preserve = %v, error = %v", keep, err)
			}
		})
	}
}

func seedDNSAuthorization(t *testing.T, objects *prog.UsidObjects, ci, pi uint32, ct, pt uint64) {
	t.Helper()
	for _, address := range []string{dnsPrimary, dnsSecondary} {
		addr := netip.MustParseAddr(address).As16()
		if err := objects.ServiceRouteTable.Put(prog.UsidServiceRouteKey{
			IngressIfindex: ci, Protocol: 17, Port: bits.ReverseBytes16(53), Addr: addr,
		}, prog.UsidServiceRouteValue{
			TargetIfindex: pi, Mode: 1, ConsumerToken: ct, ProducerToken: pt, BackendAddr: addr,
		}); err != nil {
			t.Fatal(err)
		}
		if err := objects.ServiceAccessTable.Put(
			dnsAccessKey(ci, address), prog.UsidServiceAccessValue{AttachmentToken: ct}); err != nil {
			t.Fatal(err)
		}
	}
	if err := objects.ServicePolicyStateTable.Put(uint32(0), prog.UsidServicePolicyStateValue{Enabled: 1}); err != nil {
		t.Fatal(err)
	}
}

func dnsAccessKey(ifindex uint32, address string) prog.UsidServiceAccessKey {
	return prog.UsidServiceAccessKey{
		IngressIfindex: ifindex, Protocol: 17, Port: bits.ReverseBytes16(53), Addr: netip.MustParseAddr(address).As16(),
	}
}

func assertMissingIdentityFailsClosed(t *testing.T, pin string, current *prog.UsidObjects, ci uint32, ct uint64) {
	t.Helper()
	// Lost incarnation metadata must not inherit otherwise valid old rows.
	for _, address := range []string{dnsPrimary, dnsSecondary} {
		if err := current.ServiceAccessTable.Put(
			dnsAccessKey(ci, address), prog.UsidServiceAccessValue{AttachmentToken: ct}); err != nil {
			t.Fatal(err)
		}
	}
	if err := current.AttachmentIdentityTable.Delete(ci); err != nil {
		t.Fatal(err)
	}
	missing, _, err := Start(pin)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = missing.Close() }()
	var newToken uint64
	if err := missing.AttachmentIdentityTable.Lookup(ci, &newToken); err != nil {
		t.Fatal(err)
	}
	if newToken == 0 || newToken == ct {
		t.Fatalf("missing identity inherited token %d", newToken)
	}
	assertDNSVerdict(t, missing.UsidServiceEgress, ci, 2)

}
