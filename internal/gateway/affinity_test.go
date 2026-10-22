// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

// affinityTestBackends returns n backends sharing port, each on its own
// worker uSID.
func affinityTestBackends(n int, port uint16) []DesiredBackend {
	out := make([]DesiredBackend, n)
	for i := range out {
		out[i] = DesiredBackend{
			Address: netip.MustParseAddr(fmt.Sprintf("fd00:10:1::%x", i+0x20)),
			Port:    port,
			USID:    netip.MustParseAddr(fmt.Sprintf("2001:db8:2::%x", i+1)),
		}
	}
	return out
}

// affinityTestRules returns three services over the same eight backend
// addresses, as the API has a tenant spread them: TCP 443 to backend port
// 8443, TCP 80 to backend port 8080 on another VIP, and UDP 443 to backend
// port 8443 on a third.
func affinityTestRules(affinity string) []DesiredRule {
	return []DesiredRule{
		{
			Key: "ns/https", Protocol: protocolTCP, Port: 443, Affinity: affinity,
			VIPAddresses: []netip.Addr{netip.MustParseAddr("2001:db8:1::10")},
			Backends:     affinityTestBackends(8, 8443),
		},
		{
			Key: "ns/http", Protocol: protocolTCP, Port: 80, Affinity: affinity,
			VIPAddresses: []netip.Addr{netip.MustParseAddr("2001:db8:1::11")},
			Backends:     affinityTestBackends(8, 8080),
		},
		{
			Key: "ns/quic", Protocol: protocolUDP, Port: 443, Affinity: affinity,
			VIPAddresses: []netip.Addr{netip.MustParseAddr("2001:db8:1::12")},
			Backends:     affinityTestBackends(8, 8443),
		},
	}
}

// gatewayNode is one gateway node's programmed vip_table, for predicting the
// backend its datapath picks.
type gatewayNode struct {
	t *testing.T
	d *KernelDatapath
}

// newGatewayNode applies rules to a fresh datapath, as each gateway node does
// independently from the same NetworkServices.
func newGatewayNode(t *testing.T, rules []DesiredRule) gatewayNode {
	t.Helper()
	d := newTestKernelDatapath()
	for _, rule := range rules {
		if err := d.ApplyRule(context.Background(), rule); err != nil {
			t.Fatalf("ApplyRule %s: %v", rule.Key, err)
		}
	}
	return gatewayNode{t: t, d: d}
}

// pick returns the backend address this node's datapath sends a flow from
// client:sport to, reading the entry's own affinity and Maglev table and
// hashing as edge_lb does.
func (n gatewayNode) pick(rule DesiredRule, client netip.Addr, sport uint16) netip.Addr {
	n.t.Helper()
	proto, err := protoNumber(rule.Protocol)
	if err != nil {
		n.t.Fatal(err)
	}
	key := edgemap.VIPKey{Proto: proto, VPort: rule.Port, VIP: rule.VIPAddresses[0]}
	entry, ok, err := n.d.vipTable.Get(key)
	if err != nil || !ok {
		n.t.Fatalf("Get %+v: ok=%v err=%v", key, ok, err)
	}
	slot := edgeprog.FlowHash(client.As16(), entry.Affinity, proto, sport) % edgemap.MaglevTableSize
	return entry.Backends[entry.MaglevTable[slot]].Addr
}

// TestAffinity_PinsClientsAsEachModeSays checks each mode's contract over
// 500 clients, IPv6 and IPv4, each opening connections from four random source
// ports to each of three services over one backend set, as seen by two gateway
// nodes that programmed the same services on their own:
//
//   - every mode: both nodes pick the same backend for the same flow
//   - None: a client's connections spread over backends
//   - ClientIP: every connection from one client reaches one backend, across
//     ports, services and protocols
//   - ClientIPAndProtocol: every connection from one client over one protocol
//     reaches one backend, across ports and services
func TestAffinity_PinsClientsAsEachModeSays(t *testing.T) {
	const (
		clients = 500
		ports   = 4
	)
	for _, mode := range []string{affinityNone, affinityClientIP, affinityClientIPAndProtocol} {
		t.Run(mode, func(t *testing.T) {
			rules := affinityTestRules(mode)
			nodeA, nodeB := newGatewayNode(t, rules), newGatewayNode(t, rules)
			r := rand.New(rand.NewPCG(733, 1))

			var spread int
			for c := range clients {
				client := randomAddr(r, c%2 == 0)
				byProto := map[string]netip.Addr{}
				seen := map[netip.Addr]struct{}{}
				for _, rule := range rules {
					for range ports {
						sport := uint16(1024 + r.IntN(65536-1024))
						got := nodeA.pick(rule, client, sport)
						if other := nodeB.pick(rule, client, sport); other != got {
							t.Fatalf("%s from %s:%d: node A picks %s, node B %s", rule.Key, client, sport, got, other)
						}
						seen[got] = struct{}{}

						// The connections a mode pins together: all of a
						// client's under ClientIP, one protocol's under
						// ClientIPAndProtocol.
						pin := rule.Protocol
						if mode == affinityClientIP {
							pin = ""
						}
						pinned, ok := byProto[pin]
						switch {
						case mode == affinityNone:
						case !ok:
							byProto[pin] = got
						case got != pinned:
							t.Fatalf("%s from %s:%d reaches %s, want %s, the backend its other %s connections reach",
								rule.Key, client, sport, got, pinned, mode)
						}
					}
				}
				if len(seen) > 1 {
					spread++
				}
			}

			if mode == affinityNone && spread < clients/2 {
				t.Errorf("None: %d of %d clients reached more than one backend over %d connections, want most",
					spread, clients, len(rules)*ports)
			}
			if mode == affinityClientIP && spread != 0 {
				t.Errorf("ClientIP: %d clients reached more than one backend, want none", spread)
			}
		})
	}
}

// TestAffinity_ClientIPModesKeyTheTableByAddress checks that a client-IP mode
// builds the same Maglev table for services whose backends share addresses but
// not ports, and that None keeps keying by address and port, so the tables of
// rules already running under None do not move.
func TestAffinity_ClientIPModesKeyTheTableByAddress(t *testing.T) {
	for _, tt := range []struct {
		mode string
		same bool
	}{
		{affinityNone, false},
		{affinityClientIP, true},
		{affinityClientIPAndProtocol, true},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			rules := affinityTestRules(tt.mode)
			_, https, err := buildMaglevTable(rules[0], rules[0].Backends)
			if err != nil {
				t.Fatal(err)
			}
			_, http, err := buildMaglevTable(rules[1], rules[1].Backends)
			if err != nil {
				t.Fatal(err)
			}
			if same := https == http; same != tt.same {
				t.Errorf("tables over backend ports 8443 and 8080 identical = %v, want %v", same, tt.same)
			}
		})
	}

	// An unset affinity and None both key the table by address and port, so
	// they build the same table.
	rule := affinityTestRules("")[0]
	_, unset, err := buildMaglevTable(rule, rule.Backends)
	if err != nil {
		t.Fatal(err)
	}
	rule.Affinity = affinityNone
	_, none, err := buildMaglevTable(rule, rule.Backends)
	if err != nil {
		t.Fatal(err)
	}
	if unset != none {
		t.Error("an unset affinity and None build different tables")
	}
}

func TestKernelDatapath_ApplyRuleStoresAffinity(t *testing.T) {
	for mode, want := range map[string]uint8{
		"":                          edgeprog.AffinityNone,
		affinityNone:                edgeprog.AffinityNone,
		affinityClientIP:            edgeprog.AffinityClientIP,
		affinityClientIPAndProtocol: edgeprog.AffinityClientIPAndProtocol,
	} {
		d := newTestKernelDatapath()
		rule := testDesiredRule(t, testKeyA, "2001:db8:1::10")
		rule.Affinity = mode
		if err := d.ApplyRule(context.Background(), rule); err != nil {
			t.Fatalf("ApplyRule(affinity %q): %v", mode, err)
		}
		entry, ok, err := d.vipTable.Get(edgemap.VIPKey{Proto: 6, VPort: 443, VIP: rule.VIPAddresses[0]})
		if err != nil || !ok {
			t.Fatalf("Get: ok=%v err=%v", ok, err)
		}
		if entry.Affinity != want {
			t.Errorf("affinity %q: stored %d, want %d", mode, entry.Affinity, want)
		}
	}
}

func TestKernelDatapath_ApplyRuleRejectsUnknownAffinity(t *testing.T) {
	d := newTestKernelDatapath()
	rule := testDesiredRule(t, testKeyA, "2001:db8:1::10")
	rule.Affinity = "ClientIPAndPort"
	if err := d.ApplyRule(context.Background(), rule); err == nil {
		t.Error("ApplyRule with an unknown affinity: want an error, got nil")
	}
	if entries, err := d.vipTable.List(); err != nil || len(entries) != 0 {
		t.Errorf("vip_table after a refused rule: %d entries, err %v, want none", len(entries), err)
	}
}

// TestKernelDatapath_ApplyRuleRejectsSharedBackendAddressUnderClientIP: a
// client-IP mode keys backends by address, so two backends on one address
// would be one Maglev candidate. The rule is refused rather than merged.
func TestKernelDatapath_ApplyRuleRejectsSharedBackendAddressUnderClientIP(t *testing.T) {
	d := newTestKernelDatapath()
	rule := testDesiredRule(t, testKeyA, "2001:db8:1::10")
	rule.Affinity = affinityClientIP
	second := rule.Backends[0]
	second.Port++
	rule.Backends = append(rule.Backends, second)
	if err := d.ApplyRule(context.Background(), rule); err == nil {
		t.Error("ApplyRule with two backends on one address under ClientIP: want an error, got nil")
	}
}

// TestEngine_AffinityChangeReprogramsTheRule: editing only a running rule's
// affinity reprograms its entry on the next reconcile, which every gateway
// node runs on the NetworkService's update, without a restart.
func TestEngine_AffinityChangeReprogramsTheRule(t *testing.T) {
	d := newTestKernelDatapath()
	e := NewEngine(d, &fakeQuota{}, &fakeTelemetry{})
	ctx := context.Background()
	rule := affinityTestRules(affinityNone)[0]

	for _, step := range []struct {
		affinity string
		want     uint8
	}{
		{affinityNone, edgeprog.AffinityNone},
		{affinityClientIP, edgeprog.AffinityClientIP},
		{affinityClientIPAndProtocol, edgeprog.AffinityClientIPAndProtocol},
		{affinityNone, edgeprog.AffinityNone},
	} {
		rule.Affinity = step.affinity
		if _, err := e.Reconcile(ctx, EngineState{Rules: map[string]DesiredRule{rule.Key: rule}}); err != nil {
			t.Fatalf("Reconcile(affinity %q): %v", step.affinity, err)
		}
		entry, ok, err := d.vipTable.Get(edgemap.VIPKey{Proto: 6, VPort: rule.Port, VIP: rule.VIPAddresses[0]})
		if err != nil || !ok {
			t.Fatalf("Get: ok=%v err=%v", ok, err)
		}
		if entry.Affinity != step.want {
			t.Errorf("after setting %q: programmed affinity %d, want %d", step.affinity, entry.Affinity, step.want)
		}
	}
}
