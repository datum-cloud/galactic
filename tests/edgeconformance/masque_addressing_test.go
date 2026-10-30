// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeconformance_test

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/edge/provider"
)

// masqueSubdivided are client-managed addresses in two /112 subdivisions
// of VPC 10's connector /96, none of which core or the provider allocated.
var masqueSubdivided = []string{
	"fd00:ed9e:300:1::1:1", "fd00:ed9e:300:1::1:2",
	"fd00:ed9e:300:1::2:1", "fd00:ed9e:300:1::2:2",
}

// rowAggregateRouting (M12) sends from every address of masqueSubdivided to
// VPC 10's workload on the compute node, its workload on the fixture's node
// and the off-fabric host through NAT, and requires each pair answered: the
// one aggregate /96 carries return traffic to any address inside it. While
// the connector is connected it requires exactly one BGPAdvertisement of the
// connector's route, for the /96 itself, and none for anything longer inside
// the /96.
func (m *masque) rowAggregateRouting(t *testing.T) {
	mt := m.a
	dsts := []string{m.workload(t, mt.tn, 1).addr, m.workload(t, mt.tn, 2).addr, remoteHost}
	p, err := startProbe(m.pod.Spec.NodeName, 1, "aggregate-vpc-"+mt.tn.vpc,
		append(connectArgs(m.pod, mt.token, mt.tn.vpc, mt.id, 5*time.Second, dsts),
			"-src", strings.Join(masqueSubdivided, ","))...)
	if err != nil {
		t.Fatal(err)
	}
	own := m.routeAdvertisements(t)
	evs := p.wait(m.l, t)
	pairs := len(masqueSubdivided) * len(dsts)
	requireSession(t, "VPC "+mt.tn.vpc+"'s request", evs, 5*time.Second, pairs)
	perPair := sentCount(evs) / pairs
	for _, src := range masqueSubdivided {
		for _, dst := range dsts {
			n := 0
			for _, e := range echoes(evs, dst) {
				if e.Dst == src {
					n++
				}
			}
			m.l.record(t, fmt.Sprintf("%s to %s", src, dst), fmt.Sprintf("%d/%d", n, perPair))
			if perPair == 0 || n < perPair*9/10 {
				t.Errorf("%s to %s: %d of %d answered", src, dst, n, perPair)
			}
		}
	}
	if n := others(evs); n > 0 {
		t.Errorf("the client received %d packets that were not its replies", n)
	}

	m.l.record(t, "advertisements of the connector's route", own)
	if len(own) != 1 {
		t.Errorf("route %s has %d BGPAdvertisements %v, want one", provider.RouteName(mt.vpcUID,
			netip.MustParsePrefix(masquePrefix)), len(own), own)
	}
}

// routeAdvertisements waits while VPC 10's connector is connected until its
// route is advertised, and returns its BGPAdvertisements. It fails for one
// that carries anything but the /96, and for any BGPAdvertisement carrying a
// longer prefix inside the /96.
func (m *masque) routeAdvertisements(t *testing.T) []string {
	t.Helper()
	prefix := netip.MustParsePrefix(masquePrefix)
	route := masqueNS + "/" + provider.RouteName(m.a.vpcUID, prefix)
	var advs networkv1alpha1.BGPAdvertisementList
	eventually(t, 4*time.Second, 200*time.Millisecond, "route "+route+" advertised", func() (bool, error) {
		if err := m.l.c.List(context.Background(), &advs, client.InNamespace(systemNS)); err != nil {
			return false, err
		}
		return slices.ContainsFunc(advs.Items, func(a networkv1alpha1.BGPAdvertisement) bool {
			return a.Annotations[crdnames.AnnotationEdgeRoute] == route
		}), nil
	})
	var own []string
	for _, a := range advs.Items {
		if a.Annotations[crdnames.AnnotationEdgeRoute] == route {
			own = append(own, fmt.Sprintf("%s %v", a.Name, a.Spec.Prefixes))
			if len(a.Spec.Prefixes) != 1 || string(a.Spec.Prefixes[0]) != masquePrefix {
				t.Errorf("BGPAdvertisement %s of route %s carries %v, want only %s", a.Name, route,
					a.Spec.Prefixes, masquePrefix)
			}
		}
		for _, s := range a.Spec.Prefixes {
			if q, err := netip.ParsePrefix(string(s)); err == nil && q.Bits() > prefix.Bits() &&
				prefix.Contains(q.Addr()) {
				t.Errorf("BGPAdvertisement %s carries %s, inside the connector's %s", a.Name, q, prefix)
			}
		}
	}
	return own
}
