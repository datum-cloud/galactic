// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/plumbing/ebpf/forwardgatemap"
)

var (
	edgeLinksDesc = prometheus.NewDesc("galactic_edge_foundation_links",
		"Edge attachment host links registered with the node's forwarding gate.", nil, nil)
	gatesDesc = prometheus.NewDesc("galactic_edge_foundation_gates",
		"Forwarding gates on the node's edge links, by state: open (deadline ahead), expired (deadline passed, "+
			"not yet closed by the agent) or closed (kept until the route records it closed).",
		[]string{"state"}, nil)
	gateDropsDesc = prometheus.NewDesc("galactic_edge_foundation_gate_drops_total",
		"Packets the datapath dropped on an edge link because no open gate covered the address, by check: "+
			"ingress (from the provider), egress (towards the provider) or deliver (local delivery).",
		[]string{"check"}, nil)
	scopesLostDesc = prometheus.NewDesc("galactic_edge_foundation_scopes_lost",
		"VPC ownership scopes another writer took from this process, which no longer programs or releases there.",
		nil, nil)
	nodeCollectErrorsDesc = prometheus.NewDesc("galactic_edge_foundation_node_collect_errors",
		"Reads of the node's forwarding gate or encapsulation limit the last scrape could not make, rather than "+
			"reporting zero.",
		nil, nil)
	mtuDesc = prometheus.NewDesc("galactic_edge_foundation_mtu_bytes",
		"The MTU the agent gives every attachment link, its --mtu flag.", nil, nil)
	encapLimitDesc = prometheus.NewDesc("galactic_edge_foundation_encap_limit_bytes",
		"The largest packet the fabric underlay carries once encapsulated (encap_mtu_table), read at scrape time. "+
			"An attachment MTU above it is refused. Zero means galactic-cni has not set it and the check is off.",
		nil, nil)
)

// gateStats is a GateTable that also reads the datapath's gate drop counters.
type gateStats interface {
	Stats() (forwardgatemap.Stats, error)
}

// Stats implements gateStats.
func (g PinnedGates) Stats() (s forwardgatemap.Stats, err error) {
	err = g.with(func(t *forwardgatemap.Table) error {
		s, err = t.Stats()
		return err
	})
	return s, err
}

// Collector exports the node's edge state at scrape time: its registered
// links, its gates by state, the datapath's gate drop counters, lost
// ownership scopes, and its attachment MTU with the encapsulation limit it is
// checked against, whether or not the node has attachments. No label names a
// link, prefix or attachment.
type Collector struct{ Agent *Agent }

// Describe implements prometheus.Collector.
func (c Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{edgeLinksDesc, gatesDesc, gateDropsDesc, scopesLostDesc,
		nodeCollectErrorsDesc, mtuDesc, encapLimitDesc} {
		ch <- d
	}
}

// Collect implements prometheus.Collector. It reads the pinned maps without
// taking the agent's pass lock, so a long pass never stalls a scrape.
func (c Collector) Collect(ch chan<- prometheus.Metric) {
	a := c.Agent
	a.lostMu.Lock()
	lost := len(a.lost)
	a.lostMu.Unlock()
	ch <- prometheus.MustNewConstMetric(scopesLostDesc, prometheus.GaugeValue, float64(lost))
	ch <- prometheus.MustNewConstMetric(mtuDesc, prometheus.GaugeValue, float64(a.MTU))
	if a.Gates == nil && a.EncapMTU == nil {
		return
	}
	failed := 0
	if a.EncapMTU != nil {
		if limit, err := a.EncapMTU(); err != nil {
			failed++
		} else {
			ch <- prometheus.MustNewConstMetric(encapLimitDesc, prometheus.GaugeValue, float64(limit))
		}
	}
	if a.Gates != nil {
		failed += collectGates(ch, a)
	}
	ch <- prometheus.MustNewConstMetric(nodeCollectErrorsDesc, prometheus.GaugeValue, float64(failed))
}

// collectGates exports a's links, gates by state and gate drop counters, and
// returns the reads it could not make.
func collectGates(ch chan<- prometheus.Metric, a *Agent) int {
	failed := 0
	if links, err := a.Gates.Links(); err != nil {
		failed++
	} else {
		ch <- prometheus.MustNewConstMetric(edgeLinksDesc, prometheus.GaugeValue, float64(len(links)))
		now := a.bootClock()
		states := map[string]int{"open": 0, "expired": 0, "closed": 0}
		for ifindex := range links {
			rows, err := a.Gates.Gates(ifindex)
			if err != nil {
				failed++
				continue
			}
			for _, g := range rows {
				switch {
				case g.Deadline == 0:
					states["closed"]++
				case g.Deadline > now:
					states["open"]++
				default:
					states["expired"]++
				}
			}
		}
		for state, n := range states {
			ch <- prometheus.MustNewConstMetric(gatesDesc, prometheus.GaugeValue, float64(n), state)
		}
	}
	if gs, ok := a.Gates.(gateStats); ok {
		if s, err := gs.Stats(); err != nil {
			failed++
		} else {
			for check, n := range map[string]uint64{"ingress": s.Ingress, "egress": s.Egress, "deliver": s.Deliver} {
				ch <- prometheus.MustNewConstMetric(gateDropsDesc, prometheus.CounterValue, float64(n), check)
			}
		}
	}
	return failed
}
