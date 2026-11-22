// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/labels"
	"sigs.k8s.io/controller-runtime/pkg/event"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/controller"
	"go.datum.net/galactic/internal/gateway"
	"go.datum.net/galactic/internal/gateway/localhandoff"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
)

// publicPathPoll is how often the public path is re-read besides coverage
// changes: public_uplink_table is another component's map, with no event.
const publicPathPoll = 5 * time.Second

// publicPath decides which VIP families this gateway withdraws because its
// public path does not cover them (D44), and re-queues the NetworkGateway
// when that or the Local handoff's readiness changes.
//
// A family is withdrawn when:
//   - a public target the datapath resolved, such as a bond member, runs
//     without the load balancer, which affects both families;
//   - the gateway hands backends on this node to their TAPs and
//     public_uplink_table, through which usid_egress sends every one of
//     their replies (D43), has no row, which affects both families too, since
//     both families' replies leave through that one next hop. Those backends
//     are also reported not ready (PublicUplinkMissing), since their replies
//     fail whichever gateway selected them.
//
// A single Local backend whose handoff is not ready withdraws nothing: it is
// reported Unhealthy and leaves every gateway's Maglev table instead.
type publicPath struct {
	coverage *datapathCoverage
	uplink   func() (bool, error)
	local    *localhandoff.Manager

	events chan event.GenericEvent
	kick   chan struct{}

	mu   sync.Mutex
	last controller.PublicPathState
}

func newPublicPath(coverage *datapathCoverage, local *localhandoff.Manager) *publicPath {
	return &publicPath{coverage: coverage, uplink: pinnedUplinkPresent, local: local,
		events: make(chan event.GenericEvent, 1), kick: make(chan struct{}, 1)}
}

// pinnedUplinkPresent reports whether galactic-cni's public_uplink_table on
// this node holds a next hop.
func pinnedUplinkPresent() (bool, error) {
	pu, closer, err := egressroutemap.OpenPinnedPublicUplink(attach.PinDir)
	if err != nil {
		return false, err
	}
	defer closer.Close() //nolint:errcheck // read-only handle
	_, _, _, ok, err := pu.Get()
	return ok, err
}

// State computes the current PublicPathState.
func (p *publicPath) State() controller.PublicPathState {
	var why []string
	if missing := p.coverage.PublicMissing(); len(missing) > 0 {
		why = append(why, "public targets without the load balancer: "+strings.Join(missing, ", "))
	}
	if p.local != nil && len(p.local.Snapshot().Attachments) > 0 {
		ok, err := p.uplink()
		switch {
		case err != nil:
			why = append(why, "cannot read public_uplink_table, through which local backends reply: "+err.Error())
		case !ok:
			why = append(why, "public_uplink_table has no next hop, so local backends' replies cannot leave")
		}
		// The local backends' replies leave through that row whichever
		// gateway selected them, so they are also reported not ready, which
		// takes them out of every gateway's Maglev table.
		p.local.SetUplinkMissing(err != nil || !ok)
	} else if p.local != nil {
		p.local.SetUplinkMissing(false)
	}
	if len(why) == 0 {
		return controller.PublicPathState{}
	}
	r := strings.Join(why, "; ")
	return controller.PublicPathState{IPv6: r, IPv4: r}
}

// Current returns the state Run last computed, which the reconciler reads
// several times a pass.
func (p *publicPath) Current() controller.PublicPathState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.last
}

// Changed nudges a re-read: the coverage or the Local handoff changed.
func (p *publicPath) Changed() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// Run re-reads the public path on every nudge and every publicPathPoll, and
// re-queues the NetworkGateway on every change, and on every nudge, since a
// nudge from the Local handoff is a readiness change to publish.
func (p *publicPath) Run(ctx context.Context) {
	t := time.NewTicker(publicPathPoll)
	defer t.Stop()
	first := true
	for {
		nudged := first
		if !first {
			select {
			case <-ctx.Done():
				return
			case <-p.kick:
				nudged = true
			case <-t.C:
			}
		}
		first = false
		s := p.State()
		p.mu.Lock()
		changed := s != p.last
		p.last = s
		p.mu.Unlock()
		if changed {
			slog.Info("Gateway public path changed", "ipv6Withdrawn", s.IPv6, "ipv4Withdrawn", s.IPv4)
		}
		if changed || nudged {
			select {
			case p.events <- event.GenericEvent{Object: &bgpv1alpha1.NetworkGateway{}}:
			default:
			}
		}
	}
}

// localHandoffOrNil keeps a nil *localhandoff.Manager from becoming a non-nil
// controller.LocalHandoff.
func localHandoffOrNil(m *localhandoff.Manager) controller.LocalHandoff {
	if m == nil {
		return nil
	}
	return m
}

// clearLocalTable removes every edge_local_table row, for a gateway running
// without Galactic Worker.
func clearLocalTable(t *gateway.LocalTable) error {
	rows, err := t.List()
	if err != nil {
		return err
	}
	for sid := range rows {
		if err := t.Delete(sid); err != nil {
			return err
		}
	}
	return nil
}

// Metrics of the Local handoff and the public path, in the galactic_edge
// namespace the gateway's other series use.
var (
	workerSessionDesc = prometheus.NewDesc("galactic_edge_worker_session_up",
		"1 while this gateway holds a Galactic Worker session, 0 while it cannot open one. Absent while the "+
			"gateway runs without Worker.",
		nil, nil)
	localHandoffReadyDesc = prometheus.NewDesc("galactic_edge_local_handoff_ready",
		"1 for each backend attachment on this node whose Local handoff Worker reports ready, 0 otherwise, "+
			"with the reason. A backend at 0 has its flows through this gateway dropped and is reported "+
			"Unhealthy, so every gateway leaves it out of its Maglev table.",
		[]string{labelAttachment, labels.Reason}, nil)
	localTableErrorsDesc = prometheus.NewDesc("galactic_edge_local_table_errors_total",
		"Failed edge_local_table writes since the gateway started.",
		nil, nil)
	familyWithdrawnDesc = prometheus.NewDesc("galactic_edge_family_withdrawn",
		"1 while this gateway withdraws a VIP family from BGP because its public path does not cover it "+
			"(the NetworkGateway's PublicPath condition says why), 0 otherwise.",
		[]string{labelFamily}, nil)
)

const (
	labelAttachment = "attachment"
	labelFamily     = "family"
)

// localCollector reports the Local handoff and the public path at every
// scrape.
type localCollector struct {
	local *localhandoff.Manager
	path  *publicPath
}

// Describe implements prometheus.Collector.
func (c *localCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- workerSessionDesc
	ch <- localHandoffReadyDesc
	ch <- localTableErrorsDesc
	ch <- familyWithdrawnDesc
}

// Collect implements prometheus.Collector.
func (c *localCollector) Collect(ch chan<- prometheus.Metric) {
	if c.local != nil {
		snap := c.local.Snapshot()
		ch <- prometheus.MustNewConstMetric(workerSessionDesc, prometheus.GaugeValue, boolValue(snap.SessionUp))
		for _, a := range snap.Attachments {
			ch <- prometheus.MustNewConstMetric(localHandoffReadyDesc, prometheus.GaugeValue, boolValue(a.Ready),
				a.AttachmentUID, a.Reason)
		}
		ch <- prometheus.MustNewConstMetric(localTableErrorsDesc, prometheus.CounterValue, float64(snap.TableErrors))
	}
	s := c.path.Current()
	ch <- prometheus.MustNewConstMetric(familyWithdrawnDesc, prometheus.GaugeValue, boolValue(s.IPv6 != ""), "ipv6")
	ch <- prometheus.MustNewConstMetric(familyWithdrawnDesc, prometheus.GaugeValue, boolValue(s.IPv4 != ""), "ipv4")
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
