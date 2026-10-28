// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/metrics"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
)

// The state of node_src_addr_table, as node_source_address_status reports it.
const (
	// NodeSourceUnknown: not checked yet, because no VRF is installed.
	NodeSourceUnknown = "unknown"
	// NodeSourceUnconfigured: no resolver is configured, because the sidecar
	// has no node name, so nothing can set the address.
	NodeSourceUnconfigured = "unconfigured"
	// NodeSourceOK: the table holds this node's address.
	NodeSourceOK = "ok"
	// NodeSourceUnresolved: this node's BGPRouter does not yield an address
	// yet, so the table was left as it was.
	NodeSourceUnresolved = "unresolved"
	// NodeSourceError: reading or writing the table failed.
	NodeSourceError = "error"
)

var nodeSourceStatuses = []string{
	NodeSourceUnknown, NodeSourceUnconfigured, NodeSourceOK, NodeSourceUnresolved, NodeSourceError,
}

var (
	// errNodeSourceUnconfigured is returned when no NodeSourceAddressResolver
	// has been configured.
	errNodeSourceUnconfigured = errors.New("no node source address resolver configured")
	// errNodeSourceUnresolved wraps a resolver failure.
	errNodeSourceUnresolved = errors.New("resolve node source address")
)

// nodeSourceStatus maps an EnsureNodeSourceAddress error to its status.
func nodeSourceStatus(err error) string {
	switch {
	case err == nil:
		return NodeSourceOK
	case errors.Is(err, errNodeSourceUnconfigured):
		return NodeSourceUnconfigured
	case errors.Is(err, errNodeSourceUnresolved):
		return NodeSourceUnresolved
	default:
		return NodeSourceError
	}
}

// syncNodeSourceAddress makes table hold resolver's address for this node,
// writing only when it holds nothing or something else, and reads the write
// back. It reports whether it wrote.
func syncNodeSourceAddress(resolver NodeSourceAddressResolver, table *egressroutemap.NodeSourceAddress) (bool, error) {
	if resolver == nil {
		return false, errNodeSourceUnconfigured
	}
	want, err := resolver.ResolveNodeSourceAddress()
	if err != nil {
		return false, fmt.Errorf("%w: %w", errNodeSourceUnresolved, err)
	}
	got, ok, err := table.Get()
	if err != nil {
		return false, err
	}
	if ok && got.Equal(want) {
		return false, nil
	}
	if err := table.Set(want); err != nil {
		return false, err
	}
	got, ok, err = table.Get()
	if err != nil {
		return true, err
	}
	if !ok || !got.Equal(want) {
		return true, &nodeSourceMismatchError{want: want, got: got}
	}
	return true, nil
}

// nodeSourceMismatchError reports a write that did not read back.
type nodeSourceMismatchError struct {
	want, got net.IP
}

func (e *nodeSourceMismatchError) Error() string {
	return "node_src_addr_table reads back " + e.got.String() + " after writing " + e.want.String()
}

// NodeSourceMetrics reports node_src_addr_table, the per-node SRv6 source
// address usid_egress stamps on every packet it encapsulates: its state as of
// the last sweep that checked it, when that was, and how often a sweep wrote
// it. The Store records each check under its own lock. The status and the
// time are published together as one snapshot, so a scrape never sees two
// statuses set, or none, while a check changes it. Every method is safe on a
// nil receiver.
type NodeSourceMetrics struct {
	check   *nodeSourceCheckCollector
	repairs prometheus.Counter
}

// nodeSourceCheck is the result of the last check. The zero time means none
// has run.
type nodeSourceCheck struct {
	status string
	at     time.Time
}

// nodeSourceCheckCollector exports the last check's status, one-hot, and
// time from one atomically published value.
type nodeSourceCheckCollector struct {
	last   atomic.Pointer[nodeSourceCheck]
	status *prometheus.Desc
	at     *prometheus.Desc
}

func (c *nodeSourceCheckCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.status
	ch <- c.at
}

func (c *nodeSourceCheckCollector) Collect(ch chan<- prometheus.Metric) {
	last := c.last.Load()
	for _, s := range nodeSourceStatuses {
		v := 0.0
		if s == last.status {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.status, prometheus.GaugeValue, v, s)
	}
	at := 0.0
	if !last.at.IsZero() {
		at = float64(last.at.UnixNano()) / 1e9
	}
	ch <- prometheus.MustNewConstMetric(c.at, prometheus.GaugeValue, at)
}

// NewNodeSourceMetrics creates node source address metrics with the status
// unknown and no repairs. The repair count is on the instrumentation
// library's registry, which keeps it across calls, so each call starts it
// over; MustRegister exports the status.
func NewNodeSourceMetrics() *NodeSourceMetrics {
	check := &nodeSourceCheckCollector{
		status: prometheus.NewDesc(
			prometheus.BuildFQName(metricsNamespace, "", "node_source_address_status"),
			"1 for the state node_src_addr_table was in at the last check: unknown (never checked, since no VRF "+
				"has been installed since start), unconfigured (no node name), ok, unresolved (this node's "+
				"BGPRouter yields no address yet), or error (reading or writing the table failed). "+
				"Encapsulation fails open until it is ok.",
			[]string{statusLabel}, nil),
		at: prometheus.NewDesc(
			prometheus.BuildFQName(metricsNamespace, "", "node_source_address_last_checked_timestamp_seconds"),
			"Unix time of the last sweep that checked node_src_addr_table; 0 before the first. Sweeps check "+
				"only while a VRF is installed.",
			nil, nil),
	}
	check.last.Store(&nodeSourceCheck{status: NodeSourceUnknown})
	return &NodeSourceMetrics{
		check: check,
		repairs: newCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "node_source_address_repairs_total",
			Help: "Sweeps that found node_src_addr_table unset or holding another address and wrote this " +
				"node's, successfully.",
		}),
	}
}

// MustRegister registers m's status collector on the instrumentation
// library's registry. Call it once per process.
func (m *NodeSourceMetrics) MustRegister() {
	metrics.MustRegister(m.check)
}

// observe records one check at now.
func (m *NodeSourceMetrics) observe(now time.Time, wrote bool, err error) {
	if m == nil {
		return
	}
	m.check.last.Store(&nodeSourceCheck{status: nodeSourceStatus(err), at: now})
	if wrote && err == nil {
		m.repairs.Inc()
	}
}

// SetNodeSourceMetrics configures where the Store reports node_src_addr_table.
// Call it once, before the sweeper starts.
func (s *Store) SetNodeSourceMetrics(m *NodeSourceMetrics) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodeSourceMetrics = m
}

// checkNodeSourceLocked makes node_src_addr_table hold this node's source
// address, once per Sweep, while any VRF is installed. Otherwise only
// EnsureVRF sets it, so an address that could not be resolved then, with this
// node's BGPRouter still converging after a restart, stayed unset until the
// next new VPC or datapath reload, and nothing noticed another writer
// clearing it. Called with s.mu held.
func (s *Store) checkNodeSourceLocked(now time.Time) {
	installed := false
	for _, v := range s.vrfs {
		if v.installed {
			installed = true
			break
		}
	}
	if !installed {
		return
	}
	wrote, err := s.backend.EnsureNodeSourceAddress()
	s.nodeSourceMetrics.observe(now, wrote, err)
	// Logged on a change of status only, since a sweep repeats the check
	// every interval. The status series report it from then on.
	status := nodeSourceStatus(err)
	changed := status != s.nodeSourceStatus
	s.nodeSourceStatus = status
	switch {
	case status == NodeSourceUnconfigured:
		// No node name: ensureEgressDatapath already warns for every VRF.
	case err != nil && changed:
		slog.Warn("ingresssidecar: check this node's SRv6 source address; "+
			"egress encapsulation fails open until it is set", "status", status, "err", err)
	case wrote:
		slog.Info("ingresssidecar: restored this node's SRv6 source address in node_src_addr_table")
	}
}
