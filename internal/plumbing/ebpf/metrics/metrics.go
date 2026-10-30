// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	instmetrics "go.miloapis.com/instrumentation/metrics"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/nldump"
)

// Metrics bundles this datapath's Prometheus instrumentation, created on the
// instrumentation library's registry, which the caller serves with that
// library's metrics.Handler.
type Metrics struct {
	Events *EventCounters
	// Egress is galactic-cni's egress shard group control-loop state.
	Egress *EgressControl
	// SidecarReturn is the ingress sidecar's host-side return path.
	SidecarReturn *SidecarReturn
	// EndpointSliceRepair counts the per-pod EndpointSlices galactic-cni's
	// repair pass recreated and the passes that failed.
	EndpointSliceRepair *EndpointSliceRepair
}

// New creates every series that does not read loaded eBPF objects. Call
// RegisterDatapathCollector once the datapath is loaded to also expose live map
// state. A process calls New once.
func New() *Metrics {
	return &Metrics{
		Events: NewEventCounters(), Egress: NewEgressControl(), SidecarReturn: NewSidecarReturn(),
		EndpointSliceRepair: NewEndpointSliceRepair(),
	}
}

// RegisterDatapathCollector registers a collector reading live map state from
// objs at every scrape. Call it once, after the datapath is loaded.
func (m *Metrics) RegisterDatapathCollector(objs *prog.UsidObjects) {
	instmetrics.MustRegister(NewCollectorFromObjects(objs))
}

// RegisterAttachmentCollector registers a collector reading each attachment's
// host-link byte counters at every scrape. Call it once.
func (m *Metrics) RegisterAttachmentCollector() {
	instmetrics.MustRegister(NewAttachmentCollector(nldump.LinkList))
}
