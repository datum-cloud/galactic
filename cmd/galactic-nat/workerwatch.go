// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/labels"
	"go.miloapis.com/instrumentation/metrics"
	"k8s.io/apimachinery/pkg/api/meta"
	toolscache "k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/natattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/natmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

// ownShard returns this node's EgressShard once its datapath is programmed
// with it: exactly one shard targets the node, it is not being deleted, and
// it reports a SID and Programmed=True. Anything else claims nothing.
func ownShard(shards []bgpv1alpha1.EgressShard, node string) shardIdentity {
	var mine []bgpv1alpha1.EgressShard
	for _, s := range shards {
		if s.Spec.TargetRef.Name == node && s.DeletionTimestamp.IsZero() {
			mine = append(mine, s)
		}
	}
	if len(mine) != 1 {
		return shardIdentity{}
	}
	s := mine[0]
	if s.Status.ShardSID == "" ||
		!meta.IsStatusConditionTrue(s.Status.Conditions, bgpv1alpha1.ConditionTypeProgrammed) {
		return shardIdentity{}
	}
	return shardIdentity{Name: s.Name, UID: string(s.UID)}
}

// nodeVPCs returns the VPCs with a VPCAttachment on node that is not being
// deleted and records its VPC.
func nodeVPCs(attachments []cloudv1alpha1.VPCAttachment, node string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range attachments {
		if a.Status.Node != node || !a.DeletionTimestamp.IsZero() || a.Status.VPC == "" || seen[a.Status.VPC] {
			continue
		}
		seen[a.Status.VPC] = true
		out = append(out, a.Status.VPC)
	}
	return out
}

// watchWorkerSources feeds w its shard and VPCs from the manager's cache,
// on every EgressShard or VPCAttachment change and every minute.
func watchWorkerSources(ctx context.Context, c cache.Cache, reader client.Reader, node string, w *natWorker) error {
	changed := make(chan struct{}, 1)
	poke := func(any) {
		select {
		case changed <- struct{}{}:
		default:
		}
	}
	for _, obj := range []client.Object{&bgpv1alpha1.EgressShard{}, &cloudv1alpha1.VPCAttachment{}} {
		inf, err := c.GetInformer(ctx, obj)
		if err != nil {
			return fmt.Errorf("informer for %T: %w", obj, err)
		}
		if _, err := inf.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
			AddFunc: poke, UpdateFunc: func(_, n any) { poke(n) }, DeleteFunc: poke,
		}); err != nil {
			return fmt.Errorf("handler for %T: %w", obj, err)
		}
	}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-changed:
			case <-t.C:
			}
			var shards bgpv1alpha1.EgressShardList
			if err := reader.List(ctx, &shards); err != nil {
				slog.Warn("Cannot list EgressShards for local shard delivery", "err", err)
				continue
			}
			var atts cloudv1alpha1.VPCAttachmentList
			if err := reader.List(ctx, &atts); err != nil {
				slog.Warn("Cannot list VPCAttachments for local shard delivery", "err", err)
				continue
			}
			w.SetShard(ownShard(shards.Items, node))
			w.SetVPCs(nodeVPCs(atts.Items, node))
		}
	}()
	poke(nil)
	return nil
}

const (
	labelCapability = "capability"
	labelVPC        = "vpc"
	labelStat       = "stat"
)

var (
	workerSessionDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "worker", "session_up"),
		"1 while this shard holds a Galactic Worker session, 0 while it cannot open one, so no VPC on this "+
			"node is served through its local pair.",
		nil, nil,
	)
	workerCapabilityDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "worker", "capability_available"),
		"1 for each Galactic Worker capability available to this shard, 0 for one that is not, with "+
			"Worker's reason. Absent while there is no session.",
		[]string{labelCapability, labels.Reason}, nil,
	)
	localHandoffReadyDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "local", "handoff_ready"),
		"1 for each VPC on this node whose local pair Worker reports Ready, so its tenants may use this "+
			"shard through it, 0 otherwise, with the claim's reason.",
		[]string{labelVPC, labels.Reason}, nil,
	)
	localPacketsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "local", "packets_total"),
		"Packets through local pairs: forward (translated from a pair), return (sent back into one), "+
			"return_no_pair (a reply whose pair could not be reached) and forward_unclaimed (dropped from a "+
			"pair untranslated).",
		[]string{labelStat}, nil,
	)
)

// workerCollector reports the Worker integration's state at every scrape.
type workerCollector struct {
	worker *natWorker
	stats  natmap.CounterReader
}

// Describe implements prometheus.Collector.
func (c *workerCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- workerSessionDesc
	ch <- workerCapabilityDesc
	ch <- localHandoffReadyDesc
	ch <- localPacketsDesc
}

// Collect implements prometheus.Collector.
func (c *workerCollector) Collect(ch chan<- prometheus.Metric) {
	snap := c.worker.snapshot()
	ch <- prometheus.MustNewConstMetric(workerSessionDesc, prometheus.GaugeValue, boolValue(snap.SessionUp))
	for _, cp := range snap.Capabilities {
		ok := cp.GetState() == workerv1alpha1.CapabilityState_CAPABILITY_STATE_AVAILABLE && cp.GetAllowed()
		reason := cp.GetReason()
		if !cp.GetAllowed() {
			reason = workerv1alpha1.ReasonCapabilityNotAllowed
		}
		ch <- prometheus.MustNewConstMetric(workerCapabilityDesc, prometheus.GaugeValue, boolValue(ok),
			cp.GetName(), reason)
	}
	for vpc, r := range snap.VPCs {
		ch <- prometheus.MustNewConstMetric(localHandoffReadyDesc, prometheus.GaugeValue, boolValue(r.Ready),
			vpc, r.Reason)
	}
	if c.stats == nil {
		return
	}
	totals, err := natmap.LocalStatTotals(c.stats)
	if err != nil {
		return
	}
	for i, v := range totals {
		ch <- prometheus.MustNewConstMetric(localPacketsDesc, prometheus.CounterValue, float64(v),
			natprog.LocalStat(i).String()) //nolint:gosec // a small index
	}
}

// startLocalDelivery starts serving this node's tenants through their VPCs'
// local pairs: it claims a pair per VPC from Galactic Worker and attaches the
// loaded datapath to each.
func startLocalDelivery(ctx context.Context, cfg *config.NATConfig, mgr ctrl.Manager) error {
	plumb, err := loadedLocal()
	if err != nil {
		return err
	}
	w := newNATWorker(cfg.NodeName, workerclientDial(cfg.WorkerSocket, cfg.WorkerTokenFile), plumb)
	metrics.MustRegister(&workerCollector{worker: w, stats: natDatapathKeepAlive.objs.NatLocalStats})
	if err := watchWorkerSources(ctx, mgr.GetCache(), mgr.GetClient(), cfg.NodeName, w); err != nil {
		return err
	}
	go w.Run(ctx)
	slog.Info("Local shard delivery through Galactic Worker is on", "socket", cfg.WorkerSocket)
	return nil
}

// loadedLocal returns the Local plumbing over the datapath this process
// loaded.
func loadedLocal() (*kernelLocal, error) {
	objs := natDatapathKeepAlive.objs
	if objs == nil {
		return nil, errors.New("the datapath is not loaded")
	}
	return newKernelLocal(objs.NatIngress, natattach.PinDir,
		natmap.LocalTables{Pair: natmap.KernelTable{Map: objs.NatLocalPair},
			Return: natmap.KernelTable{Map: objs.NatLocalReturn}},
		natmap.VLANTable{Table: natmap.KernelTable{Map: objs.NatVlanEgress}})
}

// openLocalPlumbing opens the Local state to prune on a start with the Worker
// integration off: through the loaded datapath when there is one, otherwise
// from what a previous process pinned.
func openLocalPlumbing(cfg *config.NATConfig) (localPlumbing, func(), error) {
	if cfg.DatapathEnabled {
		plumb, err := loadedLocal()
		return plumb, func() {}, err
	}
	return openPinnedLocal(natattach.PinDir)
}

// settleLocalDelivery runs start when cfg turns the Worker integration on.
// Otherwise it prunes every Local pin and row a previous process left, so
// a pair that still exists stops translating now rather than when Worker
// withdraws its claim at session-lease expiry.
//
// A failure to prune is logged, not returned, like turnOffDatapath's: a
// crash-looping process would not remove the state either, and Worker
// deletes the pairs once their claims lapse.
func settleLocalDelivery(cfg *config.NATConfig, start func() error,
	open func() (localPlumbing, func(), error),
) error {
	if cfg.WorkerSocket != "" && cfg.DatapathEnabled {
		return start()
	}
	plumb, closeFn, err := open()
	if err != nil {
		slog.Error("Cannot open the Local pair state to remove it; "+
			"Local pairs keep translating until Worker withdraws their claims", "err", err)
		return nil
	}
	defer closeFn()
	if err := plumb.Prune(nil); err != nil {
		slog.Error("Cannot remove the Local pair state; "+
			"Local pairs keep translating until Worker withdraws their claims", "err", err)
		return nil
	}
	slog.Info("Local shard delivery is off; removed any Local pair links and rows left by a previous process")
	return nil
}
