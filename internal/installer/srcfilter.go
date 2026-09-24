// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/vishvananda/netlink"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/srcfiltermap"
	"go.datum.net/galactic/internal/srcfilter"
)

// srcFilterResyncInterval paces the source filter's periodic full pass, which
// heals drift no netlink event reports. A var so tests can shrink it.
var srcFilterResyncInterval = 60 * time.Second

// srcFilterTopDenied is how many denied sources each periodic pass logs at
// debug level.
const srcFilterTopDenied = 5

// srcFilterHealthServiceName is the gRPC health service reporting whether the
// source filter's last pass succeeded. It is separate from
// ebpfHealthServiceName so a control-plane fault here never fails the
// datapath's own probes.
const srcFilterHealthServiceName = "srv6-source-filter"

// startSourceFilter configures the uSID datapath's SRv6 ingress source filter
// from the environment and, unless it is off, starts a goroutine that keeps its
// allow-list in step with this node's routes until ctx is canceled.
//
// A pass runs at startup, after every debounced re-evaluation of st.watcher,
// and every srcFilterResyncInterval, so the filter keeps being maintained if
// the watch loop dies. Mode off, or a configuration error, writes mode off and
// starts nothing; a configuration error also reports the health service not
// serving. A nil st.objs means no datapath is loaded, and nothing happens.
func startSourceFilter(ctx context.Context, st ebpfDatapathState, healthSrv *health.Server) {
	if st.objs == nil {
		return
	}
	filter := srcfiltermap.NewFromObjects(st.objs)
	target := srcfilter.USIDTarget{Filter: filter}

	settings, err := srcfilter.LoadSettings(os.Getenv)
	if err != nil {
		slog.Error("SRv6 source filter configuration is invalid; leaving the filter off", "err", err)
		healthSrv.SetServingStatus(srcFilterHealthServiceName, grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		disableSourceFilter(target)
		return
	}
	if settings.Mode == srcfilter.ModeOff {
		disableSourceFilter(target)
		return
	}

	r, err := srcfilter.New(srcfilter.Options{
		Settings:   settings,
		Target:     target,
		Routes:     srcfilter.MainTableRoutes,
		Links:      netlink.LinkList,
		Uplinks:    attach.ResolveInterfaces,
		OwnLocator: ownLocatorFn(st),
	})
	if err != nil {
		slog.Error("Could not start the SRv6 source filter reconciler; leaving the filter off", "err", err)
		healthSrv.SetServingStatus(srcFilterHealthServiceName, grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		disableSourceFilter(target)
		return
	}

	slog.Info("SRv6 source filter reconciler starting", "mode", settings.Mode.String(),
		"binding", settings.Binding.String(), "domainPrefixes", settings.DomainPrefixes,
		"extraSources", settings.ExtraSources)
	healthSrv.SetServingStatus(srcFilterHealthServiceName, grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	go runSourceFilter(ctx, r, filter, st.watcher, healthSrv)
}

// runSourceFilter drives r until ctx is canceled, publishing each pass's
// outcome on the health service.
func runSourceFilter(
	ctx context.Context, r *srcfilter.Reconciler, filter *srcfiltermap.Filter, w *attach.Watcher,
	healthSrv *health.Server,
) {
	ticker := time.NewTicker(srcFilterResyncInterval)
	defer ticker.Stop()

	var lastErr string
	pass := func() {
		lastErr = sourceFilterPass(ctx, r, healthSrv, lastErr)
	}

	pass()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.Reevaluated():
			pass()
		case <-ticker.C:
			pass()
			logTopDeniedSources(ctx, filter)
		}
	}
}

// sourceFilterPass runs one pass and reports it. lastErr is the previous
// pass's error text, empty after a success; a repeated failure logs at debug
// rather than error. It returns this pass's error text.
func sourceFilterPass(ctx context.Context, r *srcfilter.Reconciler, healthSrv *health.Server, lastErr string) string {
	res, err := r.Reconcile(ctx)
	if err != nil {
		healthSrv.SetServingStatus(srcFilterHealthServiceName, grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		level := slog.LevelError
		if err.Error() == lastErr {
			level = slog.LevelDebug
		}
		slog.Log(ctx, level, "SRv6 source filter pass failed; keeping the previous allow-list",
			"err", err, "populated", res.State.Populated)
		return err.Error()
	}

	healthSrv.SetServingStatus(srcFilterHealthServiceName, grpc_health_v1.HealthCheckResponse_SERVING)
	if lastErr != "" {
		slog.Info("SRv6 source filter pass recovered")
	}
	if res.Changed {
		slog.Info("SRv6 source filter allow-list updated", "entries", res.Entries, "added", res.Added,
			"updated", res.Updated, "removed", res.Removed, "unbound", res.Unbound, "uplinks", res.SlotCount,
			"mode", res.State.Mode.String(), "generation", res.State.Generation)
	}
	return ""
}

// ownLocatorFn returns the lookup for this node's own locator, or nil when no
// Kubernetes client is available, in which case the own locator is not
// excluded.
func ownLocatorFn(st ebpfDatapathState) func(context.Context) (netip.Prefix, error) {
	if st.k8sClient == nil {
		slog.Warn("SRv6 source filter cannot exclude this node's own locator: no Kubernetes client")
		return nil
	}
	return func(ctx context.Context) (netip.Prefix, error) {
		return nodeLocatorPrefix(ctx, st.k8sClient, st.namespace, st.nodeName)
	}
}

// disableSourceFilter writes mode off, logging a failure.
func disableSourceFilter(target srcfilter.Target) {
	if err := srcfilter.Disable(target); err != nil {
		slog.Error("Could not turn the SRv6 source filter off", "err", err)
	}
}

// logTopDeniedSources logs the most-denied sources at debug level, for triage
// without turning source addresses into metric labels.
func logTopDeniedSources(ctx context.Context, filter *srcfiltermap.Filter) {
	if !slog.Default().Enabled(ctx, slog.LevelDebug) {
		return
	}
	denied, err := filter.DeniedSources()
	if err != nil {
		slog.Debug("Could not read SRv6 source filter denials", "err", err)
		return
	}
	for _, d := range denied[:min(len(denied), srcFilterTopDenied)] {
		slog.Debug("SRv6 source filter denied source", "prefix", d.Prefix.String(), "count", d.Count,
			"lastIfindex", d.LastIfindex, "lastReason", d.LastReason.String())
	}
}
