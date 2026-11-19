// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/refusal"
	"go.datum.net/galactic/internal/worker/routes"
)

// routesServer serves the Routes service, which records the tenant routes
// galactic-router hands Worker.
type routesServer struct {
	workerv1alpha1.UnimplementedRoutesServer
	w *Worker
}

// Sync implements workerv1alpha1.RoutesServer. It refuses a caller not
// allowed fabric.routes, records each request's routes, requeues the VPCs
// they change and answers with the routes it rejected. The open stream
// renews the caller's session.
func (s *routesServer) Sync(stream grpc.BidiStreamingServer[workerv1alpha1.RoutesSyncRequest,
	workerv1alpha1.RoutesSyncResponse]) error {
	w := s.w
	ctx := stream.Context()
	caller, err := w.begin(ctx)
	if err != nil {
		return err
	}
	if !caller.Allowed(workerv1alpha1.CapabilityFabricRoutes) {
		return w.refuse(refusal.New(codes.PermissionDenied, workerv1alpha1.ReasonCapabilityNotAllowed,
			caller.ServiceAccount+" may not use "+workerv1alpha1.CapabilityFabricRoutes, nil))
	}
	if w.d.Routes == nil {
		return w.refuse(refusal.New(codes.Unavailable, workerv1alpha1.ReasonModuleNotRunning,
			"no running module serves "+workerv1alpha1.CapabilityFabricRoutes, nil))
	}
	if w.shutting.Load() {
		return w.refuse(errShuttingDown())
	}
	if err := stream.SendHeader(metadata.MD{}); err != nil {
		return err
	}

	reqs := make(chan *workerv1alpha1.RoutesSyncRequest)
	recvErr := make(chan error, 1)
	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case reqs <- req:
			case <-ctx.Done():
				return
			}
		}
	}()

	renew := time.NewTicker(w.cfg.RenewInterval)
	defer renew.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-recvErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case <-renew.C:
			if err := w.touchSession(ctx, caller); err != nil {
				return err
			}
		case req := <-reqs:
			if err := stream.Send(s.record(req)); err != nil {
				return err
			}
		}
	}
}

// record parses one request, records the routes that parse and requeues the
// VPCs they change.
func (s *routesServer) record(req *workerv1alpha1.RoutesSyncRequest) *workerv1alpha1.RoutesSyncResponse {
	resp := &workerv1alpha1.RoutesSyncResponse{Sequence: req.GetSequence()}
	reject := func(k *workerv1alpha1.TenantRouteKey, err error) {
		resp.Rejected = append(resp.Rejected, &workerv1alpha1.RejectedRoute{
			Key: k, Reason: workerv1alpha1.ReasonMalformedRoute, Message: err.Error(),
		})
	}
	var upserts []routes.Route
	for _, r := range req.GetUpserts() {
		key := &workerv1alpha1.TenantRouteKey{Vpc: r.GetVpc(), Prefix: r.GetPrefix()}
		route, err := parseRoute(r)
		if err != nil {
			reject(key, err)
			continue
		}
		upserts = append(upserts, route)
	}
	var withdrawals []routes.Key
	for _, k := range req.GetWithdrawals() {
		key, err := parseRouteKey(k.GetVpc(), k.GetPrefix())
		if err != nil {
			reject(k, err)
			continue
		}
		withdrawals = append(withdrawals, key)
	}
	for _, vpc := range s.w.d.Routes.Apply(upserts, withdrawals) {
		s.w.RoutesChanged(vpc)
	}
	return resp
}

func parseRouteKey(vpc, prefix string) (routes.Key, error) {
	if vpc == "" {
		return routes.Key{}, errors.New("vpc is empty")
	}
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return routes.Key{}, fmt.Errorf("prefix: %w", err)
	}
	return routes.Key{VPC: vpc, Prefix: p.Masked()}, nil
}

func parseRoute(r *workerv1alpha1.TenantRoute) (routes.Route, error) {
	key, err := parseRouteKey(r.GetVpc(), r.GetPrefix())
	if err != nil {
		return routes.Route{}, err
	}
	if r.GetTableId() == 0 {
		return routes.Route{}, errors.New("table_id is 0")
	}
	sid, err := netip.ParseAddr(r.GetSid())
	if err != nil {
		return routes.Route{}, fmt.Errorf("sid: %w", err)
	}
	if !sid.Is6() || sid.Is4In6() || sid.IsUnspecified() {
		return routes.Route{}, fmt.Errorf("sid %s is not a specified IPv6 address", sid)
	}
	return routes.Route{Key: key, TableID: r.GetTableId(), SID: sid}, nil
}
