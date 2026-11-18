// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"slices"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/refusal"
)

// servedVersions are the API versions this Worker serves, oldest first.
var servedVersions = []string{workerv1alpha1.Version}

// Register registers the Worker service on s.
func (w *Worker) Register(s *grpc.Server) { workerv1alpha1.RegisterWorkerServer(s, w) }

// GetCapabilities implements workerv1alpha1.WorkerServer.
func (w *Worker) GetCapabilities(ctx context.Context, req *workerv1alpha1.GetCapabilitiesRequest) (
	*workerv1alpha1.GetCapabilitiesResponse, error) {
	caller, err := w.d.Auth.Authenticate(ctx)
	if err != nil {
		return nil, w.refuse(err)
	}
	version := ""
	for i := len(servedVersions) - 1; i >= 0 && version == ""; i-- {
		if slices.Contains(req.GetVersions(), servedVersions[i]) {
			version = servedVersions[i]
		}
	}
	if version == "" {
		return nil, w.refuse(refusal.New(codes.FailedPrecondition, workerv1alpha1.ReasonUnsupportedVersion,
			"no common API version", map[string]string{
				workerv1alpha1.MetadataServedVersions: strings.Join(servedVersions, ","),
			}))
	}
	id, err := w.openSession(ctx, caller)
	if err != nil {
		return nil, err
	}
	resp := &workerv1alpha1.GetCapabilitiesResponse{
		Version:       version,
		SessionId:     id,
		Lease:         durationpb.New(w.cfg.Lease),
		RenewInterval: durationpb.New(w.cfg.RenewInterval),
		Node:          w.cfg.Node,
	}
	for _, c := range w.d.Modules.Capabilities() {
		state := workerv1alpha1.CapabilityState_CAPABILITY_STATE_UNAVAILABLE
		if c.Available {
			state = workerv1alpha1.CapabilityState_CAPABILITY_STATE_AVAILABLE
		}
		resp.Capabilities = append(resp.Capabilities, &workerv1alpha1.Capability{
			Name: c.Name, State: state, Reason: c.Reason, Message: c.Message, Allowed: caller.Allowed(c.Name),
		})
	}
	return resp, nil
}

// Request implements workerv1alpha1.WorkerServer.
func (w *Worker) Request(ctx context.Context, req *workerv1alpha1.RequestRequest) (
	*workerv1alpha1.RequestResponse, error) {
	caller, err := w.begin(ctx)
	if err != nil {
		return nil, err
	}
	st, err := w.put(ctx, caller, req.GetKey(), req.GetGeneration(), req.GetSpec(), false)
	if err != nil {
		return nil, err
	}
	return &workerv1alpha1.RequestResponse{Status: st}, nil
}

// Update implements workerv1alpha1.WorkerServer.
func (w *Worker) Update(ctx context.Context, req *workerv1alpha1.UpdateRequest) (
	*workerv1alpha1.UpdateResponse, error) {
	caller, err := w.begin(ctx)
	if err != nil {
		return nil, err
	}
	st, err := w.put(ctx, caller, req.GetKey(), req.GetGeneration(), req.GetSpec(), true)
	if err != nil {
		return nil, err
	}
	return &workerv1alpha1.UpdateResponse{Status: st}, nil
}

// Release implements workerv1alpha1.WorkerServer.
func (w *Worker) Release(ctx context.Context, req *workerv1alpha1.ReleaseRequest) (
	*workerv1alpha1.ReleaseResponse, error) {
	caller, err := w.begin(ctx)
	if err != nil {
		return nil, err
	}
	st, err := w.release(caller, req.GetKey(), req.GetGeneration())
	if err != nil {
		return nil, err
	}
	return &workerv1alpha1.ReleaseResponse{Status: st}, nil
}

// Observe implements workerv1alpha1.WorkerServer.
func (w *Worker) Observe(req *workerv1alpha1.ObserveRequest,
	stream grpc.ServerStreamingServer[workerv1alpha1.ObserveResponse]) error {
	ctx := stream.Context()
	caller, err := w.begin(ctx)
	if err != nil {
		return err
	}
	sub := &subscriber{caller: caller.ServiceAccount, notify: make(chan struct{}, 1),
		pending: map[module.ClaimKey]*workerv1alpha1.ClaimStatus{}}
	if req.GetKey() != nil {
		k, err := w.validateKey(req.GetKey())
		if err != nil {
			return w.refuse(err)
		}
		sub.key = &k
	}
	w.mu.Lock()
	if sub.key != nil {
		if c := w.claims[*sub.key]; c != nil && c.rec.Owner != caller.ServiceAccount {
			w.mu.Unlock()
			return w.refuse(refusal.New(codes.PermissionDenied, workerv1alpha1.ReasonNotOwner,
				"another caller owns this claim", nil))
		}
	}
	for k, c := range w.claims {
		if sub.wants(c.rec.Owner, k) {
			sub.pending[k] = proto.Clone(c.status).(*workerv1alpha1.ClaimStatus)
		}
	}
	w.subs[sub] = struct{}{}
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		delete(w.subs, sub)
		w.mu.Unlock()
	}()
	if err := stream.SendHeader(metadata.MD{}); err != nil {
		return err
	}
	sub.notify <- struct{}{}

	renew := time.NewTicker(w.cfg.RenewInterval)
	defer renew.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-renew.C:
			// An open stream renews the session lease.
			if err := w.touchSession(ctx, caller); err != nil {
				return err
			}
		case <-sub.notify:
			w.mu.Lock()
			batch := make([]*workerv1alpha1.ClaimStatus, 0, len(sub.pending))
			for _, st := range sub.pending {
				batch = append(batch, st)
			}
			clear(sub.pending)
			w.mu.Unlock()
			sort.Slice(batch, func(i, j int) bool { return batch[i].GetRevision() < batch[j].GetRevision() })
			for _, st := range batch {
				if err := stream.Send(&workerv1alpha1.ObserveResponse{Status: st}); err != nil {
					return err
				}
			}
		}
	}
}
