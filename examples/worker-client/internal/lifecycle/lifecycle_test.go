// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package lifecycle

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/pkg/workerclient"
)

// fake is a contract-shaped Worker: sessions, generations and statuses, with
// no host state. The Galactic module's own test runs this client's binary
// against the real Worker.
type fake struct {
	workerv1alpha1.UnimplementedWorkerServer

	mu       sync.Mutex
	session  string
	claim    *workerv1alpha1.ClaimStatus
	hash     []byte
	revision uint64
	changed  chan struct{}
	calls    []string
}

func refuse(code codes.Code, reason string) error {
	st, _ := status.New(code, reason).WithDetails(&errdetails.ErrorInfo{
		Reason: reason, Domain: workerv1alpha1.ErrorDomain})
	return st.Err()
}

func (f *fake) check(ctx context.Context, needSession bool) error {
	md, _ := metadata.FromIncomingContext(ctx)
	if len(md.Get("authorization")) != 1 || md.Get("authorization")[0] != "Bearer test-token" {
		return refuse(codes.Unauthenticated, workerv1alpha1.ReasonNoIdentity)
	}
	if needSession {
		s := md.Get(workerv1alpha1.SessionMetadataKey)
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(s) != 1 || s[0] != f.session {
			return refuse(codes.FailedPrecondition, workerv1alpha1.ReasonNoSession)
		}
	}
	return nil
}

func (f *fake) GetCapabilities(ctx context.Context, _ *workerv1alpha1.GetCapabilitiesRequest) (
	*workerv1alpha1.GetCapabilitiesResponse, error) {
	if err := f.check(ctx, false); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.session = "s1"
	resp := &workerv1alpha1.GetCapabilitiesResponse{Version: workerv1alpha1.Version, SessionId: f.session,
		Lease: durationpb.New(2 * time.Minute), RenewInterval: durationpb.New(10 * time.Second)}
	for _, n := range workerv1alpha1.Capabilities {
		resp.Capabilities = append(resp.Capabilities, &workerv1alpha1.Capability{Name: n,
			State:   workerv1alpha1.CapabilityState_CAPABILITY_STATE_AVAILABLE,
			Allowed: n == workerv1alpha1.CapabilityLocalVethPair})
	}
	return resp, nil
}

func (f *fake) publish(st *workerv1alpha1.ClaimStatus) {
	f.revision++
	st.Revision = f.revision
	f.claim = st
	select {
	case f.changed <- struct{}{}:
	default:
	}
}

func (f *fake) Request(ctx context.Context, req *workerv1alpha1.RequestRequest) (
	*workerv1alpha1.RequestResponse, error) {
	if err := f.check(ctx, true); err != nil {
		return nil, err
	}
	if req.GetSpec().GetHandoff() != workerv1alpha1.Handoff_HANDOFF_VETH_PAIR {
		return nil, refuse(codes.PermissionDenied, workerv1alpha1.ReasonCapabilityNotAllowed)
	}
	h, _ := proto.Marshal(req.GetSpec())
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "request/"+strconv.FormatUint(req.GetGeneration(), 10))
	if f.claim != nil && !f.claim.GetReleased() {
		if f.claim.GetGeneration() == req.GetGeneration() && string(h) == string(f.hash) {
			return &workerv1alpha1.RequestResponse{Status: f.claim}, nil
		}
		return nil, refuse(codes.FailedPrecondition, workerv1alpha1.ReasonClaimExists)
	}
	f.hash = h
	f.publish(&workerv1alpha1.ClaimStatus{Key: req.GetKey(), Generation: req.GetGeneration(),
		ObservedGeneration: req.GetGeneration()})
	return &workerv1alpha1.RequestResponse{Status: f.claim}, nil
}

func (f *fake) Update(ctx context.Context, req *workerv1alpha1.UpdateRequest) (*workerv1alpha1.UpdateResponse, error) {
	if err := f.check(ctx, true); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "update/"+strconv.FormatUint(req.GetGeneration(), 10))
	f.publish(&workerv1alpha1.ClaimStatus{Key: req.GetKey(), Generation: req.GetGeneration(),
		ObservedGeneration: req.GetGeneration()})
	return &workerv1alpha1.UpdateResponse{Status: f.claim}, nil
}

func (f *fake) Release(ctx context.Context, req *workerv1alpha1.ReleaseRequest) (
	*workerv1alpha1.ReleaseResponse, error) {
	if err := f.check(ctx, true); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "release/"+strconv.FormatUint(req.GetGeneration(), 10))
	switch {
	case f.claim == nil || f.claim.GetReleased():
		return &workerv1alpha1.ReleaseResponse{}, nil
	case req.GetGeneration() < f.claim.GetGeneration():
		return nil, refuse(codes.Aborted, workerv1alpha1.ReasonStaleGeneration)
	}
	f.publish(&workerv1alpha1.ClaimStatus{Key: req.GetKey(), Generation: req.GetGeneration(),
		ObservedGeneration: req.GetGeneration(), Released: true})
	return &workerv1alpha1.ReleaseResponse{Status: f.claim}, nil
}

func (f *fake) Observe(_ *workerv1alpha1.ObserveRequest,
	s grpc.ServerStreamingServer[workerv1alpha1.ObserveResponse]) error {
	if err := f.check(s.Context(), true); err != nil {
		return err
	}
	if err := s.SendHeader(metadata.MD{}); err != nil {
		return err
	}
	var sent uint64
	for {
		f.mu.Lock()
		st := f.claim
		f.mu.Unlock()
		if st != nil && st.GetRevision() > sent {
			sent = st.GetRevision()
			// Send every snapshot twice: the client drops the duplicate.
			for range 2 {
				if err := s.Send(&workerv1alpha1.ObserveResponse{Status: st}); err != nil {
					return err
				}
			}
			continue
		}
		select {
		case <-s.Context().Done():
			return nil
		case <-f.changed:
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func TestLifecycleAgainstContractFake(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "w.sock")
	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	f := &fake{changed: make(chan struct{}, 1)}
	srv := grpc.NewServer()
	workerv1alpha1.RegisterWorkerServer(srv, f)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := workerclient.Dial(ctx, workerclient.Options{SocketPath: sock,
		Token: func() (string, error) { return "test-token", nil }, RetryMin: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	p := Plan{
		Key:                &workerv1alpha1.ClaimKey{Node: "node-a", Vpc: "vpcA", AttachmentUid: "att-1"},
		Handoff:            workerv1alpha1.Handoff_HANDOFF_VETH_PAIR,
		Destinations:       []string{"dst-1"},
		UpdateDestinations: []string{"dst-1", "dst-2"},
		Forbidden:          workerv1alpha1.Handoff_HANDOFF_TAP,
	}
	if err := Run(ctx, c, p, t.Logf); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	want := []string{"request/1", "request/1", "update/2", "release/1", "release/2", "release/2"}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != len(want) {
		t.Fatalf("calls = %v, want %v", f.calls, want)
	}
	for i := range want {
		if f.calls[i] != want[i] {
			t.Fatalf("calls = %v, want %v", f.calls, want)
		}
	}
}

func TestCheckCapabilitiesRefusesWrongPrivileges(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "w.sock")
	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	workerv1alpha1.RegisterWorkerServer(srv, &fake{changed: make(chan struct{}, 1)})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	c, err := workerclient.Dial(context.Background(), workerclient.Options{SocketPath: sock,
		Token: func() (string, error) { return "test-token", nil }, NoKeepAlive: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// The fake allows only veth_pair; a plan that needs tap must fail before
	// any call.
	if err := CheckCapabilities(c, Plan{Handoff: workerv1alpha1.Handoff_HANDOFF_TAP}); err == nil {
		t.Fatal("CheckCapabilities() = nil, want an error for a capability the caller lacks")
	}
	if err := CheckCapabilities(c, Plan{Handoff: workerv1alpha1.Handoff_HANDOFF_VETH_PAIR,
		Forbidden: workerv1alpha1.Handoff_HANDOFF_VETH_PAIR}); err == nil {
		t.Fatal("CheckCapabilities() = nil, want an error when the forbidden capability is allowed")
	}
}
