// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package workerclient is the client library of Galactic Worker's service
// API (docs/worker/contract.md). It is part of the published interface: it
// imports only the API package and gRPC, never Galactic internals.
//
// A Client dials Worker's unix socket, negotiates the API version and opens
// a session with GetCapabilities, and keeps that session alive. Every call
// carries the caller's projected ServiceAccount token, read again for each
// call because the kubelet rotates it. Calls that the contract says to retry
// (UNAVAILABLE, RESOURCE_EXHAUSTED, an expired identity or a lost session)
// are retried with exponential backoff from 200 ms to 30 s with full jitter.
package workerclient

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
)

// DefaultTokenFile is where a pod mounts its projected Worker token by
// convention.
const DefaultTokenFile = "/var/run/secrets/galactic-worker/token"

// Options configure a Client.
type Options struct {
	// SocketPath is Worker's socket, workerv1alpha1.DefaultSocketPath when
	// empty.
	SocketPath string
	// TokenFile is the projected token, DefaultTokenFile when empty and
	// Token is nil.
	TokenFile string
	// Token returns the bearer token for a call. It overrides TokenFile.
	Token func() (string, error)
	// Versions are the API versions the client supports, newest last.
	Versions []string
	// RetryMin, RetryMax and Attempts bound retries: 200 ms, 30 s and 8 by
	// default.
	RetryMin time.Duration
	RetryMax time.Duration
	Attempts int
	// NoKeepAlive disables the background session renewal. A client that
	// keeps an Observe stream open does not need it.
	NoKeepAlive bool
}

// Client is a Worker client.
type Client struct {
	opts   Options
	cc     *grpc.ClientConn
	api    workerv1alpha1.WorkerClient
	routes workerv1alpha1.RoutesClient

	mu      sync.Mutex
	session string
	caps    *workerv1alpha1.GetCapabilitiesResponse

	stop chan struct{}
	done sync.WaitGroup
}

// Dial connects to Worker and opens a session.
func Dial(ctx context.Context, opts Options) (*Client, error) {
	if opts.SocketPath == "" {
		opts.SocketPath = workerv1alpha1.DefaultSocketPath
	}
	if opts.Token == nil {
		file := opts.TokenFile
		if file == "" {
			file = DefaultTokenFile
		}
		opts.Token = func() (string, error) {
			b, err := os.ReadFile(file)
			if err != nil {
				return "", err
			}
			return strings.TrimSpace(string(b)), nil
		}
	}
	if len(opts.Versions) == 0 {
		opts.Versions = []string{workerv1alpha1.Version}
	}
	if opts.RetryMin == 0 {
		opts.RetryMin = 200 * time.Millisecond
	}
	if opts.RetryMax == 0 {
		opts.RetryMax = 30 * time.Second
	}
	if opts.Attempts == 0 {
		opts.Attempts = 8
	}
	socket := opts.SocketPath
	cc, err := grpc.NewClient("passthrough:///galactic-worker",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}))
	if err != nil {
		return nil, fmt.Errorf("workerclient: %w", err)
	}
	c := &Client{opts: opts, cc: cc, api: workerv1alpha1.NewWorkerClient(cc),
		routes: workerv1alpha1.NewRoutesClient(cc), stop: make(chan struct{})}
	if err := c.openSession(ctx, false); err != nil {
		_ = cc.Close()
		return nil, err
	}
	if !opts.NoKeepAlive {
		c.done.Add(1)
		go c.keepAlive()
	}
	return c, nil
}

// Close stops the session renewal and closes the connection. Claims stay:
// they belong to the caller's identity, and a client that reconnects within
// the lease finds them unchanged.
func (c *Client) Close() error {
	close(c.stop)
	c.done.Wait()
	return c.cc.Close()
}

// Capabilities returns the latest GetCapabilities response.
func (c *Client) Capabilities() *workerv1alpha1.GetCapabilitiesResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.caps
}

// Session returns the current session ID.
func (c *Client) Session() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session
}

// Request creates a claim.
func (c *Client) Request(ctx context.Context, key *workerv1alpha1.ClaimKey, generation uint64,
	spec *workerv1alpha1.ClaimSpec) (*workerv1alpha1.ClaimStatus, error) {
	var out *workerv1alpha1.ClaimStatus
	err := c.retry(ctx, func(ctx context.Context) error {
		r, err := c.api.Request(ctx, &workerv1alpha1.RequestRequest{Key: key, Generation: generation, Spec: spec})
		out = r.GetStatus()
		return err
	})
	return out, err
}

// Update replaces a claim's spec.
func (c *Client) Update(ctx context.Context, key *workerv1alpha1.ClaimKey, generation uint64,
	spec *workerv1alpha1.ClaimSpec) (*workerv1alpha1.ClaimStatus, error) {
	var out *workerv1alpha1.ClaimStatus
	err := c.retry(ctx, func(ctx context.Context) error {
		r, err := c.api.Update(ctx, &workerv1alpha1.UpdateRequest{Key: key, Generation: generation, Spec: spec})
		out = r.GetStatus()
		return err
	})
	return out, err
}

// Release removes a claim at its current generation. It returns nil status
// when no such claim exists.
func (c *Client) Release(ctx context.Context, key *workerv1alpha1.ClaimKey, generation uint64) (
	*workerv1alpha1.ClaimStatus, error) {
	var out *workerv1alpha1.ClaimStatus
	err := c.retry(ctx, func(ctx context.Context) error {
		r, err := c.api.Release(ctx, &workerv1alpha1.ReleaseRequest{Key: key, Generation: generation})
		out = r.GetStatus()
		return err
	})
	return out, err
}

// Observer receives status snapshots.
type Observer struct {
	stream grpc.ServerStreamingClient[workerv1alpha1.ObserveResponse]
	last   map[string]uint64
}

// Recv returns the next snapshot, dropping duplicates and reorderings.
func (o *Observer) Recv() (*workerv1alpha1.ClaimStatus, error) {
	for {
		r, err := o.stream.Recv()
		if err != nil {
			return nil, err
		}
		st := r.GetStatus()
		k := st.GetKey()
		id := k.GetNode() + "/" + k.GetVpc() + "/" + k.GetAttachmentUid()
		if st.GetRevision() <= o.last[id] {
			continue
		}
		o.last[id] = st.GetRevision()
		return st, nil
	}
}

// Observe opens a status stream for key, or for every claim of the caller
// when key is nil. Cancel ctx to close it.
func (c *Client) Observe(ctx context.Context, key *workerv1alpha1.ClaimKey) (*Observer, error) {
	var stream grpc.ServerStreamingClient[workerv1alpha1.ObserveResponse]
	err := c.retry(ctx, func(ctx context.Context) error {
		s, err := c.api.Observe(ctx, &workerv1alpha1.ObserveRequest{Key: key})
		if err != nil {
			return err
		}
		// Worker sends headers once it admits the stream. A stream that
		// ends without them was refused; Recv returns the refusal so it is
		// retried like any other call.
		md, err := s.Header()
		if err != nil {
			return err
		}
		if md == nil {
			if _, err := s.Recv(); err != nil {
				return err
			}
			return errors.New("workerclient: Observe stream ended without headers")
		}
		stream = s
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &Observer{stream: stream, last: map[string]uint64{}}, nil
}

// RouteStream is an open Routes.Sync stream.
type RouteStream = grpc.BidiStreamingClient[workerv1alpha1.RoutesSyncRequest, workerv1alpha1.RoutesSyncResponse]

// SyncRoutes opens a Routes.Sync stream, which hands Worker tenant routes.
// Only a caller allowed fabric.routes may open one. Cancel ctx to close it.
func (c *Client) SyncRoutes(ctx context.Context) (RouteStream, error) {
	var stream RouteStream
	err := c.retry(ctx, func(ctx context.Context) error {
		s, err := c.routes.Sync(ctx)
		if err != nil {
			return err
		}
		// Worker sends headers once it admits the stream; a stream that
		// ends without them was refused.
		md, err := s.Header()
		if err != nil {
			return err
		}
		if md == nil {
			if _, err := s.Recv(); err != nil {
				return err
			}
			return errors.New("workerclient: Routes.Sync stream ended without headers")
		}
		stream = s
		return nil
	})
	if err != nil {
		return nil, err
	}
	return stream, nil
}

// Reason returns the contract reason of a Worker error, or "".
func Reason(err error) string {
	st, ok := status.FromError(err)
	if !ok {
		return ""
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetDomain() == workerv1alpha1.ErrorDomain {
			return info.GetReason()
		}
	}
	return ""
}

// Retryable reports whether the contract says to retry err with backoff.
func Retryable(err error) bool {
	switch status.Code(err) {
	case codes.Unavailable, codes.ResourceExhausted:
		return true
	case codes.Unauthenticated:
		return Reason(err) == workerv1alpha1.ReasonIdentityExpired
	}
	return false
}

func (c *Client) callContext(ctx context.Context, withSession bool) (context.Context, error) {
	token, err := c.opts.Token()
	if err != nil {
		return nil, fmt.Errorf("workerclient: read token: %w", err)
	}
	pairs := []string{"authorization", "Bearer " + token}
	if withSession {
		if s := c.Session(); s != "" {
			pairs = append(pairs, workerv1alpha1.SessionMetadataKey, s)
		}
	}
	return metadata.AppendToOutgoingContext(ctx, pairs...), nil
}

// openSession calls GetCapabilities, renewing the current session when
// renew is set.
func (c *Client) openSession(ctx context.Context, renew bool) error {
	cctx, err := c.callContext(ctx, renew)
	if err != nil {
		return err
	}
	resp, err := c.api.GetCapabilities(cctx, &workerv1alpha1.GetCapabilitiesRequest{Versions: c.opts.Versions})
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.session, c.caps = resp.GetSessionId(), resp
	c.mu.Unlock()
	return nil
}

func (c *Client) keepAlive() {
	defer c.done.Done()
	interval := c.Capabilities().GetRenewInterval().AsDuration()
	if interval <= 0 {
		interval = 10 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), interval)
			_ = c.openSession(ctx, true)
			cancel()
		}
	}
}

// retry runs call, retrying as the contract says.
func (c *Client) retry(ctx context.Context, call func(context.Context) error) error {
	var err error
	for attempt := range c.opts.Attempts {
		var cctx context.Context
		if cctx, err = c.callContext(ctx, true); err != nil {
			return err
		}
		err = call(cctx)
		if err == nil {
			return nil
		}
		if Reason(err) == workerv1alpha1.ReasonNoSession {
			if serr := c.openSession(ctx, false); serr != nil {
				err = errors.Join(err, serr)
			}
			continue
		}
		if !Retryable(err) {
			return err
		}
		ceiling := min(c.opts.RetryMin<<attempt, c.opts.RetryMax)
		wait := time.Duration(rand.Int64N(int64(ceiling) + 1))
		select {
		case <-ctx.Done():
			return errors.Join(err, ctx.Err())
		case <-time.After(wait):
		}
	}
	return err
}
