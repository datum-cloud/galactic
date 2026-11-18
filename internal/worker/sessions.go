// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/auth"
	"go.datum.net/galactic/internal/worker/refusal"
	"go.datum.net/galactic/internal/worker/store"
)

// session is one client session. The caller, not the session, owns claims:
// a client that restarts opens a new session and keeps its claims.
type session struct {
	id      string
	caller  string
	expires time.Time
}

func sessionID(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx)
	if v := md.Get(workerv1alpha1.SessionMetadataKey); len(v) == 1 {
		return v[0]
	}
	return ""
}

// openSession renews the live session the call names, or starts a new one.
func (w *Worker) openSession(ctx context.Context, caller auth.Caller) (string, error) {
	now := w.d.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	if id := sessionID(ctx); id != "" {
		if s, ok := w.sessions[id]; ok && s.caller == caller.ServiceAccount && now.Before(s.expires) {
			s.expires = now.Add(w.cfg.Lease)
			w.lastSeen[caller.ServiceAccount] = now
			return id, nil
		}
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", refusal.New(codes.Unavailable, workerv1alpha1.ReasonShuttingDown, "cannot create a session ID", nil)
	}
	id := hex.EncodeToString(b)
	w.sessions[id] = &session{id: id, caller: caller.ServiceAccount, expires: now.Add(w.cfg.Lease)}
	w.lastSeen[caller.ServiceAccount] = now
	setSessions(len(w.sessions))
	return id, nil
}

// touchSession renews the session the call names, which must be a live
// session of caller.
func (w *Worker) touchSession(ctx context.Context, caller auth.Caller) error {
	id := sessionID(ctx)
	now := w.d.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	s, ok := w.sessions[id]
	if id == "" || !ok || s.caller != caller.ServiceAccount || !now.Before(s.expires) {
		return refusal.New(codes.FailedPrecondition, workerv1alpha1.ReasonNoSession,
			"no live session; call GetCapabilities and send its session ID in "+workerv1alpha1.SessionMetadataKey, nil)
	}
	s.expires = now.Add(w.cfg.Lease)
	w.lastSeen[caller.ServiceAccount] = now
	return nil
}

// begin authenticates a call other than GetCapabilities and renews its
// session.
func (w *Worker) begin(ctx context.Context) (auth.Caller, error) {
	caller, err := w.d.Auth.Authenticate(ctx)
	if err != nil {
		countRefusal(refusal.Reason(err))
		return auth.Caller{}, err
	}
	if err := w.touchSession(ctx, caller); err != nil {
		countRefusal(workerv1alpha1.ReasonNoSession)
		return auth.Caller{}, err
	}
	return caller, nil
}

// ExpireLeases withdraws every claim of a caller that has had no live
// session for a lease, with scope "every claim of the caller", and drops
// expired sessions. The lease checker calls it every renew interval.
func (w *Worker) ExpireLeases() {
	now := w.d.Now()
	w.mu.Lock()
	for id, s := range w.sessions {
		if !now.Before(s.expires) {
			delete(w.sessions, id)
		}
	}
	setSessions(len(w.sessions))
	live := map[string]bool{}
	for _, s := range w.sessions {
		live[s.caller] = true
	}
	var expired []keyGen
	for k, c := range w.claims {
		if c.rec.Releasing || live[c.rec.Owner] {
			continue
		}
		if seen, ok := w.lastSeen[c.rec.Owner]; ok && now.Sub(seen) < w.cfg.Lease {
			continue
		}
		expired = append(expired, keyGen{k, c.rec.Generation})
	}
	w.mu.Unlock()
	for _, e := range expired {
		// A failed write is retried at the next check.
		if err := w.withdraw(e.key, e.gen, store.WithdrawCaller, workerv1alpha1.ReasonLeaseExpired); err != nil {
			w.log.Error("withdraw claims of an expired caller", "owner", e.key.String(), "error", err)
		}
	}
}
