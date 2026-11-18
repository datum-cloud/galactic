// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package lifecycle drives one claim through the documented Worker
// interface: request, observe, update, observe, release, observe the
// release. It also checks that a capability the caller is not allowed is
// refused, so the client proves it works with only its advertised
// privileges.
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"io"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/pkg/workerclient"
)

// Plan is one lifecycle run.
type Plan struct {
	Key *workerv1alpha1.ClaimKey
	// Handoff is the claim's handoff; its capability must be allowed.
	Handoff workerv1alpha1.Handoff
	// Destinations and UpdateDestinations are attachment UIDs for the
	// request and the update.
	Destinations       []string
	UpdateDestinations []string
	// Forbidden, when set, is a handoff whose capability the caller is not
	// allowed. Requesting it must be refused with CapabilityNotAllowed.
	Forbidden workerv1alpha1.Handoff
}

// Logf reports progress.
type Logf func(format string, args ...any)

func spec(h workerv1alpha1.Handoff, uids []string) *workerv1alpha1.ClaimSpec {
	s := &workerv1alpha1.ClaimSpec{Handoff: h, Mode: workerv1alpha1.Mode_MODE_AUTO}
	for _, u := range uids {
		s.Destinations = append(s.Destinations, &workerv1alpha1.Destination{
			Target: &workerv1alpha1.Destination_Attachment{Attachment: &workerv1alpha1.AttachmentRef{Uid: u}},
		})
	}
	return s
}

// CheckCapabilities verifies the session's version and that the plan's
// handoff is allowed and the forbidden one is not, as GetCapabilities
// reports them.
func CheckCapabilities(c *workerclient.Client, p Plan) error {
	caps := c.Capabilities()
	if caps.GetVersion() != workerv1alpha1.Version {
		return fmt.Errorf("negotiated version %q, want %q", caps.GetVersion(), workerv1alpha1.Version)
	}
	allowed := map[string]bool{}
	for _, cp := range caps.GetCapabilities() {
		allowed[cp.GetName()] = cp.GetAllowed()
	}
	if name := workerv1alpha1.HandoffCapability(p.Handoff); !allowed[name] {
		return fmt.Errorf("capability %s is not allowed for this caller", name)
	}
	if p.Forbidden != workerv1alpha1.Handoff_HANDOFF_UNSPECIFIED {
		if name := workerv1alpha1.HandoffCapability(p.Forbidden); allowed[name] {
			return fmt.Errorf("capability %s is allowed, but the plan expects it refused", name)
		}
	}
	return nil
}

// Run drives the lifecycle and returns the first deviation from the
// contract.
func Run(ctx context.Context, c *workerclient.Client, p Plan, logf Logf) error {
	if err := CheckCapabilities(c, p); err != nil {
		return err
	}
	if p.Forbidden != workerv1alpha1.Handoff_HANDOFF_UNSPECIFIED {
		_, err := c.Request(ctx, p.Key, 1, spec(p.Forbidden, p.Destinations))
		if status.Code(err) != codes.PermissionDenied ||
			workerclient.Reason(err) != workerv1alpha1.ReasonCapabilityNotAllowed {
			return fmt.Errorf("request with a forbidden capability: got %w, want PERMISSION_DENIED/%s",
				err, workerv1alpha1.ReasonCapabilityNotAllowed)
		}
		logf("forbidden capability refused: %s", workerclient.Reason(err))
	}

	obsCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	st, err := c.Request(ctx, p.Key, 1, spec(p.Handoff, p.Destinations))
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	logf("requested generation %d", st.GetGeneration())
	// A repeated request with the same generation and spec is a duplicate.
	if _, err := c.Request(ctx, p.Key, 1, spec(p.Handoff, p.Destinations)); err != nil {
		return fmt.Errorf("duplicate request: %w", err)
	}

	obs, err := c.Observe(obsCtx, p.Key)
	if err != nil {
		return fmt.Errorf("observe: %w", err)
	}
	if err := waitFor(obs, logf, func(s *workerv1alpha1.ClaimStatus) bool {
		return s.GetObservedGeneration() >= 1
	}); err != nil {
		return fmt.Errorf("observe generation 1: %w", err)
	}

	if _, err := c.Update(ctx, p.Key, 2, spec(p.Handoff, p.UpdateDestinations)); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	logf("updated to generation 2")
	if err := waitFor(obs, logf, func(s *workerv1alpha1.ClaimStatus) bool {
		return s.GetObservedGeneration() >= 2
	}); err != nil {
		return fmt.Errorf("observe generation 2: %w", err)
	}

	// A release at the replaced generation is stale and changes nothing.
	if _, err := c.Release(ctx, p.Key, 1); status.Code(err) != codes.Aborted {
		return fmt.Errorf("stale release: got %w, want ABORTED/%s", err, workerv1alpha1.ReasonStaleGeneration)
	}
	if _, err := c.Release(ctx, p.Key, 2); err != nil {
		return fmt.Errorf("release: %w", err)
	}
	logf("released generation 2")
	if err := waitFor(obs, logf, func(s *workerv1alpha1.ClaimStatus) bool { return s.GetReleased() }); err != nil {
		return fmt.Errorf("observe release: %w", err)
	}
	// Releasing a claim that no longer exists succeeds, so a retry is safe.
	if _, err := c.Release(ctx, p.Key, 2); err != nil {
		return fmt.Errorf("repeated release: %w", err)
	}
	return nil
}

// waitFor receives snapshots until done holds.
func waitFor(obs *workerclient.Observer, logf Logf, done func(*workerv1alpha1.ClaimStatus) bool) error {
	for {
		s, err := obs.Recv()
		if errors.Is(err, io.EOF) {
			return errors.New("stream closed")
		}
		if err != nil {
			return err
		}
		logf("status generation=%d observed=%d released=%t conditions=%s",
			s.GetGeneration(), s.GetObservedGeneration(), s.GetReleased(), conditions(s))
		if done(s) {
			return nil
		}
	}
}

func conditions(s *workerv1alpha1.ClaimStatus) string {
	out := ""
	for _, c := range s.GetConditions() {
		if out != "" {
			out += ","
		}
		out += fmt.Sprintf("%s=%s/%s", c.GetType(),
			c.GetStatus().String()[len("CONDITION_STATUS_"):], c.GetReason())
	}
	return out
}
