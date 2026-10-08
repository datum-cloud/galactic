// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/srv6"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// Backoff bounds for waiting on this node's BGPRouter at startup.
const (
	encapSourceRetryInitial = time.Second
	encapSourceRetryMax     = 30 * time.Second
)

// noRouterYetError reports that no BGPRouter targeting this node carries an SRv6
// locator and node ID yet. resolveEncapSource retries it, as it does
// listRoutersError; every other error is returned.
type noRouterYetError struct{ nodeName string }

func (e noRouterYetError) Error() string {
	return "no BGPRouter with an SRv6 locator and node ID targets node " + e.nodeName
}

// listRoutersError reports that listing BGPRouters failed: the API server was
// unreachable, timed out, refused the request, or does not serve the kind.
// resolveEncapSource retries it, logging the error on every attempt.
type listRoutersError struct{ err error }

func (e listRoutersError) Error() string { return "list BGPRouters: " + e.err.Error() }

func (e listRoutersError) Unwrap() error { return e.err }

// resolveEncapSource returns the outer-header source the edge datapath writes
// on every packet it encapsulates: configured when it is set, and otherwise
// this node's locator address, derived from the BGPRouter targeting it (#707).
// The derived value is what deployments used to set by hand, so leaving the
// setting unset changes nothing on the wire.
//
// It runs before the manager starts, so reader must be uncached
// (mgr.GetAPIReader()). The lookup spans every namespace: the gateway has no
// namespace setting of its own, and its ClusterRole already lists BGPRouters
// cluster-wide.
//
// A node whose router is missing or still lacks a locator or node ID is
// waited on, with backoff, until ctx is done, and so is a failed list of
// BGPRouters. Each failed list is logged as a warning, so an error that
// persists, such as a missing RBAC grant, stays visible while it is retried.
// The gateway cannot advertise a VIP without that router anyway, and
// both health services stay NOT_SERVING meanwhile, so the wait is bounded by
// the caller's startup probe: the kubelet restarts the container when it
// expires, and the wait starts over.
// Two routers for this node that disagree on the address are an error, never
// a guess.
func resolveEncapSource(ctx context.Context, reader client.Reader, nodeName, configured string) (string, error) {
	if configured != "" {
		slog.Info("Using the configured edge gateway SRv6 encapsulation source", "address", configured)
		return configured, nil
	}

	delay := encapSourceRetryInitial
	for {
		addr, err := encapSourceFromRouters(ctx, reader, nodeName)
		if err == nil {
			slog.Info("Derived the edge gateway SRv6 encapsulation source from this node's BGPRouter",
				"address", addr)
			return addr.String(), nil
		}
		switch {
		case errors.As(err, &listRoutersError{}):
			slog.Warn("Listing BGPRouters to derive the edge gateway SRv6 encapsulation source failed; retrying",
				"node", nodeName, "retryIn", delay, "error", err)
		case errors.As(err, &noRouterYetError{}):
			slog.Info("Waiting for this node's BGPRouter to derive the edge gateway SRv6 encapsulation source",
				"node", nodeName, "retryIn", delay)
		default:
			return "", err
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", fmt.Errorf("derive SRv6 encapsulation source: %w (last: %w)", ctx.Err(), err)
		case <-timer.C:
		}
		delay = min(2*delay, encapSourceRetryMax)
	}
}

// encapSourceFromRouters derives this node's locator address from every
// BGPRouter whose target is the Node nodeName (an empty kind counts as Node)
// and that carries a locator and node ID. It returns noRouterYetError when
// there is none, and listRoutersError when the list fails.
func encapSourceFromRouters(ctx context.Context, reader client.Reader, nodeName string) (netip.Addr, error) {
	list := &bgpv1alpha1.BGPRouterList{}
	if err := reader.List(ctx, list); err != nil {
		return netip.Addr{}, listRoutersError{err: err}
	}

	var (
		found netip.Addr
		from  string
	)
	for i := range list.Items {
		router := &list.Items[i]
		if router.Spec.TargetRef.Name != nodeName {
			continue
		}
		if kind := router.Spec.TargetRef.Kind; kind != "" && kind != "Node" {
			continue
		}
		if router.Spec.SRv6Locator == "" || router.Spec.NodeID == 0 {
			continue
		}
		addr, err := srv6.NodeLocatorAddress(router.Spec.SRv6Locator, router.Spec.NodeID)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("derive SRv6 encapsulation source from BGPRouter %s/%s: %w",
				router.Namespace, router.Name, err)
		}
		name := router.Namespace + "/" + router.Name
		if found.IsValid() && found != addr {
			return netip.Addr{}, fmt.Errorf(
				"BGPRouters %s and %s both target node %s but derive different SRv6 encapsulation sources "+
					"(%s, %s); set %s or remove one", from, name, nodeName, found, addr, config.EnvGatewaySRv6Address)
		}
		found, from = addr, name
	}
	if !found.IsValid() {
		return netip.Addr{}, noRouterYetError{nodeName: nodeName}
	}
	return found, nil
}
