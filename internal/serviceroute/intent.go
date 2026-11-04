// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package serviceroute programs the route intents that serviceplan compiles
// into a node's service-route datapath.
package serviceroute

import (
	"errors"

	"go.datum.net/galactic/pkg/serviceplan"
)

// The route intent vocabulary is defined by serviceplan, which compiles it.
type (
	RouteIntent     = serviceplan.RouteIntent
	RouteIntentKind = serviceplan.RouteIntentKind
	IntentSlot      = serviceplan.IntentSlot
	ProducerTarget  = serviceplan.ProducerTarget
	ServiceGrantID  = serviceplan.ServiceGrantID
)

const (
	RouteIntentLocal          = serviceplan.RouteIntentLocal
	RouteIntentLocalSet       = serviceplan.RouteIntentLocalSet
	RouteIntentRemoteConsumer = serviceplan.RouteIntentRemoteConsumer
	RouteIntentRemoteProducer = serviceplan.RouteIntentRemoteProducer
)

// ErrProducerSetsUnavailable is returned for a LocalSet intent while the
// node's datapath predates LocalSet routes. Every other intent still applies.
var ErrProducerSetsUnavailable = errors.New(
	"node's eBPF datapath has no producer set map; LocalSet routes need a newer galactic-cni")

// RouteProgrammer installs and removes route intents in a node's datapath.
type RouteProgrammer interface {
	Initialize() error
	Apply(RouteIntent) error
	Cleanup(RouteIntent) error
	Remove(RouteIntent) error
	Finalize() error
}
