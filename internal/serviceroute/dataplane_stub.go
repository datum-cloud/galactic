//go:build !linux

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import "errors"

// EBPFRouteProgrammer is unavailable outside Linux. The stub keeps API and
// planner packages testable on developer workstations; CI and production use
// the Linux implementation.
type EBPFRouteProgrammer struct {
	PinDir string
}

func (*EBPFRouteProgrammer) Initialize() error {
	return errors.New("service route dataplane programming requires linux")
}

func (*EBPFRouteProgrammer) Apply(RouteIntent) error {
	return errors.New("service route dataplane programming requires linux")
}

func (*EBPFRouteProgrammer) Remove(RouteIntent) error {
	return errors.New("service route dataplane programming requires linux")
}

func (*EBPFRouteProgrammer) Cleanup(RouteIntent) error {
	return errors.New("service route dataplane programming requires linux")
}

func (*EBPFRouteProgrammer) Finalize() error {
	return errors.New("service route dataplane programming requires linux")
}
