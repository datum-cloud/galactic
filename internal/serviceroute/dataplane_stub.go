//go:build !linux

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import "fmt"

// LinuxRouteProgrammer is unavailable outside Linux. The stub keeps API and
// planner packages testable on developer workstations; CI and production use
// the Linux implementation.
type LinuxRouteProgrammer struct{}

func (LinuxRouteProgrammer) Apply(RouteIntent) error {
	return fmt.Errorf("service route dataplane programming requires linux")
}

func (LinuxRouteProgrammer) Remove(RouteIntent) error {
	return fmt.Errorf("service route dataplane programming requires linux")
}
