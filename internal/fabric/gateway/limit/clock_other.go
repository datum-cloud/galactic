// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package limit

import "errors"

// KernelClock reports every clock unhealthy: only Linux exposes the clock
// discipline it reads.
func KernelClock() error { return errors.New("clock health is unknown on this platform") }
