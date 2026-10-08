//go:build !linux

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroutemap

import (
	"errors"
	"time"
)

func authorizationClock() (time.Time, uint64, error) {
	return time.Time{}, 0, errors.New("authorization leases require Linux")
}
