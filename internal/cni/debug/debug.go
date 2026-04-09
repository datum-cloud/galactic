// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package debug

const Default = "unknown"

var DebugVersion = Default
var DebugRef = Default

func Version() string {
	if DebugVersion != Default {
		return DebugVersion
	}
	if DebugRef != Default {
		return DebugRef
	}
	return Default
}
