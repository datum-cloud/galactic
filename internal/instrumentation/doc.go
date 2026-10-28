// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package instrumentation holds the module-wide checks that every metric and
// logger goes through go.miloapis.com/instrumentation. It has no code of its
// own; its tests read the module's source and link every package that
// defines a metric through the library.
package instrumentation
