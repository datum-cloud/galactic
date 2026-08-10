// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"strings"
)

// EnvIPAMEnableLocalIPAM is galactic-ipam's own local-IPAM default-filler
// flag, read fresh on every invocation (mirrors CNIConfig's env-only
// resolution — galactic-ipam has no conflist/kubeconfig to read a
// middle-tier value from, since it has no k8s dependency at all).
//
// Renamed from the historical GALACTIC_CNI_ENABLE_LOCAL_IPAM now that the
// flag belongs entirely to galactic-ipam: it's no longer a trigger deciding
// whether IPAM runs at all (that's the "ipam" block's presence, decided by
// the master plugin before it ever delegates) — only a default-filler for
// when the ipam block is present but under-specified. See
// go.datum.net/galactic/internal/cniipam's own doc comment.
const EnvIPAMEnableLocalIPAM = "GALACTIC_IPAM_ENABLE_LOCAL_IPAM"

// IPAMGetEnableLocalIPAM reports whether galactic-ipam's local-IPAM
// default-filler is enabled via environment variable. Returns false if the
// variable is unset or not "true".
func IPAMGetEnableLocalIPAM() bool {
	val := os.Getenv(EnvIPAMEnableLocalIPAM)
	return strings.EqualFold(val, "true")
}
