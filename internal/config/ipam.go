// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"strings"
)

// EnvIPAMEnableLocalIPAM is the IPAM plugin's local default-filler flag, read
// fresh on every invocation: that plugin has no conflist or kubeconfig to read a
// middle-tier value from, having no Kubernetes dependency at all.
//
// It is not a trigger deciding whether IPAM runs, which the ipam block's
// presence decides in the master plugin before it delegates, but only a
// default-filler for when that block is present and under-specified.
const EnvIPAMEnableLocalIPAM = "GALACTIC_IPAM_ENABLE_LOCAL_IPAM"

// IPAMGetEnableLocalIPAM reports whether the local default-filler is enabled.
// Returns false when the variable is unset or not "true".
func IPAMGetEnableLocalIPAM() bool {
	val := os.Getenv(EnvIPAMEnableLocalIPAM)
	return strings.EqualFold(val, "true")
}
