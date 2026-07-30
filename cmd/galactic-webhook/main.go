// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command galactic-webhook is the mutating admission webhook that provisions
// NAD + VPCAttachment ID allocation for pods requesting VPC attachment. See
// internal/webhook for the handler logic and this repo's design plan
// (.local/plan-vpc-nad-webhook-plan.md) for the full rationale.
package main

import "os"

func main() {
	cmd := newRootCommand()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
