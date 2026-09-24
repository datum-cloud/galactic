// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// FRR validates and applies FRR configuration files.
type FRR interface {
	// Check validates the configuration in path without applying it.
	Check(ctx context.Context, path string) error
	// Reload applies the difference between the running configuration and
	// the configuration in path.
	Reload(ctx context.Context, path string) error
}

// ExecFRR implements FRR with the vtysh and frr-reload.py binaries.
type ExecFRR struct {
	// Vtysh is the path to vtysh.
	Vtysh string
	// Reloader is the path to frr-reload.py.
	Reloader string
	// ConfigDir is the FRR configuration directory frr-reload.py reads
	// daemon configuration from.
	ConfigDir string
}

// Check runs vtysh's dry-run parser over path. It returns an error carrying
// vtysh's output when any line fails to parse.
func (e ExecFRR) Check(ctx context.Context, path string) error {
	return run(ctx, e.Vtysh, "-C", "-f", path)
}

// Reload runs frr-reload.py to apply path to the running daemons. It returns
// an error carrying the tool's output when it exits non-zero.
func (e ExecFRR) Reload(ctx context.Context, path string) error {
	return run(ctx, e.Reloader, "--reload", "--stdout", "--confdir", e.ConfigDir, path)
}

// run executes name with args and returns an error including its combined
// output when it exits non-zero.
func run(ctx context.Context, name string, args ...string) error {
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(out.String()))
	}
	return nil
}
