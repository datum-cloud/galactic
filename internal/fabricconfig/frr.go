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

// Neighbors runs `show bgp neighbors json` through vtysh.
func (e ExecFRR) Neighbors(ctx context.Context) ([]byte, error) {
	return output(ctx, e.Vtysh, "-c", "show bgp neighbors json")
}

// Routes runs `show <afi> route json` through vtysh.
func (e ExecFRR) Routes(ctx context.Context, afi string) ([]byte, error) {
	return output(ctx, e.Vtysh, "-c", "show "+afi+" route json")
}

// ResetNeighbor runs `clear bgp ipv6 <neighbor>` through vtysh, a hard reset
// that tears the session down and recomputes its next hop when it comes back.
func (e ExecFRR) ResetNeighbor(ctx context.Context, neighbor string) error {
	return run(ctx, e.Vtysh, "-c", "clear bgp ipv6 "+neighbor)
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

// output executes name with args and returns its standard output. It returns
// an error including standard error when it exits non-zero.
func output(ctx context.Context, name string, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
