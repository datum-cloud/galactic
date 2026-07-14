// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"testing"
)

const helpFlag = "--help"

func TestSubcommandsRegistered(t *testing.T) {
	cmd := newRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{helpFlag})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("failed to execute help: %v", err)
	}

	output := buf.String()
	if !containsString(output, "init") {
		t.Errorf("expected output to contain 'init', got: %s", output)
	}
	if !containsString(output, "run") {
		t.Errorf("expected output to contain 'run', got: %s", output)
	}
	if !containsString(output, "--conf-file") {
		t.Errorf("expected output to contain '--conf-file', got: %s", output)
	}
}

func TestInitHelp(t *testing.T) {
	cmd := newRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"init", helpFlag})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("failed to execute init help: %v", err)
	}

	output := buf.String()
	if !containsString(output, "--node-name") {
		t.Errorf("expected output to contain '--node-name', got: %s", output)
	}
}

func TestRunHelp(t *testing.T) {
	cmd := newRootCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"run", helpFlag})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("failed to execute run help: %v", err)
	}

	output := buf.String()
	if !containsString(output, "--grpc-health-port") {
		t.Errorf("expected output to contain '--grpc-health-port', got: %s", output)
	}
}

func containsString(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}
