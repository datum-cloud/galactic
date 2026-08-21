// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cniipam

import (
	"fmt"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
)

func TestCmdAddCmdDelCmdCheckRoundTrip(t *testing.T) {
	withTempLockDir(t)

	conf := confJSON(fmt.Sprintf(`"type":%q,"ipv6_subnet":%q`, testIPAMType, testIPv6PoolDefault))
	args := &skel.CmdArgs{ContainerID: testContainerID, StdinData: []byte(conf)}

	if err := cmdAdd(args); err != nil {
		t.Fatalf("cmdAdd: unexpected error: %v", err)
	}
	if err := cmdCheck(args); err != nil {
		t.Fatalf("cmdCheck after cmdAdd: unexpected error: %v", err)
	}
	if err := cmdDel(args); err != nil {
		t.Fatalf("cmdDel: unexpected error: %v", err)
	}
	if err := cmdCheck(args); err == nil {
		t.Fatal("cmdCheck after cmdDel: expected error (allocation released), got nil")
	}
}

func TestCmdAddMissingIPAMBlock(t *testing.T) {
	args := &skel.CmdArgs{
		ContainerID: testContainerID,
		StdinData:   []byte(fmt.Sprintf(`{"cniVersion":"%s","name":"test","type":%q}`, testCNIVersion, testIPAMType)),
	}
	err := cmdAdd(args)
	if err == nil || !strings.Contains(err.Error(), "ipam block is required") {
		t.Fatalf("expected 'ipam block is required' error, got: %v", err)
	}
}

func TestCmdDelIdempotentOnUnparseableConfig(t *testing.T) {
	args := &skel.CmdArgs{ContainerID: testContainerID, StdinData: []byte("not valid json")}
	if err := cmdDel(args); err != nil {
		t.Fatalf("cmdDel with invalid config returned error = %v, want nil (idempotent)", err)
	}
}

func TestCmdDelStaticIsNoop(t *testing.T) {
	conf := confJSON(fmt.Sprintf(`"type":%q,"static_ip":"fd00::1234"`, testIPAMType))
	args := &skel.CmdArgs{ContainerID: testContainerID, StdinData: []byte(conf)}
	if err := cmdDel(args); err != nil {
		t.Fatalf("cmdDel for static IPAM returned error = %v, want nil", err)
	}
}

func TestCmdStatusValid(t *testing.T) {
	args := &skel.CmdArgs{StdinData: []byte(fmt.Sprintf(`{"cniVersion":"%s"}`, testCNIVersion))}
	if err := cmdStatus(args); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCmdStatusInvalidConfig(t *testing.T) {
	args := &skel.CmdArgs{StdinData: []byte("not valid json")}
	if err := cmdStatus(args); err == nil {
		t.Fatal("expected error for invalid config, got nil")
	}
}

func TestCmdCheckStaticAlwaysPasses(t *testing.T) {
	conf := confJSON(fmt.Sprintf(`"type":%q,"static_ip":"fd00::1234"`, testIPAMType))
	args := &skel.CmdArgs{ContainerID: testContainerID, StdinData: []byte(conf)}
	if err := cmdCheck(args); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestCmdAddCmdDelCmdCheckRoundTripAddresses exercises the delegation
// protocol end to end for pre-decided addresses. Unlike the pool path, CHECK
// still passes after DEL: nothing was allocated, so there is no record whose
// absence could fail.
func TestCmdAddCmdDelCmdCheckRoundTripAddresses(t *testing.T) {
	withTempLockDir(t)

	conf := confJSON(fmt.Sprintf(`"type":%q,%s`, testIPAMType, addressesJSON))
	args := &skel.CmdArgs{ContainerID: testContainerID, StdinData: []byte(conf)}

	if err := cmdAdd(args); err != nil {
		t.Fatalf("cmdAdd: unexpected error: %v", err)
	}
	if err := cmdCheck(args); err != nil {
		t.Fatalf("cmdCheck after cmdAdd: unexpected error: %v", err)
	}
	if err := cmdDel(args); err != nil {
		t.Fatalf("cmdDel: unexpected error: %v", err)
	}
	if err := cmdCheck(args); err != nil {
		t.Fatalf("cmdCheck after cmdDel: unexpected error: %v", err)
	}
}
