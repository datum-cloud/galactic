// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dan writes Directly Attachable Network files, the handoff a Kata
// runtime-rs shim reads instead of scanning a sandbox network namespace.
//
// A microVM guest cannot be handed an interface the way a container can. The
// shim has to be told which host device belongs to the sandbox and what the
// guest should see on it. A DAN file states that, so the guest adopts the tap
// this node's CNI plugin already created, addressed and enslaved to its VPC's
// VRF.
//
// The file is named for the sandbox ID and is the CNI plugin's property for the
// sandbox's whole lifetime. Nothing in Kata removes it, so ADD writes it and
// DEL unlinks it.
package dan

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultDir is where a runtime-rs shim configured for directly attachable
// networking looks for a sandbox's file.
//
// This is not the Go shim's directory. See GoShimDir.
const DefaultDir = "/run/kata-containers/dans-rs"

// GoShimDir is the directory the Go shim reads, which this package refuses to
// write to.
//
// The Go shim understands a different set of device types and hard-errors on
// the host tap this package emits. A file dropped there stops every sandbox on
// the node from starting, not only the ones attached to a VPC.
const GoShimDir = "/run/kata-containers/dans"

// DeviceTypeHostTap names the device type that adopts an existing tap in the
// host network namespace. The shim resolves the device by name before entering
// any namespace guard, which is why the tap must already exist on the host.
const DeviceTypeHostTap = "host-tap"

// InterfaceTypeTap is the interface type a tap-backed guest interface reports.
const InterfaceTypeTap = "tuntap"

// Document is a sandbox's whole DAN file.
//
// The top-level netns field a DAN file may carry is absent. Naming a namespace
// sends the shim back to scanning it.
type Document struct {
	Devices []Device `json:"devices"`
}

// Device is one interface handed to the guest.
//
// The shim derives the guest interface name from the position in
// Document.Devices, not from Name. Name is set for whoever reads the file
// next.
type Device struct {
	Name string `json:"name"`
	// GuestMAC is set explicitly so the guest's address is stable across
	// sandbox restarts. Left unset, the shim draws a random one.
	GuestMAC    string      `json:"guest_mac"`
	Device      DeviceSpec  `json:"device"`
	NetworkInfo NetworkInfo `json:"network_info"`
}

// DeviceSpec names the host resource backing a guest interface.
type DeviceSpec struct {
	Type    string `json:"type"`
	TapName string `json:"tap_name"`
}

// NetworkInfo is what the guest is told to configure on the interface.
type NetworkInfo struct {
	Interface Interface `json:"interface"`
	Routes    []Route   `json:"routes"`
	Neighbors []any     `json:"neighbors"`
}

// Interface carries the guest-side addressing for one device.
type Interface struct {
	IPAddresses []string `json:"ip_addresses"`
	MTU         int      `json:"mtu"`
	Ntype       string   `json:"ntype"`
	Flags       uint32   `json:"flags"`
}

// RouteFlagOnLink marks a route's gateway as reachable on the link even when
// no address on the interface covers it. It is the kernel's RTNH_F_ONLINK,
// passed through to the guest's routing table unchanged.
const RouteFlagOnLink uint32 = 4

// Route is one route installed inside the guest. An empty Dest is the default
// route for whichever family Gateway belongs to.
type Route struct {
	Dest    string `json:"dest"`
	Gateway string `json:"gateway"`
	Source  string `json:"source"`
	Scope   uint32 `json:"scope"`
	Flags   uint32 `json:"flags"`
	MTU     uint32 `json:"mtu"`
}

// Path returns the DAN file path for a sandbox under dir. The sandbox ID is the
// container ID the runtime passes the CNI plugin for the pod sandbox, which is
// byte-identical to the ID the shim looks the file up by.
func Path(dir, sandboxID string) (string, error) {
	if dir == "" {
		return "", errors.New("DAN directory is required")
	}
	if filepath.Clean(dir) == GoShimDir {
		return "", fmt.Errorf("refusing to use the Go shim's DAN directory %q: "+
			"a %s device there fails every sandbox on this node; use %q",
			GoShimDir, DeviceTypeHostTap, DefaultDir)
	}
	if err := validateSandboxID(sandboxID); err != nil {
		return "", err
	}
	return filepath.Join(dir, sandboxID+".json"), nil
}

// validateSandboxID rejects an ID that would escape dir or name something other
// than one file. The ID reaches this package straight from the runtime's
// environment, and it is used as a filename.
func validateSandboxID(sandboxID string) error {
	if sandboxID == "" {
		return errors.New("sandbox ID is required")
	}
	if strings.ContainsAny(sandboxID, `/\`) || sandboxID == "." || sandboxID == ".." {
		return fmt.Errorf("invalid sandbox ID %q: must name a single file", sandboxID)
	}
	return nil
}

// Write stores a sandbox's DAN file under dir, replacing any existing one.
//
// The write is atomic, so a shim reading concurrently sees the whole document
// or none of it. Treat a failure as fatal to CNI ADD. Without the file the shim
// falls back to scanning the sandbox namespace and produces a healthy-looking
// sandbox on the wrong network.
func Write(dir, sandboxID string, doc *Document) error {
	path, err := Path(dir, sandboxID)
	if err != nil {
		return err
	}
	if doc == nil || len(doc.Devices) == 0 {
		return fmt.Errorf("refusing to write a DAN file with no devices for sandbox %q", sandboxID)
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal DAN document for sandbox %q: %w", sandboxID, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create DAN directory %q: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, "."+sandboxID+".*")
	if err != nil {
		return fmt.Errorf("create temporary DAN file in %q: %w", dir, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write DAN file %q: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close DAN file %q: %w", tmpPath, err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("set DAN file mode on %q: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("install DAN file %q: %w", path, err)
	}
	return nil
}

// Remove deletes a sandbox's DAN file. Call it on DEL. Nothing in Kata removes
// the file, and a stale one is adopted by a later sandbox that reuses the ID. A
// missing file is not an error, because DEL is idempotent and is reached when
// ADD never wrote one.
func Remove(dir, sandboxID string) error {
	path, err := Path(dir, sandboxID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove DAN file %q: %w", path, err)
	}
	return nil
}
