// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package xdpmode decides, once per host, which XDP attach mode every
// Galactic XDP attachment on that host uses.
//
// Native (driver) mode is the default. A host with any NIC driven by bnxt_en
// uses generic (SKB) mode for every attachment instead, virtual interfaces
// included, so the host never mixes native and generic redirect paths.
// Native XDP redirect traffic on bnxt_en is associated with receive queues
// that stall permanently (#673). The suspected driver defect suppresses RX
// producer updates while the paired XDP TX ring is busy; generic mode runs
// the same programs after the driver has built an skb, so the XDP TX ring is
// never used. The cost is per-packet throughput, since generic mode allocates
// an skb for every frame.
package xdpmode

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink/nl"
)

// Mode is an XDP attach mode.
type Mode int

const (
	// Native attaches in driver mode, the program running in the NIC
	// driver's receive path before an skb exists.
	Native Mode = iota
	// Generic attaches in SKB mode, the program running in the core
	// receive path after the driver has built an skb.
	Generic
)

// String returns the mode's name as logs and docs use it.
func (m Mode) String() string {
	switch m {
	case Native:
		return "native"
	case Generic:
		return "generic"
	default:
		return fmt.Sprintf("Mode(%d)", int(m))
	}
}

// AttachFlags returns the flags that request m from link.AttachXDP. Each mode
// names its flag explicitly, so the kernel never picks a mode on its own.
func (m Mode) AttachFlags() link.XDPAttachFlags {
	if m == Generic {
		return link.XDPGenericMode
	}
	return link.XDPDriverMode
}

// Matches reports whether attachMode, an interface's IFLA_XDP_ATTACHED value
// as netlink.LinkXdp.AttachMode reports it, is m.
func (m Mode) Matches(attachMode uint32) bool {
	switch m {
	case Native:
		return attachMode == nl.XDP_ATTACHED_DRV
	case Generic:
		return attachMode == nl.XDP_ATTACHED_SKB
	default:
		return false
	}
}

// FromAttachMode returns the Mode for an interface's IFLA_XDP_ATTACHED value,
// and false for none, hardware offload, or several programs at once.
func FromAttachMode(attachMode uint32) (Mode, bool) {
	switch attachMode {
	case nl.XDP_ATTACHED_DRV:
		return Native, true
	case nl.XDP_ATTACHED_SKB:
		return Generic, true
	default:
		return 0, false
	}
}

// GenericDrivers are the NIC drivers whose presence on a host selects generic
// mode for every attachment on it.
var GenericDrivers = []string{"bnxt_en"}

// Decision is Select's result: the mode, why, and what it was based on.
type Decision struct {
	Mode Mode
	// Drivers maps every physical NIC on the host to its driver.
	Drivers map[string]string
	// Reason says, in a sentence for a log line, why Mode was chosen.
	Reason string
	// Skipped lists physical NICs left out because their driver link was
	// gone, as while a driver unbinds, each with why. None is a target.
	Skipped []string
}

// sysClassNet is where Select reads interfaces and their drivers from.
// Galactic's XDP processes run in the host network namespace, so it lists the
// host's interfaces. Tests point it elsewhere.
var sysClassNet = "/sys/class/net"

// Select decides the host's attach mode from the drivers of its physical NICs
// in sysfs. required lists the interfaces the caller is about to attach to;
// one that does not exist fails the decision, as does a required NIC whose
// driver cannot be read, or any NIC whose driver link exists but cannot be
// read, so none of them ever settles a mode by omission. A NIC that is not a
// target and has no driver link at all, as while its driver unbinds, carries
// no driver traffic; it is left out and listed in Skipped. An interface with
// no device link, such as a bond master, a veth or a VLAN, is virtual and has
// no driver of its own to consider.
func Select(required ...string) (Decision, error) {
	entries, err := os.ReadDir(sysClassNet)
	if err != nil {
		return Decision{}, fmt.Errorf("xdpmode: list interfaces in %s: %w", sysClassNet, err)
	}
	present := make(map[string]bool, len(entries))
	drivers := map[string]string{}
	var (
		errs    []error
		skipped []string
	)
	for _, e := range entries {
		name := e.Name()
		present[name] = true
		driver, physical, err := interfaceDriver(name)
		switch {
		case err != nil && errors.Is(err, os.ErrNotExist) && !slices.Contains(required, name):
			skipped = append(skipped, err.Error())
		case err != nil:
			errs = append(errs, err)
		case physical:
			drivers[name] = driver
		}
	}
	for _, name := range required {
		if !present[name] {
			errs = append(errs, fmt.Errorf("xdpmode: interface %s does not exist", name))
		}
	}
	if len(errs) > 0 {
		return Decision{}, errors.Join(errs...)
	}
	d := decide(drivers)
	d.Skipped = skipped
	return d, nil
}

// interfaceDriver returns name's driver and whether it is a physical NIC,
// which is when sysfs gives it a device link.
func interfaceDriver(name string) (driver string, physical bool, err error) {
	dir := filepath.Join(sysClassNet, name)
	if _, err := os.Lstat(filepath.Join(dir, "device")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("xdpmode: read device of %s: %w", name, err)
	}
	target, err := os.Readlink(filepath.Join(dir, "device", "driver"))
	if err != nil {
		return "", true, fmt.Errorf("xdpmode: read driver of %s: %w", name, err)
	}
	return filepath.Base(target), true, nil
}

// decide picks the mode for a host whose physical NICs have drivers.
func decide(drivers map[string]string) Decision {
	var matched []string
	for name, driver := range drivers {
		if slices.Contains(GenericDrivers, driver) {
			matched = append(matched, name+"="+driver)
		}
	}
	if len(matched) == 0 {
		return Decision{Mode: Native, Drivers: drivers,
			Reason: "no NIC on this host uses a driver that needs generic mode"}
	}
	slices.Sort(matched)
	return Decision{Mode: Generic, Drivers: drivers,
		Reason: "NICs on this host use a driver whose native XDP redirect stalls receive queues (#673): " +
			strings.Join(matched, ", ")}
}
