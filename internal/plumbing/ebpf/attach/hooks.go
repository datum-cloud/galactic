// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

// LoadHook and AttachHook are process-wide observability callbacks for program
// load and filter attach and detach outcomes. They default to no-ops, so this
// package needs no dependency on a metrics library: the metrics package is the
// only production caller of SetHooks, wiring real counters in once at process
// startup.
//
// AttachHook is invoked from the two internal choke points every attach and
// detach path goes through, so installing it once observes every such event this
// package performs, whether at startup or during a later re-attachment.
type LoadHook func(err error)

// AttachHook reports the outcome of attaching or detaching this package's
// own TC-BPF ingress filter (filterName) on one named interface.
type AttachHook func(iface string, err error)

// Hooks bundles the observability callbacks SetHooks installs. A nil field
// leaves the corresponding hook a no-op.
type Hooks struct {
	OnLoad   LoadHook
	OnAttach AttachHook
	OnDetach AttachHook
}

var (
	loadHook   LoadHook   = func(error) {}
	attachHook AttachHook = func(string, error) {}
	detachHook AttachHook = func(string, error) {}
)

// SetHooks installs h's callbacks, defaulting any nil field to a no-op. Not safe
// to call concurrently with the load, attach, or watch paths: call it once,
// before starting the datapath.
func SetHooks(h Hooks) {
	loadHook = h.OnLoad
	if loadHook == nil {
		loadHook = func(error) {}
	}
	attachHook = h.OnAttach
	if attachHook == nil {
		attachHook = func(string, error) {}
	}
	detachHook = h.OnDetach
	if detachHook == nil {
		detachHook = func(string, error) {}
	}
}
