// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

// LoadHook and AttachHook are process-wide observability callbacks for BPF
// program load and TC-BPF ingress filter attach/detach outcomes (design
// plan .local/plan-ebpf-xdp-usid-datapath.md §9's "BPF program load/reload
// events and failures" metric; Milestone 4 of
// .local/implementation-plan-ebpf-xdp-usid-datapath.md). They default to
// no-ops so this package never needs a direct dependency on a metrics
// library -- internal/plumbing/ebpf/metrics's Prometheus registration is
// the only production caller of SetHooks, wiring real counters in once at
// process startup (internal/installer.Run), exactly like watch.go's own
// test-only onReconcileDone hook already does for tests within this
// package.
//
// AttachHook is invoked from attachOne and detachOne -- the two internal
// choke points every attach/detach path in this package ultimately goes
// through (Start's initial Attach call, Watch's netlink-driven reconcile,
// and Detach's direct callers) -- so installing it once observes every
// attach/detach event this package ever performs, regardless of whether it
// happened at startup or as part of a later re-attachment ("reload").
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

// SetHooks installs h's callbacks, defaulting any nil field to a no-op. Not
// safe to call concurrently with Load/Attach/Detach/Watch -- call once,
// before starting the datapath, exactly like internal/installer.Run does.
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
