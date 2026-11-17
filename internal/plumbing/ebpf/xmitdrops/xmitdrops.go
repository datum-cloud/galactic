// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xmitdrops

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Stage says where the kernel dropped a redirected frame, mirroring the C enum
// xmit_drop_stage.
type Stage uint32

const (
	// StageRedirect is a frame xdp_do_redirect could not queue to its target.
	StageRedirect Stage = 0
	// StageXmit is a frame the target's driver dropped when the queued frames
	// were flushed to it.
	StageXmit Stage = 1
)

// String returns the stage's metric label value.
func (s Stage) String() string {
	switch s {
	case StageRedirect:
		return "redirect"
	case StageXmit:
		return "xmit"
	default:
		return fmt.Sprintf("stage_%d", uint32(s))
	}
}

// Key identifies one drop counter.
type Key struct {
	// Ifindex is the interface the frame was redirected to.
	Ifindex uint32
	Stage   Stage
	// Errno is the positive errno the kernel reported, 0 when a driver
	// dropped frames without one.
	Errno uint32
}

// Counter holds the loaded tracepoint programs and their counter map. Its
// counts live only as long as it does.
type Counter struct {
	objs  XmitdropsObjects
	links []link.Link
}

// Attach loads the programs and attaches them to both tracepoints, as raw
// tracepoints, which need no tracefs mount. Only drops to interfaces in the
// calling thread's network namespace are counted, so that each count's ifindex
// resolves there. It needs CAP_BPF and CAP_PERFMON, or CAP_SYS_ADMIN, and
// kernel BTF to resolve the device field reads. It returns an error, without
// loading anything, on a kernel whose tracepoint argument layout predates
// the map_type argument.
func Attach() (*Counter, error) {
	inum, err := threadNetnsInode()
	if err != nil {
		return nil, err
	}
	if err := checkTracepointLayout(); err != nil {
		return nil, err
	}
	c := &Counter{}
	if err := LoadXmitdropsObjects(&c.objs, nil); err != nil {
		return nil, fmt.Errorf("load XDP transmit drop counters: %w", err)
	}
	if err := c.objs.XmitConfig.Put(uint32(0), XmitdropsXmitCfg{NetnsInum: inum}); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("configure XDP transmit drop counters: %w", err)
	}
	for _, tp := range []struct {
		name string
		prog *ebpf.Program
	}{
		{"xdp_redirect_err", c.objs.XdpRedirectErr},
		{"xdp_devmap_xmit", c.objs.XdpDevmapXmit},
	} {
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: tp.name, Program: tp.prog})
		if err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("attach to raw tracepoint %s: %w", tp.name, err)
		}
		c.links = append(c.links, l)
	}
	return c, nil
}

// threadNetnsInode returns the inode number of the calling thread's network
// namespace, which the kernel reports as that namespace's ns.inum.
func threadNetnsInode() (uint32, error) {
	var st unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &st); err != nil {
		return 0, fmt.Errorf("read this thread's network namespace: %w", err)
	}
	return uint32(st.Ino), nil
}

// Read returns every counter, summed across CPUs.
func (c *Counter) Read() (map[Key]uint64, error) {
	return readMap(c.objs.XmitDrops)
}

// Close detaches the programs and releases the map.
func (c *Counter) Close() error {
	errs := make([]error, 0, len(c.links)+1)
	for _, l := range c.links {
		errs = append(errs, l.Close())
	}
	c.links = nil
	errs = append(errs, c.objs.Close())
	return errors.Join(errs...)
}

func readMap(m *ebpf.Map) (map[Key]uint64, error) {
	out := map[Key]uint64{}
	var (
		key    XmitdropsXmitDropKey
		perCPU []uint64
	)
	iter := m.Iterate()
	for iter.Next(&key, &perCPU) {
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		out[Key{Ifindex: key.Ifindex, Stage: Stage(key.Stage), Errno: key.Err}] = sum
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("read XDP transmit drop counters: %w", err)
	}
	return out, nil
}
