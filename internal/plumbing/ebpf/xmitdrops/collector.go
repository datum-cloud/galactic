// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xmitdrops

import (
	"log/slog"
	"net"
	"strconv"
	"strings"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

// Reader is the one operation Collector needs from a Counter, so tests can
// substitute an in-memory fake.
type Reader interface {
	Read() (map[Key]uint64, error)
}

const (
	labelInterface = "interface"
	labelReason    = "reason"
)

const help = "XDP frames the kernel dropped after an XDP program redirected them to an interface in " +
	"the gateway's network namespace, by that interface and reason (stage and errno). redirect_* " +
	"reasons are frames xdp_do_redirect could not queue, for example to an interface that cannot " +
	"take XDP frames (redirect_eopnotsupp); xmit_* reasons are frames the target's driver dropped " +
	"when they were flushed to it. The redirecting program counts these as forwarded, so they " +
	"appear in no drops_total. Every XDP program that redirects into this namespace is counted, " +
	"not only the gateway's. interface is the ifindex when the interface no longer exists. Reset " +
	"when the gateway restarts."

// Collector exports a Reader's counts as <namespace>_redirect_xmit_drops_total.
type Collector struct {
	reader Reader
	desc   *prometheus.Desc
	// ifname resolves an ifindex to its name in this process's network
	// namespace. Overridden in tests.
	ifname func(ifindex uint32) string
}

// NewCollector returns a Collector for reader, naming its metric under
// namespace.
func NewCollector(namespace string, reader Reader) *Collector {
	return &Collector{
		reader: reader,
		desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "redirect_xmit_drops_total"),
			help,
			[]string{labelInterface, labelReason}, nil,
		),
		ifname: interfaceName,
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	counts, err := c.reader.Read()
	if err != nil {
		slog.Warn("Cannot read the XDP transmit drop counters", "err", err)
		return
	}
	// Two ifindexes can resolve to the same label set when an interface is
	// replaced between drops, so sum by label set before emitting.
	type labelSet struct{ iface, reason string }
	sums := map[labelSet]uint64{}
	for k, v := range counts {
		sums[labelSet{c.ifname(k.Ifindex), Reason(k.Stage, k.Errno)}] += v
	}
	for ls, v := range sums {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(v), ls.iface, ls.reason)
	}
}

// Reason is the reason label for a stage and errno: the stage, then the
// errno's lowercase name, or "dropped" when the driver reported none.
func Reason(stage Stage, errno uint32) string {
	name := "dropped"
	if errno != 0 {
		name = unix.ErrnoName(syscall.Errno(errno))
		// Linux gives ENOTSUP and EOPNOTSUPP one value, and the kernel's XDP
		// paths return it as EOPNOTSUPP.
		if syscall.Errno(errno) == unix.EOPNOTSUPP {
			name = "EOPNOTSUPP"
		}
		if name == "" {
			name = "errno_" + strconv.FormatUint(uint64(errno), 10)
		}
	}
	return stage.String() + "_" + strings.ToLower(name)
}

func interfaceName(ifindex uint32) string {
	if iface, err := net.InterfaceByIndex(int(ifindex)); err == nil {
		return iface.Name
	}
	return strconv.FormatUint(uint64(ifindex), 10)
}
