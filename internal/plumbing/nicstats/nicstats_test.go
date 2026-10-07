// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nicstats

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/safchain/ethtool"
)

// bnxt_en's counters for ring 2, the stalled queue from #673.
const (
	bnxtRing2Packets  = "[2]: rx_ucast_packets"
	bnxtRing2Discards = "[2]: rx_discards"
)

func TestParseQueueStats(t *testing.T) {
	tests := []struct {
		name   string
		driver string
		stats  map[string]uint64
		want   map[int]QueueStats
	}{
		{
			// Abridged from a bnxt_en uplink's ethtool -S. Queue 2 is the
			// stalled one from #673. Per-ring TX and port-wide counters are
			// ignored.
			name:   "bnxt_en packets and discards",
			driver: DriverBnxt,
			stats: map[string]uint64{
				"[0]: rx_ucast_packets": 100,
				"[0]: rx_mcast_packets": 5,
				"[0]: rx_bcast_packets": 1,
				"[0]: rx_discards":      0,
				"[0]: rx_errors":        3,
				"[0]: tx_ucast_packets": 90,
				bnxtRing2Packets:        313000,
				bnxtRing2Discards:       23554,
				"rx_total_discard_pkts": 23554,
				"rx_good_frames":        313106,
			},
			want: map[int]QueueStats{
				0: {Queue: 0, Packets: 106, Discards: 0, HasDiscards: true},
				2: {Queue: 2, Packets: 313000, Discards: 23554, HasDiscards: true},
			},
		},
		{
			name:   "ixgbe has no per-queue discards",
			driver: DriverIxgbe,
			stats: map[string]uint64{
				"rx_queue_0_packets":  10,
				"rx_queue_0_bytes":    1000,
				"rx_queue_11_packets": 20,
				"tx_queue_0_packets":  30,
				"rx_missed_errors":    7,
			},
			want: map[int]QueueStats{
				0:  {Queue: 0, Packets: 10},
				11: {Queue: 11, Packets: 20},
			},
		},
		{
			name:   "i40e packets only",
			driver: DriverI40e,
			stats:  map[string]uint64{"rx-3.packets": 4, "rx-3.bytes": 400, "tx-3.packets": 5},
			want:   map[int]QueueStats{3: {Queue: 3, Packets: 4}},
		},
		{
			// rxN_xdp_drop counts the XDP program's own drops, not the NIC's,
			// so it is not a discard.
			name:   "mlx5_core packets only",
			driver: DriverMlx5,
			stats:  map[string]uint64{"rx1_packets": 8, "rx1_xdp_drop": 2, "rx_packets": 8},
			want:   map[int]QueueStats{1: {Queue: 1, Packets: 8}},
		},
		{
			name:   "unknown driver",
			driver: "veth",
			stats:  map[string]uint64{"rx_queue_0_xdp_packets": 1, "rx_queue_0_drops": 1},
			want:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseQueueStats(tt.driver, tt.stats)
			if tt.want == nil {
				if got != nil {
					t.Fatalf("ParseQueueStats() = %v, want nil", got)
				}
				return
			}
			flat := map[int]QueueStats{}
			for k, v := range got {
				flat[k] = *v
			}
			if !reflect.DeepEqual(flat, tt.want) {
				t.Errorf("ParseQueueStats() = %+v, want %+v", flat, tt.want)
			}
		})
	}
}

func TestParseRingStats(t *testing.T) {
	// Abridged from a bnxt_en uplink's ethtool -S. Receive packets and
	// discards belong to ParseQueueStats, port-wide counters to neither.
	stats := map[string]uint64{
		"[0]: rx_ucast_packets": 100,
		"[0]: rx_discards":      0,
		"[0]: tx_ucast_packets": 90,
		"[0]: rx_buf_errors":    0,
		bnxtRing2Packets:        313000,
		bnxtRing2Discards:       23554,
		"[2]: tx_ucast_packets": 4,
		"[2]: tx_discards":      0,
		"[2]: tx_errors":        0,
		"[2]: rx_errors":        0,
		"[2]: rx_resets":        0,
		"[2]: missed_irqs":      0,
		"[2]: rx_ucast_bytes":   1,
		"tx_total_discard_pkts": 0,
	}
	want := []RingStat{
		{Queue: 0, Stat: "rx_buf_errors", Value: 0},
		{Queue: 0, Stat: "tx_ucast_packets", Value: 90},
		{Queue: 2, Stat: "missed_irqs", Value: 0},
		{Queue: 2, Stat: "rx_errors", Value: 0},
		{Queue: 2, Stat: "rx_resets", Value: 0},
		{Queue: 2, Stat: "tx_discards", Value: 0},
		{Queue: 2, Stat: "tx_errors", Value: 0},
		{Queue: 2, Stat: "tx_ucast_packets", Value: 4},
	}
	if got := ParseRingStats(DriverBnxt, stats); !reflect.DeepEqual(got, want) {
		t.Errorf("ParseRingStats() = %+v, want %+v", got, want)
	}
	if got := ParseRingStats(DriverIxgbe, map[string]uint64{"tx_queue_0_packets": 1}); got != nil {
		t.Errorf("ParseRingStats(ixgbe) = %+v, want nil", got)
	}
}

type fakeReader struct {
	drivers map[string]string
	stats   map[string]map[string]uint64
}

func (f fakeReader) DriverInfo(intf string) (ethtool.DrvInfo, error) {
	d, ok := f.drivers[intf]
	if !ok {
		return ethtool.DrvInfo{}, errors.New("no such device")
	}
	return ethtool.DrvInfo{Driver: d, Version: d + "-ver", FwVersion: d + "-fw"}, nil
}

func (f fakeReader) Stats(intf string) (map[string]uint64, error) {
	s, ok := f.stats[intf]
	if !ok {
		return nil, errors.New("no such device")
	}
	return s, nil
}

// info is the galactic_nat_uplink_info sample fakeReader's DriverInfo yields
// for iface on driver.
func info(driver, iface string) string {
	return `galactic_nat_uplink_info{driver="` + driver + `",driver_version="` + driver + `-ver",` +
		`firmware_version="` + driver + `-fw",interface="` + iface + `",kernel="6.8.0"} 1`
}

func TestCollector(t *testing.T) {
	const (
		stalled = "ens1f1np1"
		healthy = "eth0"
		unknown = "veth0"
	)
	reader := fakeReader{
		drivers: map[string]string{stalled: DriverBnxt, healthy: DriverIxgbe, unknown: "veth"},
		stats: map[string]map[string]uint64{
			stalled: {bnxtRing2Packets: 313000, bnxtRing2Discards: 23554, "[2]: tx_ucast_packets": 4},
			healthy: {"rx_queue_0_packets": 10},
			unknown: {"rx_queue_0_drops": 1},
		},
	}
	orig := kernelRelease
	kernelRelease = func() string { return "6.8.0" }
	t.Cleanup(func() { kernelRelease = orig })

	// gone has disappeared since the uplink set was resolved: it is left
	// out, and the scrape still succeeds. unknown's driver has no parser, so
	// it exports only its info.
	c := NewCollector("galactic_nat", reader, func() []string {
		return []string{stalled, healthy, unknown, "gone"}
	})

	want := `
# HELP galactic_nat_uplink_info ` + infoHelp + `
# TYPE galactic_nat_uplink_info gauge
` + info("bnxt_en", "ens1f1np1") + `
` + info("ixgbe", "eth0") + `
` + info("veth", "veth0") + `
# HELP galactic_nat_uplink_queue_driver_stat_total ` + ringStatHelp + `
# TYPE galactic_nat_uplink_queue_driver_stat_total counter
galactic_nat_uplink_queue_driver_stat_total{driver="bnxt_en",interface="ens1f1np1",queue="2",` +
		`stat="tx_ucast_packets"} 4
# HELP galactic_nat_uplink_rx_queue_discards_total ` + discardsHelp + `
# TYPE galactic_nat_uplink_rx_queue_discards_total counter
galactic_nat_uplink_rx_queue_discards_total{driver="bnxt_en",interface="ens1f1np1",queue="2"} 23554
# HELP galactic_nat_uplink_rx_queue_packets_total ` + packetsHelp + `
# TYPE galactic_nat_uplink_rx_queue_packets_total counter
galactic_nat_uplink_rx_queue_packets_total{driver="bnxt_en",interface="ens1f1np1",queue="2"} 313000
galactic_nat_uplink_rx_queue_packets_total{driver="ixgbe",interface="eth0",queue="0"} 10
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want)); err != nil {
		t.Error(err)
	}
}
