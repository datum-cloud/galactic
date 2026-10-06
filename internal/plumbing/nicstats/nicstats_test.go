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
				"[2]: rx_ucast_packets": 313000,
				"[2]: rx_discards":      23554,
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

type fakeReader struct {
	drivers map[string]string
	stats   map[string]map[string]uint64
}

func (f fakeReader) DriverName(intf string) (string, error) {
	d, ok := f.drivers[intf]
	if !ok {
		return "", errors.New("no such device")
	}
	return d, nil
}

func (f fakeReader) Stats(intf string) (map[string]uint64, error) {
	s, ok := f.stats[intf]
	if !ok {
		return nil, errors.New("no such device")
	}
	return s, nil
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
			stalled: {"[2]: rx_ucast_packets": 313000, "[2]: rx_discards": 23554},
			healthy: {"rx_queue_0_packets": 10},
			unknown: {"rx_queue_0_drops": 1},
		},
	}
	// gone has disappeared since the uplink set was resolved: it is left
	// out, and the scrape still succeeds.
	c := NewCollector("galactic_nat", reader, func() []string {
		return []string{stalled, healthy, unknown, "gone"}
	})

	want := `
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
