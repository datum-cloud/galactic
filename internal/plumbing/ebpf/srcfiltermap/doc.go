// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package srcfiltermap implements the read/write API for the eBPF uSID
// datapath's SRv6 ingress source filter: src_allow_table, uplink_slot_table,
// src_filter_config_table, src_filter_stats and src_filter_denied.
//
// It decides nothing about which sources are allowed or when. A control-plane
// reconciler computes the desired allow-list and uplink slots and applies them
// here, then marks the filter populated once its first complete sync lands.
// Until then the datapath lets every packet through, counted as a bypass.
package srcfiltermap
