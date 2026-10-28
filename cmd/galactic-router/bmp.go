// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/runtime/gobgp"
)

// bmpConfigFromRouter builds the runtime's BMP configuration from cfg, naming
// the router nodeName in each collector's Initiation message. It returns the
// zero BMPConfig, which disables BMP, when no stations are configured, and an
// error for a station or policy cfg.Validate would also reject.
func bmpConfigFromRouter(cfg *config.RouterConfig, nodeName string) (gobgp.BMPConfig, error) {
	if len(cfg.BMPStations) == 0 {
		return gobgp.BMPConfig{}, nil
	}
	policy, err := gobgp.ParseBMPPolicy(cfg.BMPPolicy)
	if err != nil {
		return gobgp.BMPConfig{}, err
	}
	stations := make([]gobgp.BMPStation, 0, len(cfg.BMPStations))
	for _, s := range cfg.BMPStations {
		host, port, err := config.ParseBMPStation(s)
		if err != nil {
			return gobgp.BMPConfig{}, fmt.Errorf("%s: %w", config.EnvRouterBMPStations, err)
		}
		stations = append(stations, gobgp.BMPStation{Host: host, Port: port})
	}
	return gobgp.BMPConfig{
		Stations:           stations,
		Policy:             policy,
		StatisticsInterval: cfg.BMPStatisticsInterval,
		SysName:            nodeName,
		Observer:           gobgp.BMPStationGauge{},
	}, nil
}
