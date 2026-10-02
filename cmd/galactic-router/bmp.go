// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/runtime/gobgp"
)

// bmpStationUp reports, per BGPRouter and BMP station, whether the router's
// session to that collector is established. A station that is configured but
// down, or whose host does not resolve, reads 0, so an alert can tell a
// collector this router has lost apart from one it was never told about.
var bmpStationUp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "galactic_router_bmp_station_up",
	Help: "Whether the router's BMP session to a collector is established (1) or not (0).",
}, []string{"router", "station"})

func init() {
	ctrlmetrics.Registry.MustRegister(bmpStationUp)
}

// bmpGaugeObserver records each BMP station's state in bmpStationUp.
type bmpGaugeObserver struct{}

// BMPStationState sets the station's gauge to 1 when up and 0 otherwise.
func (bmpGaugeObserver) BMPStationState(router, station string, up bool) {
	v := 0.0
	if up {
		v = 1
	}
	bmpStationUp.WithLabelValues(router, station).Set(v)
}

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
		Observer:           bmpGaugeObserver{},
	}, nil
}
