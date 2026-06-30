// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"encoding/json"
	"fmt"
)

// parseConf unmarshals the CNI configuration from stdin data and validates
// the interface type. Returns an error if the config is malformed or
// interface_type is not one of the supported values.
func parseConf(data []byte) (*PluginConf, error) {
	conf := &PluginConf{}
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("parse CNI config: %w", err)
	}
	if conf.InterfaceType == "" {
		conf.InterfaceType = interfaceTypeVeth
	}
	switch conf.InterfaceType {
	case interfaceTypeVeth, interfaceTypeTap:
	default:
		return nil, fmt.Errorf(
			"invalid interface_type %q: must be %q or %q",
			conf.InterfaceType, interfaceTypeVeth, interfaceTypeTap,
		)
	}
	return conf, nil
}

// subnetAnnotationKey returns the annotation key for storing the allocated
// subnet for the given container ID. Kubernetes limits the name part of an
// annotation key to 63 bytes; "allocated-subnet." is 17 bytes, leaving 46
// bytes for the container ID prefix.
func subnetAnnotationKey(containerID string) string {
	id := containerID
	if len(id) > annotationContainerIDLen {
		id = id[:annotationContainerIDLen]
	}
	return fmt.Sprintf("%s.%s", annotationAllocatedSubnet, id)
}
