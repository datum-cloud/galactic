// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"

	"go.datum.net/galactic/internal/plumbing/intf"
)

func hostDeviceExecutable() string {
	path, _ := os.Executable()
	dir := filepath.Dir(path)
	return filepath.Join(dir, "host-device")
}

func hostDevice(command string, skelArgs *skel.CmdArgs, pluginConf *PluginConf) error {
	conf, err := json.Marshal(HostDevicePluginConf{
		PluginConf: types.PluginConf{
			CNIVersion: pluginConf.CNIVersion,
			Name:       pluginConf.Name,
			Type:       "host-device",
		},
		Device: intf.GenerateInterfaceNameGuest(pluginConf.VPC, pluginConf.VPCAttachment),
	})
	if err != nil {
		return err
	}

	invokeExec := &invoke.DefaultExec{
		RawExec:       &invoke.RawExec{Stderr: os.Stderr},
		PluginDecoder: version.PluginDecoder{},
	}
	invokeArgs := invoke.Args{
		Command:       command,
		ContainerID:   skelArgs.ContainerID,
		NetNS:         skelArgs.Netns,
		PluginArgsStr: skelArgs.Args,
		IfName:        skelArgs.IfName,
		Path:          skelArgs.Path,
	}
	if _, err := invokeExec.ExecPlugin(
		context.Background(), hostDeviceExecutable(), conf,
		invokeArgs.AsEnv(),
	); err != nil {
		return err
	}
	return nil
}
