// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"

	"go.datum.net/galactic/internal/plumbing/intf"
)

func hostDeviceExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot determine executable path: %w", err)
	}
	path := filepath.Join(filepath.Dir(exe), "host-device")
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("host-device binary not found at %s: %w", path, err)
	}
	return path, nil
}

func hostDevice(command string, skelArgs *skel.CmdArgs, pluginConf *PluginConf) error {
	hostDevicePath, err := hostDeviceExecutable()
	if err != nil {
		return fmt.Errorf("resolve host-device binary: %w", err)
	}

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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := invokeExec.ExecPlugin(ctx, hostDevicePath, conf, invokeArgs.AsEnv())
	if err != nil {
		return fmt.Errorf("host-device plugin failed: %w", err)
	}
	if result == nil {
		return errors.New("host-device plugin returned nil result")
	}
	_ = result // Result validated as non-nil; host-device is a delegation helper, not an IPAM provider.
	return nil
}
