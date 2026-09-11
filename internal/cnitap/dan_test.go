// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/plumbing/dan"
)

// ipv6Result is a single-stack allocation, the shape a VPC attachment has
// today.
func ipv6Result() *cniipam.IPAMResult {
	_, subnet, _ := net.ParseCIDR("fd20:0:f::4:0:0/96")
	subnet.IP = net.ParseIP("fd20:0:f::4:0:0")
	return &cniipam.IPAMResult{
		IPv6Subnet:  subnet,
		IPv6Gateway: net.ParseIP("fd20:0:f::1"),
	}
}

// TestBuildDANDocumentDescribesTheAttachment checks the document against the
// values the plugin already holds, including the guest address and default
// route the guest is told to configure.
func TestBuildDANDocumentDescribesTheAttachment(t *testing.T) {
	document, err := buildDANDocument("G00000000bayhH", ipv6Result(), 1460)
	if err != nil {
		t.Fatalf("buildDANDocument: %v", err)
	}

	if len(document.Devices) != 1 {
		t.Fatalf("document holds %d devices, want 1", len(document.Devices))
	}
	device := document.Devices[0]
	if device.Device.Type != dan.DeviceTypeHostTap {
		t.Errorf("device type = %q, want %q", device.Device.Type, dan.DeviceTypeHostTap)
	}
	if device.Device.TapName != "G00000000bayhH" {
		t.Errorf("tap name = %q, want the host interface's", device.Device.TapName)
	}
	if device.NetworkInfo.Interface.MTU != 1460 {
		t.Errorf("MTU = %d, want 1460", device.NetworkInfo.Interface.MTU)
	}
	wantAddresses := []string{"fd20:0:f::4:0:0/96"}
	if !reflect.DeepEqual(device.NetworkInfo.Interface.IPAddresses, wantAddresses) {
		t.Errorf("addresses = %v, want %v", device.NetworkInfo.Interface.IPAddresses, wantAddresses)
	}
	wantRoutes := []dan.Route{{Gateway: "fd20:0:f::1"}}
	if !reflect.DeepEqual(device.NetworkInfo.Routes, wantRoutes) {
		t.Errorf("routes = %v, want %v", device.NetworkInfo.Routes, wantRoutes)
	}
	if device.NetworkInfo.Neighbors == nil {
		t.Error("neighbors is nil, want an empty list so the file carries []")
	}
}

// TestBuildDANDocumentOrdersDualStackAddresses covers a dual-stack attachment.
// Both families land on the one device, because the guest has one interface
// either way.
func TestBuildDANDocumentOrdersDualStackAddresses(t *testing.T) {
	res := ipv6Result()
	res.IPv4Address = net.ParseIP("10.244.1.5")
	res.IPv4Gateway = net.ParseIP("10.244.1.1")

	document, err := buildDANDocument("G00000000bayhH", res, 1460)
	if err != nil {
		t.Fatalf("buildDANDocument: %v", err)
	}
	if len(document.Devices) != 1 {
		t.Fatalf("document holds %d devices, want 1", len(document.Devices))
	}
	want := []string{"fd20:0:f::4:0:0/96", "10.244.1.5/25"}
	if !reflect.DeepEqual(document.Devices[0].NetworkInfo.Interface.IPAddresses, want) {
		t.Errorf("addresses = %v, want %v", document.Devices[0].NetworkInfo.Interface.IPAddresses, want)
	}
	wantRoutes := []dan.Route{{Gateway: "fd20:0:f::1"}, {Gateway: "10.244.1.1"}}
	if !reflect.DeepEqual(document.Devices[0].NetworkInfo.Routes, wantRoutes) {
		t.Errorf("routes = %v, want %v", document.Devices[0].NetworkInfo.Routes, wantRoutes)
	}
}

// TestGuestMACIsStableAndLocal covers the two properties the guest depends on:
// the same attachment always gets the same address, and the address is
// locally administered and unicast.
func TestGuestMACIsStableAndLocal(t *testing.T) {
	first := guestMAC("G00000000bayhH")
	if !reflect.DeepEqual(first, guestMAC("G00000000bayhH")) {
		t.Error("guest MAC differs between calls for the same tap")
	}
	if reflect.DeepEqual(first, guestMAC("G00000000otherH")) {
		t.Error("two taps share a guest MAC")
	}
	if first[0]&0x02 == 0 {
		t.Errorf("guest MAC %s is not locally administered", first)
	}
	if first[0]&0x01 != 0 {
		t.Errorf("guest MAC %s is a multicast address", first)
	}
}

// TestBuildDANDocumentRequiresAddresses covers the case where no address was
// allocated. A guest with a tap and no address looks healthy until traffic is
// tried, so the build must fail instead.
func TestBuildDANDocumentRequiresAddresses(t *testing.T) {
	for name, res := range map[string]*cniipam.IPAMResult{
		"no IPAM result": nil,
		"empty result":   {},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := buildDANDocument("G00000000bayhH", res, 1460); err == nil {
				t.Error("buildDANDocument succeeded, want an error")
			}
		})
	}
}

// TestWriteDANFileProducesTheProvenShape checks the whole path from allocation
// to bytes on disk against the document observed to work on a real node.
func TestWriteDANFileProducesTheProvenShape(t *testing.T) {
	dir := t.TempDir()
	if err := writeDANFile(dir, "sandbox-1", "G00000000bayhH", ipv6Result(), 1460); err != nil {
		t.Fatalf("writeDANFile: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "sandbox-1.json"))
	if err != nil {
		t.Fatalf("read DAN file: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("parse DAN file: %v", err)
	}

	devices, ok := got["devices"].([]any)
	if !ok || len(devices) != 1 {
		t.Fatalf("devices = %v, want one entry", got["devices"])
	}
	device := devices[0].(map[string]any)
	if device["guest_mac"] == "" {
		t.Error("guest_mac is empty, want an explicit address")
	}
	deviceSpec := device["device"].(map[string]any)
	if deviceSpec["type"] != "host-tap" || deviceSpec["tap_name"] != "G00000000bayhH" {
		t.Errorf("device = %v, want the host tap", deviceSpec)
	}
	if _, present := got["netns"]; present {
		t.Errorf("DAN JSON carries a netns field: %s", data)
	}
}

// TestWriteDANFileFailsOnTheGoShimDirectory checks that ADD's write reaches the
// guardrail rather than routing around it.
func TestWriteDANFileFailsOnTheGoShimDirectory(t *testing.T) {
	if err := writeDANFile(dan.GoShimDir, "sandbox-1", "G00000000bayhH", ipv6Result(), 1460); err == nil {
		t.Error("writeDANFile succeeded on the Go shim's directory, want refusal")
	}
}

// TestWriteDANFileReportsWriteFailures checks that a failed write surfaces to
// ADD. A sandbox with no DAN file comes up on the wrong network and looks
// healthy, so ADD must fail rather than continue.
func TestWriteDANFileReportsWriteFailures(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("create blocking file: %v", err)
	}
	if err := writeDANFile(blocked, "sandbox-1", "G00000000bayhH", ipv6Result(), 1460); err == nil {
		t.Error("writeDANFile succeeded where the directory cannot exist, want an error")
	}
}

// TestDANRequestedIsOptIn covers the gate that keeps DAN files off the path of
// a workload whose runtime never reads one.
func TestDANRequestedIsOptIn(t *testing.T) {
	base := `{"cniVersion":"1.0.0","name":"net","type":"galactic-tap","vpc":"a","vpcattachment":"b"`
	for name, tc := range map[string]struct {
		config string
		want   bool
	}{
		"field absent":     {base + "}", false},
		"explicitly false": {base + `,"dan":false}`, false},
		"explicitly true":  {base + `,"dan":true}`, true},
		"malformed config": {`{"dan":`, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := danRequested([]byte(tc.config)); got != tc.want {
				t.Errorf("danRequested = %v, want %v", got, tc.want)
			}
		})
	}
}
