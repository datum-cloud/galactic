// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"testing"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/dan"
	"go.datum.net/galactic/internal/plumbing/intf"
)

// A tap handed to its guest by a DAN file has a MAC the host knows, so the
// host gateway can prime the guest's neighbor entry; any other tap has none.
func TestTapGuestHWAddrReadsTheDANFile(t *testing.T) {
	saved := cniConfig
	t.Cleanup(func() { cniConfig = saved })
	cniConfig = config.NewCNIConfig()
	cniConfig.DANDir = t.TempDir()

	const vpc, attachment = "7nXb3k", "2fLq9w"
	tap := intf.GenerateInterfaceNameHost(vpc, attachment)
	if err := dan.Write(cniConfig.DANDir, "sandbox-1", &dan.Document{Devices: []dan.Device{{
		Name: "guest0", GuestMAC: "02:a7:de:f3:26:ef",
		Device: dan.DeviceSpec{Type: dan.DeviceTypeHostTap, TapName: tap},
	}}}); err != nil {
		t.Fatalf("write DAN file: %v", err)
	}

	if mac := tapGuestHWAddr("sandbox-1", vpc, attachment); mac.String() != "02:a7:de:f3:26:ef" {
		t.Errorf("guest MAC = %v, want 02:a7:de:f3:26:ef", mac)
	}
	if mac := tapGuestHWAddr("sandbox-2", vpc, attachment); mac != nil {
		t.Errorf("a sandbox with no DAN file got guest MAC %v, want none", mac)
	}
}
