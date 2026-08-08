// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cniipam

import (
	"fmt"
	"strings"
	"testing"
)

const (
	testCNIVersion = "1.0.0"
	testIPAMType   = "galactic-ipam"
)

// confJSON builds a minimal CNI config document carrying the given "ipam"
// block body (already-JSON-encoded, e.g. `"type":"galactic-ipam"`), keeping
// every test case below short enough to stay under the project's line
// length limit.
func confJSON(ipamBody string) string {
	return fmt.Sprintf(`{"cniVersion":"%s","name":"test","ipam":{%s}}`, testCNIVersion, ipamBody)
}

func TestParseConf(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantErr  string
		wantType string
	}{
		{
			name:    "missing ipam block rejected",
			input:   fmt.Sprintf(`{"cniVersion":"%s","name":"test","type":"%s"}`, testCNIVersion, testIPAMType),
			wantErr: "ipam block is required",
		},
		{
			name:     "static_ip accepted",
			input:    confJSON(fmt.Sprintf(`"type":%q,"static_ip":"fd00::1234"`, testIPAMType)),
			wantType: testIPAMType,
		},
		{
			name:    "invalid ipv6_subnet CIDR rejected",
			input:   confJSON(fmt.Sprintf(`"type":%q,"ipv6_subnet":"not-a-cidr"`, testIPAMType)),
			wantErr: "invalid CIDR value for field 'ipam.ipv6_subnet'",
		},
		{
			name:    "ipv4 given where ipv6_subnet expected rejected",
			input:   confJSON(fmt.Sprintf(`"type":%q,"ipv6_subnet":"10.0.0.0/24"`, testIPAMType)),
			wantErr: "ipam.ipv6_subnet must be an IPv6 CIDR, got IPv4",
		},
		{
			name:    "ipv6_subnet prefix length over 96 rejected",
			input:   confJSON(fmt.Sprintf(`"type":%q,"ipv6_subnet":"fd00:10:ff01::/112"`, testIPAMType)),
			wantErr: "ipam.ipv6_subnet prefix length 112 exceeds maximum of 96",
		},
		{
			name:    "invalid ipv4_subnet CIDR rejected",
			input:   confJSON(fmt.Sprintf(`"type":%q,"ipv4_subnet":"not-a-cidr"`, testIPAMType)),
			wantErr: "invalid CIDR value for field 'ipam.ipv4_subnet'",
		},
		{
			name:    "ipv6 given where ipv4_subnet expected rejected",
			input:   confJSON(fmt.Sprintf(`"type":%q,"ipv4_subnet":"2001:db8::/64"`, testIPAMType)),
			wantErr: "ipam.ipv4_subnet must be an IPv4 CIDR, got IPv6",
		},
		{
			name:    "ipv4_subnet prefix length over 32 rejected",
			input:   confJSON(fmt.Sprintf(`"type":%q,"ipv4_subnet":"::ffff:10.0.0.0/40"`, testIPAMType)),
			wantErr: "ipam.ipv4_subnet prefix length 40 exceeds maximum of 32",
		},
		{
			name: "invalid address_families entry rejected",
			input: confJSON(fmt.Sprintf(
				`"type":%q,"ipv6_subnet":"fd00::/64","address_families":["ipv6","bogus"]`, testIPAMType)),
			wantErr: `invalid ipam.address_families entry "bogus"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf, err := parseConf([]byte(tt.input))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if conf.IPAM.Type != tt.wantType {
				t.Errorf("IPAM.Type = %q, want %q", conf.IPAM.Type, tt.wantType)
			}
		})
	}
}

func TestParseConfDefaultFillerOnlyWhenUnderspecified(t *testing.T) {
	t.Setenv("GALACTIC_IPAM_ENABLE_LOCAL_IPAM", "true")

	// ipam present but specifies neither static_ip nor a subnet: filled in.
	conf, err := parseConf([]byte(confJSON(fmt.Sprintf(`"type":%q`, testIPAMType))))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.IPAM.IPv6Subnet != localIPAMDefaultPool {
		t.Errorf("IPv6Subnet = %q, want default-filled %q", conf.IPAM.IPv6Subnet, localIPAMDefaultPool)
	}

	// ipam present and already specifies a subnet: default-filler must not
	// override it.
	conf, err = parseConf([]byte(confJSON(fmt.Sprintf(`"type":%q,"ipv4_subnet":"10.0.0.0/24"`, testIPAMType))))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.IPAM.IPv6Subnet != "" {
		t.Errorf("IPv6Subnet = %q, want empty (ipv4_subnet already specified)", conf.IPAM.IPv6Subnet)
	}
}

func TestParseConfDefaultFillerRequiresEnvVar(t *testing.T) {
	t.Setenv("GALACTIC_IPAM_ENABLE_LOCAL_IPAM", "false")

	conf, err := parseConf([]byte(confJSON(fmt.Sprintf(`"type":%q`, testIPAMType))))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.IPAM.IPv6Subnet != "" || conf.IPAM.IPv4Subnet != "" {
		t.Errorf("IPv6Subnet/IPv4Subnet = %q/%q, want both empty (default-filler disabled)",
			conf.IPAM.IPv6Subnet, conf.IPAM.IPv4Subnet)
	}
}

func TestParseStatusConf(t *testing.T) {
	if err := parseStatusConf([]byte(`{"cniVersion":"1.0.0"}`)); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := parseStatusConf([]byte(`not json`)); err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
	if err := parseStatusConf([]byte(`{}`)); err == nil {
		t.Error("expected error for missing cniVersion, got nil")
	}
}
