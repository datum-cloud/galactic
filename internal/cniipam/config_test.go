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
	testCNIVersion     = "1.0.0"
	testIPAMType       = "galactic-ipam"
	testIPv6SubnetCIDR = "fd00::/64"
	testIPv4SubnetCIDR = "10.0.0.0/24"
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
			name:    "MissingIPAMBlockRejected",
			input:   fmt.Sprintf(`{"cniVersion":"%s","name":"test","type":"%s"}`, testCNIVersion, testIPAMType),
			wantErr: "ipam block is required",
		},
		{
			name:     "StaticIPAccepted",
			input:    confJSON(fmt.Sprintf(`"type":%q,"static_ip":"fd00::1234"`, testIPAMType)),
			wantType: testIPAMType,
		},
		{
			name:    "InvalidIPv6SubnetCIDRRejected",
			input:   confJSON(fmt.Sprintf(`"type":%q,"ipv6_subnet":"not-a-cidr"`, testIPAMType)),
			wantErr: "invalid CIDR value for field 'ipam.ipv6_subnet'",
		},
		{
			name:    "IPv4GivenWhereIPv6SubnetExpectedRejected",
			input:   confJSON(fmt.Sprintf(`"type":%q,"ipv6_subnet":"10.0.0.0/24"`, testIPAMType)),
			wantErr: "ipam.ipv6_subnet must be an IPv6 CIDR, got IPv4",
		},
		{
			name:    "IPv6SubnetPrefixLengthOver96Rejected",
			input:   confJSON(fmt.Sprintf(`"type":%q,"ipv6_subnet":"fd00:10:ff01::/112"`, testIPAMType)),
			wantErr: "ipam.ipv6_subnet prefix length 112 exceeds maximum of 96",
		},
		{
			name:    "InvalidIPv4SubnetCIDRRejected",
			input:   confJSON(fmt.Sprintf(`"type":%q,"ipv4_subnet":"not-a-cidr"`, testIPAMType)),
			wantErr: "invalid CIDR value for field 'ipam.ipv4_subnet'",
		},
		{
			name:    "IPv6GivenWhereIPv4SubnetExpectedRejected",
			input:   confJSON(fmt.Sprintf(`"type":%q,"ipv4_subnet":"2001:db8::/64"`, testIPAMType)),
			wantErr: "ipam.ipv4_subnet must be an IPv4 CIDR, got IPv6",
		},
		{
			name:    "IPv4SubnetPrefixLengthOver32Rejected",
			input:   confJSON(fmt.Sprintf(`"type":%q,"ipv4_subnet":"::ffff:10.0.0.0/40"`, testIPAMType)),
			wantErr: "ipam.ipv4_subnet prefix length 40 exceeds maximum of 32",
		},
		{
			name: "InvalidAddressFamiliesEntryRejected",
			input: confJSON(fmt.Sprintf(
				`"type":%q,"ipv6_subnet":"fd00::/64","address_families":["ipv6","bogus"]`, testIPAMType)),
			wantErr: `invalid ipam.address_families entry "bogus"`,
		},
		{
			name: "AddressFamiliesExcludingEveryConfiguredPoolRejected",
			input: confJSON(fmt.Sprintf(
				`"type":%q,"ipv6_subnet":"fd00::/64","address_families":["ipv4"]`, testIPAMType)),
			wantErr: "excludes every pool this config configures",
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
	conf, err = parseConf([]byte(confJSON(fmt.Sprintf(
		`"type":%q,"ipv4_subnet":%q`, testIPAMType, testIPv4SubnetCIDR))))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.IPAM.IPv6Subnet != "" {
		t.Errorf("IPv6Subnet = %q, want empty (ipv4_subnet already specified)", conf.IPAM.IPv6Subnet)
	}
}

// TestParseConfAddressFamiliesRestrictsConfiguredPools covers issue #330:
// address_families must actually narrow which of ipv6_subnet/ipv4_subnet
// take effect, not just be validated and discarded.
func TestParseConfAddressFamiliesRestrictsConfiguredPools(t *testing.T) {
	bothSubnets := fmt.Sprintf(`"ipv6_subnet":%q,"ipv4_subnet":%q`, testIPv6SubnetCIDR, testIPv4SubnetCIDR)

	tests := []struct {
		name           string
		input          string
		wantIPv6Subnet string
		wantIPv4Subnet string
	}{
		{
			// The issue's own repro: both pools configured, restricted to
			// IPv6 — the IPv4 pool must not survive parseConf.
			name: "RestrictsToIPv6WhenBothConfigured",
			input: confJSON(fmt.Sprintf(
				`"type":%q,%s,"address_families":["ipv6"]`, testIPAMType, bothSubnets)),
			wantIPv6Subnet: testIPv6SubnetCIDR,
			wantIPv4Subnet: "",
		},
		{
			name: "RestrictsToIPv4WhenBothConfigured",
			input: confJSON(fmt.Sprintf(
				`"type":%q,%s,"address_families":["ipv4"]`, testIPAMType, bothSubnets)),
			wantIPv6Subnet: "",
			wantIPv4Subnet: testIPv4SubnetCIDR,
		},
		{
			name: "BothFamiliesListedLeavesDualStackUnaffected",
			input: confJSON(fmt.Sprintf(
				`"type":%q,%s,"address_families":["ipv6","ipv4"]`, testIPAMType, bothSubnets)),
			wantIPv6Subnet: testIPv6SubnetCIDR,
			wantIPv4Subnet: testIPv4SubnetCIDR,
		},
		{
			// Regression test: an unset field must mean "no restriction",
			// not silently default to IPv6-only.
			name:           "UnsetLeavesBothConfiguredPoolsUnaffected",
			input:          confJSON(fmt.Sprintf(`"type":%q,%s`, testIPAMType, bothSubnets)),
			wantIPv6Subnet: testIPv6SubnetCIDR,
			wantIPv4Subnet: testIPv4SubnetCIDR,
		},
		{
			// Meaningless for the static path — the filter must not touch
			// anything when static_ip is set, even if address_families
			// would otherwise exclude every pool.
			name: "StaticIPBypassesFilter",
			input: confJSON(fmt.Sprintf(
				`"type":%q,"static_ip":"fd00::1234","address_families":["ipv4"]`, testIPAMType)),
			wantIPv6Subnet: "",
			wantIPv4Subnet: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf, err := parseConf([]byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if conf.IPAM.IPv6Subnet != tt.wantIPv6Subnet {
				t.Errorf("IPv6Subnet = %q, want %q", conf.IPAM.IPv6Subnet, tt.wantIPv6Subnet)
			}
			if conf.IPAM.IPv4Subnet != tt.wantIPv4Subnet {
				t.Errorf("IPv4Subnet = %q, want %q", conf.IPAM.IPv4Subnet, tt.wantIPv4Subnet)
			}
		})
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

// addressesJSON is the dual-stack addresses block used by the cases below.
const addressesJSON = `"addresses":[` +
	`{"address":"fd20:60:ff03:0:1::/96","gateway":"fd20:60:ff03::1"},` +
	`{"address":"203.0.113.17/32","gateway":"203.0.113.1"}]`

func TestParseConfAddresses(t *testing.T) {
	conf, err := parseConf([]byte(confJSON(fmt.Sprintf(`"type":%q,%s`, testIPAMType, addressesJSON))))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(conf.IPAM.Addresses) != 2 {
		t.Fatalf("Addresses = %v, want both families", conf.IPAM.Addresses)
	}
	if conf.IPAM.IPv6Subnet != "" || conf.IPAM.IPv4Subnet != "" {
		t.Errorf("IPv6Subnet/IPv4Subnet = %q/%q, want both empty (the addresses path allocates nothing)",
			conf.IPAM.IPv6Subnet, conf.IPAM.IPv4Subnet)
	}
}

// TestParseConfAddressesDefaultFillerDoesNotApply guards against the local
// IPAM default pool being filled in behind a config that already carries its
// own addresses.
func TestParseConfAddressesDefaultFillerDoesNotApply(t *testing.T) {
	t.Setenv("GALACTIC_IPAM_ENABLE_LOCAL_IPAM", "true")

	conf, err := parseConf([]byte(confJSON(fmt.Sprintf(`"type":%q,%s`, testIPAMType, addressesJSON))))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.IPAM.IPv6Subnet != "" {
		t.Errorf("IPv6Subnet = %q, want empty", conf.IPAM.IPv6Subnet)
	}
}

// TestParseConfAddressesWithAddressFamilies covers address_families being
// meaningless here rather than rejecting the config: these addresses were
// decided upstream and are carried as given.
func TestParseConfAddressesWithAddressFamilies(t *testing.T) {
	body := fmt.Sprintf(`"type":%q,%s,"address_families":["ipv6"]`, testIPAMType, addressesJSON)
	if _, err := parseConf([]byte(confJSON(body))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseConfAddressesRejectsMixedModes(t *testing.T) {
	tests := []struct{ name, extra string }{
		{"WithStaticIP", `"static_ip":"fd00:1::1"`},
		{"WithIPv6Subnet", fmt.Sprintf(`"ipv6_subnet":%q`, testIPv6SubnetCIDR)},
		{"WithIPv4Subnet", fmt.Sprintf(`"ipv4_subnet":%q`, testIPv4SubnetCIDR)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`"type":%q,%s,%s`, testIPAMType, addressesJSON, tt.extra)
			_, err := parseConf([]byte(confJSON(body)))
			if err == nil {
				t.Fatal("expected a config error combining ipam.addresses with another mode, got nil")
			}
			if !strings.Contains(err.Error(), "ipam.addresses cannot be combined") {
				t.Errorf("error = %v, want the mixed-mode rejection", err)
			}
		})
	}
}
