package util_test

import (
	"net"
	"reflect"
	"testing"

	"github.com/datum-cloud/galactic-common/util"
)

func TestGenerateInterfaceNameVRF(t *testing.T) {
	vpc := "0000000jU"     // 1234 dec
	vpcattachment := "00G" // 42 dec
	expected := "G0000000jU00GV"
	got := util.GenerateInterfaceNameVRF(vpc, vpcattachment)
	if got != expected {
		t.Errorf("GenerateInterfaceNameVRF(%s, %s) = %s, want %s", vpc, vpcattachment, got, expected)
	}
}

func TestGenerateInterfaceNameHost(t *testing.T) {
	vpc := "0000000jU"     // 1234 dec
	vpcattachment := "00G" // 42 dec
	expected := "G0000000jU00GH"
	got := util.GenerateInterfaceNameHost(vpc, vpcattachment)
	if got != expected {
		t.Errorf("GenerateInterfaceNameHost(%s, %s) = %s, want %s", vpc, vpcattachment, got, expected)
	}
}

func TestGenerateInterfaceNameGuest(t *testing.T) {
	vpc := "0000000jU"     // 1234 dec
	vpcattachment := "00G" // 42 dec
	expected := "G0000000jU00GG"
	got := util.GenerateInterfaceNameGuest(vpc, vpcattachment)
	if got != expected {
		t.Errorf("GenerateInterfaceNameGuest(%s, %s) = %s, want %s", vpc, vpcattachment, got, expected)
	}
}

func TestParseIP(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantIP    net.IP
		wantError bool
	}{
		{"ValidIPv4", "192.168.0.1", net.ParseIP("192.168.0.1"), false},
		{"ValidIPv6", "2607:ed40:ff00::1", net.ParseIP("2607:ed40:ff00::1"), false},
		{"InvalidIP", "not_an_ip", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := util.ParseIP(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("ParseIP() error = %v, wantError = %v", err, tt.wantError)
			}
			if !reflect.DeepEqual(got, tt.wantIP) {
				t.Errorf("ParseIP() got = %v, want = %v", got, tt.wantIP)
			}
		})
	}
}

func TestParseSegments(t *testing.T) {
	tests := []struct {
		name      string
		input     []string
		wantIPs   []net.IP
		wantError bool
	}{
		{
			"ValidSingleSegment",
			[]string{"2607:ed40:ff00::1"},
			[]net.IP{net.ParseIP("2607:ed40:ff00::1")},
			false,
		},
		{
			"ValidMultipleSegments",
			[]string{"2607:ed40:ff00::1", "2607:ed40:ff01::1"},
			[]net.IP{net.ParseIP("2607:ed40:ff01::1"), net.ParseIP("2607:ed40:ff00::1")},
			false,
		},
		{
			"InvalidSegment",
			[]string{"2607:ed40:ff00::1", "invalid_ip"},
			nil,
			true,
		},
		{
			"InvalidIPv4Segment",
			[]string{"2607:ed40:ff00::1", "192.168.0.1"},
			nil,
			true,
		},
		{
			"EmptyInput",
			[]string{},
			nil,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := util.ParseSegments(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("ParseSegments() error = %v, wantError = %v", err, tt.wantError)
			}
			if !tt.wantError && !reflect.DeepEqual(got, tt.wantIPs) {
				t.Errorf("ParseSegments() got = %v, want = %v", got, tt.wantIPs)
			}
		})
	}
}

func TestDecodeSRv6Endpoint(t *testing.T) {
	srv6Endpoint := "2607:ed40:ff00::0000:0000:04d2:002a"
	vpc := "0000000004d2"
	vpcAttachment := "002a"
	gotVpc, gotVpcAttachment, _ := util.DecodeSRv6Endpoint(net.ParseIP(srv6Endpoint))
	if gotVpc != vpc || gotVpcAttachment != vpcAttachment {
		t.Errorf("DecodeSRv6Endpoint(%s) = %s, %s, want %s, %s", srv6Endpoint, gotVpc, gotVpcAttachment, vpc, vpcAttachment)
	}
}
