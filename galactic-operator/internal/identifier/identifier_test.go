package identifier_test

import (
	"testing"

	"github.com/datum-cloud/galactic-operator/internal/identifier"
)

func TestForVPC(t *testing.T) {
	id := identifier.NewFromSeed(424242)
	tests := []struct {
		name           string
		value          uint64
		wantIdentifier string
		wantError      bool
	}{
		{"InvalidSpecialMin", 0, "", true},
		{"InvalidSpecialMax", 0xFFFFFFFFFFFF, "", true},
		{"ValidMin", 1, "000000000001", false},
		{"ValidMax", 0xFFFFFFFFFFFF - 1, "fffffffffffe", false},
		{"Valid", 12345, "000000003039", false},
		{"InvalidMax", 0xFFFFFFFFFFFF + 1, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := id.FromValue(tt.value, identifier.MaxVPC)
			if (err != nil) != tt.wantError {
				t.Errorf("NewFromInteger() error = %v, wantError = %v", err, tt.wantError)
			}
			if got != tt.wantIdentifier {
				t.Errorf("NewFromInteger() got = %v, want = %v", got, tt.wantIdentifier)
			}
		})
	}
}

func TestForVPCAttachment(t *testing.T) {
	id := identifier.NewFromSeed(424242)
	tests := []struct {
		name           string
		value          uint64
		wantIdentifier string
		wantError      bool
	}{
		{"InvalidSpecialMin", 0, "", true},
		{"InvalidSpecialMax", 0xFFFF, "", true},
		{"ValidMin", 1, "0001", false},
		{"ValidMax", 0xFFFF - 1, "fffe", false},
		{"Valid", 12345, "3039", false},
		{"InvalidMax", 0xFFFF + 1, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := id.FromValue(tt.value, identifier.MaxVPCAttachment)
			if (err != nil) != tt.wantError {
				t.Errorf("NewFromInteger() error = %v, wantError = %v", err, tt.wantError)
			}
			if got != tt.wantIdentifier {
				t.Errorf("NewFromInteger() got = %v, want = %v", got, tt.wantIdentifier)
			}
		})
	}
}
