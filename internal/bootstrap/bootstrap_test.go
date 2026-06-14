package bootstrap

import (
	"testing"
)

func TestProviderName(t *testing.T) {
	cases := []struct {
		node  string
		plane string
		want  string
	}{
		{"worker-1", "overlay", "galactic-gobgp-worker-1"},
		{"worker-1", "", "galactic-gobgp-worker-1"},
		{"node-abc", "overlay", "galactic-gobgp-node-abc"},
		{"iad-rr-worker", "overlay-rr", "galactic-gobgp-iad-rr-worker-overlay-rr"},
	}
	for _, tc := range cases {
		got := providerName(tc.node, tc.plane)
		if got != tc.want {
			t.Errorf("providerName(%q, %q) = %q, want %q", tc.node, tc.plane, got, tc.want)
		}
	}
}
