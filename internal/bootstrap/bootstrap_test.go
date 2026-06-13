package bootstrap

import (
	"testing"
)

func TestProviderName(t *testing.T) {
	cases := []struct {
		node string
		want string
	}{
		{"worker-1", "galactic-gobgp-worker-1"},
		{"node-abc", "galactic-gobgp-node-abc"},
	}
	for _, tc := range cases {
		got := providerName(tc.node)
		if got != tc.want {
			t.Errorf("providerName(%q) = %q, want %q", tc.node, got, tc.want)
		}
	}
}
