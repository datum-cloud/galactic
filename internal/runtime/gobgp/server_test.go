// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"testing"
)

func TestBuildServerOptionsCount(t *testing.T) {
	tests := []struct {
		name           string
		grpcListenAddr string
		wantCount      int
	}{
		{
			name:           "Disabled",
			grpcListenAddr: "",
			wantCount:      1, // only LoggerOption
		},
		{
			name:           "Enabled",
			grpcListenAddr: ":50051",
			wantCount:      2, // LoggerOption + GrpcListenAddress
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newServer(Config{GRPCListenAddress: tt.grpcListenAddr})
			opts := s.buildServerOptions()
			if len(opts) != tt.wantCount {
				t.Errorf("buildServerOptions() has %d options, want %d", len(opts), tt.wantCount)
			}
		})
	}
}
