// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// credentialFiles are the files a credential directory holds, in the order
// Sync replaces them.
var credentialFiles = []string{"ca.crt", "tls.key", "tls.crt"}

// Sync copies a certificate, key and trust bundle from Source, a csi-driver
// volume, to Dest, a node-local directory the fabric-router pod's sidecar
// reads. It runs in the fabric-api-certs pod, so a certificate that cannot be
// issued stalls only that pod, never the fabric-router pod and FRR.
type Sync struct {
	Source string
	Dest   string
}

// Once copies the credentials if Source holds a complete, matching key pair
// that differs from Dest's. It reports whether it changed Dest.
func (s *Sync) Once() (bool, error) {
	src := map[string][]byte{}
	for _, f := range credentialFiles {
		b, err := os.ReadFile(filepath.Join(s.Source, f))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return false, nil
			}
			return false, err
		}
		src[f] = b
	}
	if _, err := tls.X509KeyPair(src["tls.crt"], src["tls.key"]); err != nil {
		return false, fmt.Errorf("source key pair: %w", err)
	}
	same := true
	for _, f := range credentialFiles {
		cur, err := os.ReadFile(filepath.Join(s.Dest, f))
		if err != nil || !bytes.Equal(cur, src[f]) {
			same = false
			break
		}
	}
	if same {
		return false, nil
	}
	// Each file is replaced atomically. A reader between two renames sees a
	// certificate that does not match its key and keeps its previous
	// credentials until its next reload.
	for _, f := range credentialFiles {
		tmp := filepath.Join(s.Dest, "."+f+".tmp")
		if err := os.WriteFile(tmp, src[f], 0o600); err != nil {
			return false, err
		}
		if err := os.Rename(tmp, filepath.Join(s.Dest, f)); err != nil {
			return false, err
		}
	}
	return true, nil
}

// Run syncs every interval until ctx ends.
func (s *Sync) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		changed, err := s.Once()
		switch {
		case err != nil:
			slog.Warn("could not sync fabric-api credentials", "error", err)
		case changed:
			slog.Info("synced fabric-api credentials", "dest", s.Dest)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
