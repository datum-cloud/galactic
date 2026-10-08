// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"os"
	"path/filepath"
	"testing"

	"go.datum.net/galactic/internal/fabric/testpki"
)

func TestSync(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	s := &Sync{Source: src, Dest: dst}

	// Nothing issued yet: nothing to do, and no error.
	if changed, err := s.Once(); changed || err != nil {
		t.Fatalf("empty source: %v %v", changed, err)
	}

	ca := testpki.NewCA(t, "dfw")
	id := Node("dfw", "galactic-system", "fabric-api-certs-abc")
	ca.Issue(t, src, testpki.Options{URIs: []string{id.URI()}})
	if changed, err := s.Once(); !changed || err != nil {
		t.Fatalf("first sync: %v %v", changed, err)
	}
	c := &Credentials{CertFile: filepath.Join(dst, "tls.crt"), KeyFile: filepath.Join(dst, "tls.key"),
		CAFile: filepath.Join(dst, "ca.crt"), Self: Node("dfw", "galactic-system", ""), AcceptAnyNode: true}
	if err := c.Reload(); err != nil {
		t.Fatalf("synced credentials do not load: %v", err)
	}
	if changed, err := s.Once(); changed || err != nil {
		t.Fatalf("unchanged source rewrote dest: %v %v", changed, err)
	}

	// A renewal is copied.
	ca.Issue(t, src, testpki.Options{URIs: []string{id.URI()}})
	if changed, err := s.Once(); !changed || err != nil {
		t.Fatalf("renewal: %v %v", changed, err)
	}

	// A torn source (key from another certificate) is not copied.
	before, _ := os.ReadFile(filepath.Join(dst, "tls.crt"))
	other := t.TempDir()
	ca.Issue(t, other, testpki.Options{URIs: []string{id.URI()}})
	key, _ := os.ReadFile(filepath.Join(other, "tls.key"))
	if err := os.WriteFile(filepath.Join(src, "tls.key"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Once(); err == nil {
		t.Error("mismatched key pair was accepted")
	}
	after, _ := os.ReadFile(filepath.Join(dst, "tls.crt"))
	if string(before) != string(after) {
		t.Error("a torn source changed dest")
	}
}
