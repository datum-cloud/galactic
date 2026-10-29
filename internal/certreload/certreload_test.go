// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package certreload

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePair writes a new self-signed certificate for name and its key.
func writePair(t *testing.T, certFile, keyFile, name string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReloadsOnChange(t *testing.T) {
	dir := t.TempDir()
	r := &Reloader{CertFile: filepath.Join(dir, "tls.crt"), KeyFile: filepath.Join(dir, "tls.key")}
	if _, err := r.GetCertificate(nil); err == nil {
		t.Fatal("GetCertificate without files succeeded")
	}
	writePair(t, r.CertFile, r.KeyFile, "first.example.test")
	first, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := r.GetCertificate(nil); again != first {
		t.Fatal("unchanged files were reloaded")
	}
	writePair(t, r.CertFile, r.KeyFile, "second.example.test")
	// The rewrite must change the stamp even on a coarse clock.
	later := time.Now().Add(time.Second)
	for _, p := range []string{r.CertFile, r.KeyFile} {
		if err := os.Chtimes(p, later, later); err != nil {
			t.Fatal(err)
		}
	}
	second, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.Leaf == nil || second.Leaf.Subject.CommonName != "second.example.test" {
		t.Fatalf("certificate after rewrite = %v, want second.example.test", second.Leaf)
	}
}
