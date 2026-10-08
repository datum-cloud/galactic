// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"
)

// Credentials holds this process's certificate, key and trust bundle, read
// from files that cert-manager rewrites on renewal, and reloads them without
// a restart. Until the files exist and parse, every handshake fails closed
// and Err reports why; the process keeps running.
type Credentials struct {
	CertFile string
	KeyFile  string
	CAFile   string
	// Self is the identity this process must present. A certificate naming
	// any other identity is refused.
	Self ID
	// AcceptAnyNode relaxes Self for a node sidecar: any node identity in
	// Self's cell and namespace is accepted. The sidecar's certificate is
	// issued to the fabric-api-certs pod on its node, whose name the sidecar
	// does not know; the gateway pins the exact identity when it dials.
	AcceptAnyNode bool

	mu      sync.RWMutex
	cert    *tls.Certificate
	leaf    *x509.Certificate
	roots   *x509.CertPool
	err     error
	digest  [32]byte
	onLoad  []func(leaf *x509.Certificate)
	nowFunc func() time.Time
}

// ErrNotLoaded is reported before credentials have ever loaded.
var ErrNotLoaded = errors.New("credentials not loaded")

func (c *Credentials) now() time.Time {
	if c.nowFunc != nil {
		return c.nowFunc()
	}
	return time.Now()
}

// OnLoad registers fn to run with the leaf certificate each time new
// credentials load, e.g. to export its expiry.
func (c *Credentials) OnLoad(fn func(leaf *x509.Certificate)) {
	c.mu.Lock()
	c.onLoad = append(c.onLoad, fn)
	c.mu.Unlock()
}

// Reload reads the files and swaps in the new credentials if they changed
// and are valid. On failure the previous credentials stay in use, unless
// they have expired.
func (c *Credentials) Reload() error {
	certPEM, err1 := os.ReadFile(c.CertFile)
	keyPEM, err2 := os.ReadFile(c.KeyFile)
	caPEM, err3 := os.ReadFile(c.CAFile)
	if err := errors.Join(err1, err2, err3); err != nil {
		return c.fail(fmt.Errorf("read credentials: %w", err))
	}
	digest := sha256.Sum256(bytes.Join([][]byte{certPEM, keyPEM, caPEM}, []byte{0}))
	c.mu.RLock()
	unchanged := c.cert != nil && digest == c.digest
	c.mu.RUnlock()
	if unchanged {
		return c.checkExpiry()
	}

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return c.fail(fmt.Errorf("parse key pair: %w", err))
	}
	leaf := pair.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return c.fail(fmt.Errorf("parse certificate: %w", err))
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return c.fail(errors.New("trust bundle has no certificates"))
	}
	id, err := FromCertificate(leaf)
	if err != nil {
		return c.fail(err)
	}
	if !c.isSelf(id) {
		return c.fail(fmt.Errorf("certificate identity %s is not %s", id, c.Self))
	}
	now := c.now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return c.fail(fmt.Errorf("certificate is not valid now (valid %s to %s)", leaf.NotBefore, leaf.NotAfter))
	}
	// The certificate must chain to the bundle it ships with, so a rotation
	// that delivers a new leaf before its CA is caught here rather than at
	// every peer.
	inter := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		if ic, err := x509.ParseCertificate(der); err == nil {
			inter.AddCert(ic)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return c.fail(fmt.Errorf("certificate does not chain to its trust bundle: %w", err))
	}

	c.mu.Lock()
	c.cert, c.leaf, c.roots, c.err, c.digest = &pair, leaf, roots, nil, digest
	hooks := append([]func(*x509.Certificate){}, c.onLoad...)
	c.mu.Unlock()
	for _, fn := range hooks {
		fn(leaf)
	}
	slog.Info("loaded fabric-api credentials", "identity", id.URI(), "notAfter", leaf.NotAfter)
	return nil
}

// isSelf reports whether id is an identity this process may present.
func (c *Credentials) isSelf(id ID) bool {
	if c.AcceptAnyNode {
		return id.Role == RoleNode && id.Cell == c.Self.Cell && id.Namespace == c.Self.Namespace
	}
	return id == c.Self
}

// fail records err; the current credentials stay in use while unexpired.
func (c *Credentials) fail(err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cert == nil || c.now().After(c.leaf.NotAfter) {
		c.cert, c.leaf, c.roots = nil, nil, nil
		c.err = err
	}
	return err
}

func (c *Credentials) checkExpiry() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.leaf != nil && c.now().After(c.leaf.NotAfter) {
		c.cert, c.leaf, c.roots = nil, nil, nil
		c.err = errors.New("certificate expired")
		return c.err
	}
	return nil
}

// Run reloads every interval until ctx ends.
func (c *Credentials) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := c.Reload(); err != nil {
			slog.Warn("fabric-api credentials unavailable", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Err reports why credentials are unavailable, or nil when they are loaded.
func (c *Credentials) Err() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cert != nil {
		return nil
	}
	if c.err != nil {
		return c.err
	}
	return ErrNotLoaded
}

func (c *Credentials) current() (*tls.Certificate, *x509.CertPool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cert == nil {
		if c.err != nil {
			return nil, nil, c.err
		}
		return nil, nil, ErrNotLoaded
	}
	return c.cert, c.roots, nil
}

// verify checks a peer chain against the current bundle for usage and
// returns the peer's identity.
func (c *Credentials) verify(raw [][]byte, usage x509.ExtKeyUsage) (ID, error) {
	_, roots, err := c.current()
	if err != nil {
		return ID{}, err
	}
	if len(raw) == 0 {
		return ID{}, errors.New("peer presented no certificate")
	}
	certs := make([]*x509.Certificate, 0, len(raw))
	for _, der := range raw {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return ID{}, err
		}
		certs = append(certs, cert)
	}
	inter := x509.NewCertPool()
	for _, ic := range certs[1:] {
		inter.AddCert(ic)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: c.now(), KeyUsages: []x509.ExtKeyUsage{usage},
	}); err != nil {
		return ID{}, err
	}
	id, err := FromCertificate(certs[0])
	if err != nil {
		return ID{}, err
	}
	if id.Cell != c.Self.Cell {
		return ID{}, fmt.Errorf("peer %s is not in cell %s", id, c.Self.Cell)
	}
	return id, nil
}

// ServerConfig returns a TLS server config that requires a client
// certificate from the current trust bundle, in this cell, whose role allow
// accepts. Per-RPC authorization happens afterwards, from the verified
// identity.
func (c *Credentials) ServerConfig(allow func(ID) error) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// Chain verification is done in VerifyPeerCertificate against the
		// bundle current at handshake time, so it follows rotations.
		ClientAuth: tls.RequireAnyClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, _, err := c.current()
			return cert, err
		},
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			id, err := c.verify(raw, x509.ExtKeyUsageClientAuth)
			if err != nil {
				return err
			}
			return allow(id)
		},
	}
}

// ClientConfig returns a TLS client config that presents the current
// certificate and accepts only a server proving identity want.
func (c *Credentials) ClientConfig(want ID) *tls.Config {
	return c.ClientConfigAny(want)
}

// ClientConfigAny is ClientConfig accepting a server that proves any one of
// want, e.g. the identities of every fabric-api-certs pod on a node while
// one replaces another.
func (c *Credentials) ClientConfigAny(want ...ID) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// The standard verifier would pin the roots at config creation and
		// check a DNS name; fabric-api checks the chain against the current
		// bundle and the URI SAN in VerifyPeerCertificate instead.
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyPeerCertificate below
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, _, err := c.current()
			return cert, err
		},
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			id, err := c.verify(raw, x509.ExtKeyUsageServerAuth)
			if err != nil {
				return err
			}
			if slices.Contains(want, id) {
				return nil
			}
			return fmt.Errorf("server identity %s is not the expected %v", id, want)
		},
	}
}

// PeerID returns the identity verified during the handshake of cs. It
// re-derives it from the leaf, which VerifyPeerCertificate already checked.
func PeerID(cs tls.ConnectionState) (ID, error) {
	if len(cs.PeerCertificates) == 0 {
		return ID{}, errors.New("no peer certificate")
	}
	return FromCertificate(cs.PeerCertificates[0])
}
