// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.datum.net/galactic/internal/fabric/testpki"
)

func TestParseRoundTrip(t *testing.T) {
	for _, id := range []ID{
		Gateway("dfw"),
		Node("dfw", "galactic-system", "fabric-router-abc12"),
		Operator("dfw", "lab-verify"),
	} {
		got, err := Parse(id.URI())
		if err != nil || got != id {
			t.Errorf("Parse(%s) = %+v, %v", id.URI(), got, err)
		}
	}
	for _, bad := range []string{
		"spiffe://other.example/cell/dfw/gateway",
		"spiffe://fabric-api.datumapis.com/cell/dfw",
		"spiffe://fabric-api.datumapis.com/cell/dfw/admin",
		"spiffe://fabric-api.datumapis.com/cell/DFW/gateway",
		"spiffe://fabric-api.datumapis.com/cell/dfw/ns/x/pod",
		"spiffe://fabric-api.datumapis.com/cell/dfw/gateway?x=1",
		"https://fabric-api.datumapis.com/cell/dfw/gateway",
		"spiffe://fabric-api.datumapis.com/cell/../gateway",
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) succeeded", bad)
		}
	}
}

func loaded(t *testing.T, f testpki.Files, self ID) *Credentials {
	t.Helper()
	c := &Credentials{CertFile: f.Cert, KeyFile: f.Key, CAFile: f.CA, Self: self}
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
	return c
}

// handshake runs one mTLS handshake and returns the server's view of the
// client and both errors.
func handshake(t *testing.T, server, client *tls.Config) (ID, error, error) {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	type res struct {
		id  ID
		err error
	}
	done := make(chan res, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- res{err: err}
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		s := tls.Server(c, server)
		err = s.HandshakeContext(t.Context())
		var id ID
		if err == nil {
			id, err = PeerID(s.ConnectionState())
			// TLS 1.3 clients finish before the server checks their
			// certificate; read once so a rejection reaches the client.
			_, _ = s.Write([]byte{1})
		}
		done <- res{id, err}
	}()
	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	c := tls.Client(conn, client)
	cerr := c.HandshakeContext(t.Context())
	if cerr == nil {
		_, cerr = c.Read(make([]byte, 1))
	}
	if cerr != nil {
		_ = conn.Close()
	}
	r := <-done
	return r.id, r.err, cerr
}

func allowGateway(id ID) error {
	if id.Role != RoleGateway {
		return errors.New("not the gateway")
	}
	return nil
}

func TestMutualTLS(t *testing.T) {
	dir := t.TempDir()
	ca := testpki.NewCA(t, "dfw fabric-api")
	other := testpki.NewCA(t, "rogue")

	nodeID := Node("dfw", "galactic-system", "fabric-router-a")
	gwID := Gateway("dfw")
	node := loaded(t, ca.Issue(t, filepath.Join(dir, "node"), testpki.Options{URIs: []string{nodeID.URI()}}), nodeID)
	gw := loaded(t, ca.Issue(t, filepath.Join(dir, "gw"), testpki.Options{URIs: []string{gwID.URI()}}), gwID)

	got, serr, cerr := handshake(t, node.ServerConfig(allowGateway), gw.ClientConfig(nodeID))
	if serr != nil || cerr != nil || got != gwID {
		t.Fatalf("valid handshake: server %v client %v id %s", serr, cerr, got)
	}

	// The gateway expected a different pod.
	wrongNode := Node("dfw", "galactic-system", "fabric-router-b")
	_, _, cerr = handshake(t, node.ServerConfig(allowGateway), gw.ClientConfig(wrongNode))
	if cerr == nil || !strings.Contains(cerr.Error(), "not the expected") {
		t.Errorf("wrong node SAN: client err = %v", cerr)
	}

	// A client signed by another CA.
	rogueID := Gateway("dfw")
	rogueFiles := other.Issue(t, filepath.Join(dir, "rogue"), testpki.Options{URIs: []string{rogueID.URI()}})
	rogue := loaded(t, rogueFiles, rogueID)
	if _, serr, _ := handshake(t, node.ServerConfig(allowGateway), rogue.ClientConfig(nodeID)); serr == nil {
		t.Error("server accepted a client from another CA")
	}

	// Correct CA, identity not authorized.
	opID := Operator("dfw", "someone")
	op := loaded(t, ca.Issue(t, filepath.Join(dir, "op"), testpki.Options{URIs: []string{opID.URI()}}), opID)
	if _, serr, _ := handshake(t, node.ServerConfig(allowGateway), op.ClientConfig(nodeID)); serr == nil {
		t.Error("server accepted an operator where only the gateway is allowed")
	}

	// Correct CA, another cell.
	foreignID := Gateway("sjc")
	foreignFiles := ca.Issue(t, filepath.Join(dir, "sjc"), testpki.Options{URIs: []string{foreignID.URI()}})
	foreign := loaded(t, foreignFiles, foreignID)
	if _, serr, _ := handshake(t, node.ServerConfig(allowGateway), foreign.ClientConfig(nodeID)); serr == nil {
		t.Error("server accepted another cell's gateway")
	}

	// A client certificate without client-auth usage.
	srvOnly := loaded(t, ca.Issue(t, filepath.Join(dir, "srvonly"), testpki.Options{
		URIs: []string{gwID.URI()}, Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}), gwID)
	if _, serr, _ := handshake(t, node.ServerConfig(allowGateway), srvOnly.ClientConfig(nodeID)); serr == nil {
		t.Error("server accepted a certificate without client auth usage")
	}
}

func TestCredentialsLoadFailures(t *testing.T) {
	dir := t.TempDir()
	ca := testpki.NewCA(t, "ca")
	id := Gateway("dfw")

	missing := &Credentials{CertFile: filepath.Join(dir, "nope"), KeyFile: "x", CAFile: "y", Self: id}
	if missing.Reload() == nil || missing.Err() == nil {
		t.Error("missing files should fail closed")
	}
	if _, err := handshakeWith(t, missing); err == nil {
		t.Error("handshake succeeded without credentials")
	}

	reload := func(f testpki.Files) error {
		return (&Credentials{CertFile: f.Cert, KeyFile: f.Key, CAFile: f.CA, Self: id}).Reload()
	}

	wrongSelf := ca.Issue(t, filepath.Join(dir, "wrong"), testpki.Options{URIs: []string{Operator("dfw", "x").URI()}})
	if err := reload(wrongSelf); err == nil {
		t.Error("loaded a certificate for another identity")
	}

	expired := ca.Issue(t, filepath.Join(dir, "expired"), testpki.Options{URIs: []string{id.URI()},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour)})
	if err := reload(expired); err == nil {
		t.Error("loaded an expired certificate")
	}

	two := ca.Issue(t, filepath.Join(dir, "two"), testpki.Options{URIs: []string{id.URI(), Operator("dfw", "x").URI()}})
	if err := reload(two); err == nil {
		t.Error("loaded a certificate with two identities")
	}

	other := testpki.NewCA(t, "other")
	mismatched := ca.Issue(t, filepath.Join(dir, "mismatch"), testpki.Options{URIs: []string{id.URI()}}, other.PEM)
	if err := reload(mismatched); err == nil {
		t.Error("loaded a certificate that does not chain to its bundle")
	}
}

func handshakeWith(t *testing.T, client *Credentials) (ID, error) {
	dir := t.TempDir()
	ca := testpki.NewCA(t, "srv")
	nodeID := Node("dfw", "ns", "p")
	srv := loaded(t, ca.Issue(t, dir, testpki.Options{URIs: []string{nodeID.URI()}}), nodeID)
	id, serr, cerr := handshake(t, srv.ServerConfig(func(ID) error { return nil }), client.ClientConfig(nodeID))
	return id, errors.Join(serr, cerr)
}

func TestRotationWithOverlappingBundle(t *testing.T) {
	dir := t.TempDir()
	oldCA, newCA := testpki.NewCA(t, "old"), testpki.NewCA(t, "new")
	nodeID, gwID := Node("dfw", "ns", "p"), Gateway("dfw")

	// Before rotation both trust only the old CA.
	nodeFiles := oldCA.Issue(t, filepath.Join(dir, "node"), testpki.Options{URIs: []string{nodeID.URI()}})
	node := loaded(t, nodeFiles, nodeID)
	var notAfter time.Time
	node.OnLoad(func(leaf *x509.Certificate) { notAfter = leaf.NotAfter })
	gw := loaded(t, oldCA.Issue(t, filepath.Join(dir, "gw"), testpki.Options{URIs: []string{gwID.URI()}}), gwID)

	// Phase 1: the node renews from the new CA and trusts both. The gateway
	// still holds an old-CA certificate and trusts only the old CA, so it
	// rejects the node until it also learns the new CA.
	newCert := newCA.Issue(t, filepath.Join(dir, "node"), testpki.Options{URIs: []string{nodeID.URI()}},
		newCA.PEM, oldCA.PEM)
	if err := node.Reload(); err != nil || notAfter.IsZero() || newCert.Cert != nodeFiles.Cert {
		t.Fatalf("reload: %v", err)
	}
	if _, _, cerr := handshake(t, node.ServerConfig(allowGateway), gw.ClientConfig(nodeID)); cerr == nil {
		t.Error("gateway trusting only the old CA accepted the new node certificate")
	}

	// Phase 2: the gateway's bundle gains the new CA (its own certificate
	// still old). Both directions now verify.
	_ = oldCA.Issue(t, filepath.Join(dir, "gw"), testpki.Options{URIs: []string{gwID.URI()}},
		oldCA.PEM, newCA.PEM)
	if err := gw.Reload(); err != nil {
		t.Fatal(err)
	}
	_, serr, cerr := handshake(t, node.ServerConfig(allowGateway), gw.ClientConfig(nodeID))
	if serr != nil || cerr != nil {
		t.Errorf("overlap handshake: %v / %v", serr, cerr)
	}

	// A broken renewal keeps the previous valid credentials.
	if err := writeFile(filepath.Join(dir, "node", "tls.crt"), []byte("garbage")); err != nil {
		t.Fatal(err)
	}
	if err := node.Reload(); err == nil {
		t.Error("garbage certificate loaded")
	}
	if node.Err() != nil {
		t.Errorf("previous credentials should stay in use: %v", node.Err())
	}
}

func writeFile(path string, b []byte) error { return os.WriteFile(path, b, 0o600) }

func TestAcceptAnyNode(t *testing.T) {
	dir := t.TempDir()
	ca := testpki.NewCA(t, "dfw")
	certsPod := Node("dfw", "galactic-system", "fabric-api-certs-x7k2p")
	f := ca.Issue(t, filepath.Join(dir, "n"), testpki.Options{URIs: []string{certsPod.URI()}})
	self := Node("dfw", "galactic-system", "")
	c := &Credentials{CertFile: f.Cert, KeyFile: f.Key, CAFile: f.CA, Self: self, AcceptAnyNode: true}
	if err := c.Reload(); err != nil {
		t.Fatalf("node identity in the cell refused: %v", err)
	}
	for name, id := range map[string]ID{
		"other cell":      Node("sjc", "galactic-system", "p"),
		"other namespace": Node("dfw", "kube-system", "p"),
		"gateway":         Gateway("dfw"),
	} {
		g := ca.Issue(t, filepath.Join(dir, name), testpki.Options{URIs: []string{id.URI()}})
		c := &Credentials{CertFile: g.Cert, KeyFile: g.Key, CAFile: g.CA, Self: self, AcceptAnyNode: true}
		if err := c.Reload(); err == nil {
			t.Errorf("%s: loaded %s", name, id)
		}
	}
}

func TestClientConfigAny(t *testing.T) {
	dir := t.TempDir()
	ca := testpki.NewCA(t, "dfw")
	old, replacement := Node("dfw", "galactic-system", "certs-old"), Node("dfw", "galactic-system", "certs-new")
	node := loaded(t, ca.Issue(t, filepath.Join(dir, "node"), testpki.Options{URIs: []string{old.URI()}}), old)
	gwID := Gateway("dfw")
	gw := loaded(t, ca.Issue(t, filepath.Join(dir, "gw"), testpki.Options{URIs: []string{gwID.URI()}}), gwID)
	_, serr, cerr := handshake(t, node.ServerConfig(allowGateway), gw.ClientConfigAny(replacement, old))
	if serr != nil || cerr != nil {
		t.Errorf("server still presenting the replaced pod's identity was refused: %v / %v", serr, cerr)
	}
	if _, _, cerr := handshake(t, node.ServerConfig(allowGateway), gw.ClientConfigAny(replacement)); cerr == nil {
		t.Error("an identity outside the accepted set was accepted")
	}
}
