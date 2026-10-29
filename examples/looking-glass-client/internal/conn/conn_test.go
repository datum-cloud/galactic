// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package conn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	servicev1 "go.datum.net/galactic/api/fabric/service/v1"
)

type pki struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newCA(t *testing.T) pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return pki{key, cert}
}

// issue returns a leaf for uri with usage, signed by ca.
func (ca pki) issue(t *testing.T, uri string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(uri)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), URIs: []*url.URL{u},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func writePEM(t *testing.T, path, kind string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// serve runs a TLS gRPC server presenting server and returns its address.
func serve(t *testing.T, server tls.Certificate) string {
	t.Helper()
	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAnyClientCert,
	})))
	servicev1.RegisterLookingGlassServiceServer(srv, servicev1.UnimplementedLookingGlassServiceServer{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func TestGatewayIdentity(t *testing.T) {
	ca, other := newCA(t), newCA(t)
	dir := t.TempDir()
	client := ca.issue(t, "spiffe://fabric-api.datumapis.com/cell/c1/service/looking-glass", x509.ExtKeyUsageClientAuth)
	key, _ := x509.MarshalECPrivateKey(client.PrivateKey.(*ecdsa.PrivateKey))
	writePEM(t, filepath.Join(dir, "tls.crt"), "CERTIFICATE", client.Certificate[0])
	writePEM(t, filepath.Join(dir, "tls.key"), "EC PRIVATE KEY", key)
	writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", ca.cert.Raw)

	for _, tc := range []struct {
		name   string
		server tls.Certificate
		ok     bool
	}{
		{"cell gateway", ca.issue(t, GatewayURI("c1"), x509.ExtKeyUsageServerAuth), true},
		{"other cell", ca.issue(t, GatewayURI("c2"), x509.ExtKeyUsageServerAuth), false},
		{
			"node identity",
			ca.issue(t, "spiffe://fabric-api.datumapis.com/cell/c1/node/ns/pod", x509.ExtKeyUsageServerAuth), false,
		},
		{"client-only usage", ca.issue(t, GatewayURI("c1"), x509.ExtKeyUsageClientAuth), false},
		{"untrusted CA", other.issue(t, GatewayURI("c1"), x509.ExtKeyUsageServerAuth), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cc, err := Dial(Options{Addr: serve(t, tc.server), Cell: "c1", CertFile: filepath.Join(dir, "tls.crt"),
				KeyFile: filepath.Join(dir, "tls.key"), CAFile: filepath.Join(dir, "ca.crt")})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cc.Close() }()
			_, err = servicev1.NewLookingGlassServiceClient(cc).GetCapabilities(t.Context(), &servicev1.GetCapabilitiesRequest{})
			// A handshake that succeeded reaches the unimplemented server.
			if got := status.Code(err) == codes.Unimplemented; got != tc.ok {
				t.Errorf("reached the server = %t, want %t (%v)", got, tc.ok, err)
			}
		})
	}
}
