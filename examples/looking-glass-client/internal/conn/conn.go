// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package conn dials a cell's fabric-api gateway as a Looking Glass service:
// mutual TLS with the service's certificate, accepting only a server that
// proves the cell's gateway identity.
package conn

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// GatewayURI is the URI SAN a cell's gateway certificate carries.
func GatewayURI(cell string) string {
	return "spiffe://fabric-api.datumapis.com/cell/" + cell + "/gateway"
}

// Options name the gateway and the service's credentials, as PEM files.
type Options struct {
	Addr     string
	Cell     string
	CertFile string
	KeyFile  string
	CAFile   string
}

// TLSConfig loads the credentials and returns a client config that checks
// the server's chain against the CA bundle and requires its only URI SAN to
// be the cell's gateway. An empty CertFile presents no client certificate.
func TLSConfig(o Options) (*tls.Config, error) {
	var certs []tls.Certificate
	if o.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load service certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	pem, err := os.ReadFile(o.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("CA bundle holds no certificate")
	}
	want := GatewayURI(o.Cell)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: certs,
		// The gateway's certificate names it by URI SAN only, so the
		// standard verifier's DNS check cannot apply; the chain and the
		// URI are checked below instead.
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyPeerCertificate
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("gateway presented no certificate")
			}
			certs := make([]*x509.Certificate, len(raw))
			for i, der := range raw {
				if certs[i], err = x509.ParseCertificate(der); err != nil {
					return err
				}
			}
			inter := x509.NewCertPool()
			for _, c := range certs[1:] {
				inter.AddCert(c)
			}
			if _, err := certs[0].Verify(x509.VerifyOptions{
				Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}); err != nil {
				return err
			}
			if uris := certs[0].URIs; len(uris) != 1 || uris[0].String() != want {
				return fmt.Errorf("gateway identity %v is not %s", uris, want)
			}
			return nil
		},
	}, nil
}

// Dial opens a connection to the gateway. gRPC retries are off: the
// service must never replay an attempt.
func Dial(o Options, extra ...grpc.DialOption) (*grpc.ClientConn, error) {
	cfg, err := TLSConfig(o)
	if err != nil {
		return nil, err
	}
	opts := append([]grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(cfg)),
		grpc.WithDisableRetry(),
	}, extra...)
	return grpc.NewClient(o.Addr, opts...)
}
