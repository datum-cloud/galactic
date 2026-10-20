// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package connectip

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/quic-go/quic-go/http3"
)

// quicheClientEnv names the environment variable holding the command that
// runs google/quiche's masque_client, for example a path to the binary or a
// "docker run ..." prefix. The test skips when it is unset.
const quicheClientEnv = "CONNECTIP_QUICHE_CLIENT"

const vpcGreeting = "hello from inside the VPC"

// TestQuicheMasqueClientInterop runs quiche's masque_client in CONNECT-IP
// mode against the server. The client tunnels its own HTTP/3 request to a
// server listening on testTarget inside the TUN device's namespace, so the
// response proves both directions of the tunnel with an independent
// CONNECT-IP implementation. masque_client sizes its tunnelled QUIC packets to
// the outer datagram payload without leaving room for the IP and UDP headers it
// prepends in CONNECT-IP mode, so the request is accepted but no packet fits
// until the client accounts for them.
func TestQuicheMasqueClientInterop(t *testing.T) {
	requireRoot(t)
	client := os.Getenv(quicheClientEnv)
	if client == "" {
		t.Skipf("skipping: %s is not set", quicheClientEnv)
	}

	netns, backend := newNetnsTUN(t)
	cert, _ := selfSignedCert(t)
	var inner net.PacketConn
	err := netns.Do(func(ns.NetNS) error {
		var err error
		inner, err = (&net.ListenConfig{}).ListenPacket(t.Context(), "udp6", net.JoinHostPort(testTarget.String(), "4433"))
		return err
	})
	if err != nil {
		t.Fatalf("listen inside the VPC: %v", err)
	}
	innerServer := &http3.Server{
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, vpcGreeting)
		}),
	}
	go func() { _ = innerServer.Serve(inner) }()
	t.Cleanup(func() {
		_ = innerServer.Close()
		_ = inner.Close()
	})

	env := startServer(t, func(c *Config) { c.Backend = backend })
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	args := []string{
		"--masque_mode=connectip",
		"--disable_certificate_verification",
		"--proxy_headers=authorization:Bearer " + tokenAlice + ";" + strings.ToLower(VPCHeader) + ":" + vpcBlue,
		env.template.Raw(),
		"https://" + net.JoinHostPort(testTarget.String(), "4433") + "/",
	}
	fields := strings.Fields(client)
	out, err := exec.CommandContext(ctx, fields[0], append(fields[1:], args...)...).CombinedOutput()
	t.Logf("masque_client output:\n%s", out)
	if err != nil {
		t.Fatalf("masque_client: %v", err)
	}
	if !strings.Contains(string(out), vpcGreeting) {
		t.Fatalf("masque_client output does not contain %q", vpcGreeting)
	}
}
