package endpoints

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	"go.datum.net/galactic/internal/edge/connectip"
)

type refuseAdmission struct{}

func (refuseAdmission) Admit(ctx context.Context, _, _ string) (connectip.Lease, error) {
	if connectip.EndpointFromContext(ctx) == nil {
		return nil, connectip.ErrUnauthenticated
	}
	return nil, connectip.ErrForbidden
}

func connectRequest(t *testing.T, protocol, hostname, vpc string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodConnect,
		"https://"+hostname+connectip.TemplatePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if protocol == "h3" {
		req.Proto = "connect-ip"
	} else {
		req.Header.Set(":protocol", "connect-ip")
	}
	req.Header.Set("Capsule-Protocol", "?1")
	req.Header.Set("Authorization", "Bearer scope-test")
	req.Header.Set(connectip.VPCHeader, vpc)
	return req
}

func (refuseAdmission) Open(context.Context, connectip.SessionInfo) (connectip.BackendSession, error) {
	return nil, errors.New("unexpected backend open")
}

func TestSharedListenersCheckEveryMultiplexedAuthority(t *testing.T) {
	for _, protocol := range []string{"h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			if protocol == "h2" && !connectip.ExtendedConnectEnabled() {
				t.Skip("start tests with GODEBUG=http2xconnect=1 for extended CONNECT")
			}
			registry := NewRegistry()
			first, firstSecret := testEndpoint(t, "first", time.Now().Add(time.Hour))
			second, secondSecret := testEndpoint(t, "second", time.Now().Add(time.Hour))
			if err := registry.Apply(first.Spec, firstSecret); err != nil {
				t.Fatal(err)
			}
			if err := registry.Apply(second.Spec, secondSecret); err != nil {
				t.Fatal(err)
			}
			server, err := connectip.NewServer(connectip.Config{ResolveEndpoint: registry.Resolve,
				TLSConfig: &tls.Config{GetCertificate: registry.GetCertificate, MinVersion: tls.VersionTLS13},
				Admission: refuseAdmission{}, Backend: refuseAdmission{}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = server.Close() }()
			var address string
			if protocol == "h3" {
				listener, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				address = listener.LocalAddr().String()
				go func() { _ = server.Serve(listener) }()
			} else {
				listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				address = listener.Addr().String()
				go func() { _ = server.ServeTLS(listener) }()
			}
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM(firstSecret.Data["tls.crt"])
			roots.AppendCertsFromPEM(secondSecret.Data["tls.crt"])
			var connections atomic.Int64
			transport := func(hostname string) http.RoundTripper {
				tlsConfig := &tls.Config{RootCAs: roots, ServerName: hostname, MinVersion: tls.VersionTLS13}
				if protocol == "h3" {
					transport := &http3.Transport{TLSClientConfig: tlsConfig, EnableDatagrams: true,
						QUICConfig: &quic.Config{EnableDatagrams: true},
						Dial: func(ctx context.Context, _ string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
							connections.Add(1)
							return quic.DialAddr(ctx, address, tlsConfig, config)
						}}
					t.Cleanup(func() { _ = transport.Close() })
					return transport
				}
				transport := &http2.Transport{TLSClientConfig: tlsConfig, //nolint:staticcheck // net/http rejects :protocol.
					DialTLSContext: func(ctx context.Context, _, _ string, config *tls.Config) (net.Conn, error) {
						connections.Add(1)
						connection, err := (&tls.Dialer{Config: config}).DialContext(ctx, "tcp", address)
						if err == nil {
							t.Cleanup(func() { _ = connection.Close() })
						}
						return connection, err
					}}
				return transport
			}
			client := &http.Client{Transport: transport(first.Spec.Hostname), Timeout: 3 * time.Second}
			hostnames := []string{first.Spec.Hostname, second.Spec.Hostname, "unknown.example.com", first.Spec.Hostname}
			for _, hostname := range hostnames {
				req := connectRequest(t, protocol, first.Spec.Hostname, "tenant/first")
				req.Host = hostname
				response, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if hostname == first.Spec.Hostname {
					if response.StatusCode != http.StatusForbidden {
						t.Fatalf("registered request did not reach scoped admission: %d", response.StatusCode)
					}
				} else if response.StatusCode != http.StatusMisdirectedRequest {
					t.Fatalf("mismatched authority returned %d", response.StatusCode)
				}
			}
			if connections.Load() != 1 {
				t.Fatalf("requests not multiplexed: %d connections", connections.Load())
			}
			registry.Remove(first.Spec.EndpointUID)
			req := connectRequest(t, protocol, first.Spec.Hostname, "tenant/first")
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != http.StatusMisdirectedRequest {
				t.Fatal("established connection bypassed removal")
			}
			otherClient := &http.Client{Transport: transport(second.Spec.Hostname), Timeout: 3 * time.Second}
			req = connectRequest(t, protocol, second.Spec.Hostname, "tenant/second")
			response, err = otherClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode == http.StatusMisdirectedRequest ||
				response.TLS.PeerCertificates[0].DNSNames[0] != second.Spec.Hostname {
				t.Fatal("shared listener failed other tenant SNI selection")
			}
		})
	}
}
