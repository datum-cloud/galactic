package authority

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/connectip"
	"go.datum.net/galactic/internal/edge/masque/endpoints"
)

type managedAdmission struct {
	fixture  *fixture
	sequence atomic.Uint64
}

func (admission *managedAdmission) Admit(ctx context.Context, credential, vpc string) (connectip.Lease, error) {
	grant, err := admission.fixture.auth.Authorize(ctx, podID(testPodA), AuthorizeRequest{
		Credential: credential, VPC: vpc, EndpointRef: connectip.EndpointFromContext(ctx),
		Nonce: rand.Text(), Issued: admission.fixture.clock(),
	})
	if err != nil {
		return nil, err
	}
	leaseCtx, cancel := context.WithCancel(ctx)
	lease := &managedLease{grant: grant, sequence: admission.sequence.Add(1), ctx: leaseCtx, cancel: cancel}
	go func() {
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-leaseCtx.Done():
				return
			case <-ticker.C:
				_, err := admission.fixture.auth.Refresh(leaseCtx, podID(testPodA),
					grant.Authorization, grant.Revision, grant.Service)
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()
	return lease, nil
}

type managedLease struct {
	grant    Grant
	sequence uint64
	ctx      context.Context
	cancel   context.CancelFunc
}

func (lease *managedLease) Info() connectip.SessionInfo {
	return connectip.SessionInfo{ID: lease.sequence, Principal: lease.grant.Connector,
		VPC: lease.grant.VPC, Prefix: lease.grant.Prefix, Connector: lease.grant.Connector,
		Attachment: lease.grant.Service.UID, Claim: lease.grant.Authorization, Epoch: 1}
}

func (lease *managedLease) Routes() []netip.Prefix { return lease.grant.Routes }
func (lease *managedLease) Done() <-chan struct{}  { return lease.ctx.Done() }
func (lease *managedLease) Close() error           { lease.cancel(); return nil }

type managedBackend struct{ opened chan *managedPacketSession }

func (backend *managedBackend) Open(_ context.Context, info connectip.SessionInfo) (connectip.BackendSession, error) {
	session := &managedPacketSession{info: info, closed: make(chan struct{})}
	backend.opened <- session
	return session, nil
}

type managedPacketSession struct {
	info   connectip.SessionInfo
	closed chan struct{}
	once   sync.Once
}

func (*managedPacketSession) WritePacket([]byte) error { return nil }
func (session *managedPacketSession) ReadPacket(ctx context.Context, _ []byte) (int, error) {
	select {
	case <-ctx.Done():
	case <-session.closed:
	}
	return 0, connectip.ErrLeaseEnded
}
func (session *managedPacketSession) Close() error {
	session.once.Do(func() { close(session.closed) })
	return nil
}

func managedCertificate(t *testing.T, endpoint *galacticv1alpha1.MASQUEEndpoint) *corev1.Secret {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(endpoint.Spec.Revision),
		DNSNames: []string{endpoint.Spec.Hostname}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour / time.Duration(endpoint.Spec.Revision)),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	endpoint.Spec.CertificateRef.Revision = hex.EncodeToString(digest[:])
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		endpoints.CertificateRevisionAnnotation: endpoint.Spec.CertificateRef.Revision}}, Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{corev1.TLSCertKey: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey})}}
}

func applyManagedEndpoint(t *testing.T, fixture *fixture, registry *endpoints.Registry,
	endpoint *galacticv1alpha1.MASQUEEndpoint, secret *corev1.Secret) {
	t.Helper()
	var err error
	if endpoint.ResourceVersion == "" {
		err = fixture.admin.Create(t.Context(), endpoint)
	} else {
		err = fixture.admin.Update(t.Context(), endpoint)
	}
	if err != nil {
		t.Fatal(err)
	}
	fence := endpoints.Fence{Name: endpoint.Name, ObjectUID: string(endpoint.UID), Spec: endpoint.Spec}
	if !endpoint.Spec.Enabled {
		fence.RevokedRevision = endpoint.Spec.Revision
	}
	encoded, err := json.Marshal(fence)
	if err != nil {
		t.Fatal(err)
	}
	key := client.ObjectKey{Namespace: testNS, Name: endpoints.FenceName(endpoint.Spec.Hostname)}
	var config corev1.ConfigMap
	if err := fixture.admin.Get(t.Context(), key, &config); client.IgnoreNotFound(err) != nil {
		t.Fatal(err)
	}
	config.Name, config.Namespace = key.Name, key.Namespace
	config.Data = map[string]string{"fence.json": string(encoded)}
	if config.ResourceVersion == "" {
		err = fixture.admin.Create(t.Context(), &config)
	} else {
		err = fixture.admin.Update(t.Context(), &config)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Apply(endpoint, secret); err != nil {
		t.Fatal(err)
	}
}

func managedTransport(t *testing.T, protocol string, server *connectip.Server, hostname string,
	roots *x509.CertPool, connections *atomic.Int64) http.RoundTripper {
	t.Helper()
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: hostname, MinVersion: tls.VersionTLS13}
	if protocol == "h3" {
		listener, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = server.Serve(listener) }()
		transport := &http3.Transport{TLSClientConfig: tlsConfig, EnableDatagrams: true,
			QUICConfig: &quic.Config{EnableDatagrams: true},
			Dial: func(ctx context.Context, _ string, config *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
				connections.Add(1)
				return quic.DialAddr(ctx, listener.LocalAddr().String(), config, quicConfig)
			}}
		t.Cleanup(func() { _ = transport.Close() })
		return transport
	}
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.ServeTLS(listener) }()
	return &http2.Transport{TLSClientConfig: tlsConfig, //nolint:staticcheck // net/http rejects :protocol.
		DialTLSContext: func(ctx context.Context, _, _ string, config *tls.Config) (net.Conn, error) {
			connections.Add(1)
			connection, err := (&tls.Dialer{Config: config}).DialContext(ctx, "tcp", listener.Addr().String())
			if err == nil {
				t.Cleanup(func() { _ = connection.Close() })
			}
			return connection, err
		}}
}

func managedRequest(t *testing.T, transport http.RoundTripper, protocol, hostname string,
	credential, selector string, expectedStatus int) {
	t.Helper()
	reader, writer := io.Pipe()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)
	t.Cleanup(func() { _ = writer.Close(); _ = reader.Close() })
	request, err := http.NewRequestWithContext(ctx, http.MethodConnect,
		"https://"+hostname+connectip.TemplatePath, reader)
	if err != nil {
		t.Fatal(err)
	}
	if protocol == "h3" {
		request.Proto = "connect-ip"
	} else {
		request.Header.Set(":protocol", "connect-ip")
	}
	request.Header.Set("Capsule-Protocol", "?1")
	request.Header.Set("Authorization", "Bearer "+credential)
	request.Header.Set(connectip.VPCHeader, selector)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != expectedStatus {
		_ = response.Body.Close()
		t.Fatalf("%s returned %d, want %d", selector, response.StatusCode, expectedStatus)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	if expectedStatus != http.StatusOK {
		cancel()
		return
	}
	go func() { _, _ = io.Copy(io.Discard, response.Body) }()
}

func nextManagedSession(t *testing.T, backend *managedBackend) *managedPacketSession {
	t.Helper()
	select {
	case session := <-backend.opened:
		return session
	case <-time.After(3 * time.Second):
		t.Fatal("missing authorized backend session")
		return nil
	}
}

func requireManagedClosed(t *testing.T, session *managedPacketSession) {
	t.Helper()
	select {
	case <-session.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("revoked stream still has a backend")
	}
}

func requireManagedLive(t *testing.T, session *managedPacketSession) {
	t.Helper()
	select {
	case <-session.closed:
		t.Fatal("sibling VPC stream was interrupted")
	case <-time.After(150 * time.Millisecond):
	}
}

func TestManagedEndpointMultiplexedAuthority(t *testing.T) {
	for _, protocol := range []string{"h3", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			if protocol == "h2" && !connectip.ExtendedConnectEnabled() {
				t.Skip("start tests with GODEBUG=http2xconnect=1")
			}
			fixture := startFixture(t)
			endpoint := scopedEndpoint()
			secret := managedCertificate(t, endpoint)
			registry := endpoints.NewRegistry()
			applyManagedEndpoint(t, fixture, registry, endpoint, secret)
			second := fixture.vpc.DeepCopy()
			second.Name, second.ResourceVersion, second.UID = "second", "", ""
			fixture.create(second)
			second.Status.VPC = "000000def"
			if err := fixture.admin.Status().Update(t.Context(), second); err != nil {
				t.Fatal(err)
			}
			ref := VPCRef{Namespace: second.Namespace, Name: second.Name, UID: string(second.UID)}
			if err := fixture.grants.ledgers().Init(t.Context(), ref, testCell, testConnectors, testPools); err != nil {
				t.Fatal(err)
			}
			mint := func(vpc *cloudv1alpha1.VPC) Issued {
				t.Helper()
				issued, err := fixture.grants.Create(t.Context(), CreateRequest{
					EndpointRef: &galacticv1alpha1.MASQUEEndpointReference{Namespace: endpoint.Namespace, Name: endpoint.Name},
					VPC:         VPCRef{Namespace: vpc.Namespace, Name: vpc.Name, UID: string(vpc.UID)},
					Lifetime:    time.Hour, Routes: []netip.Prefix{netip.MustParsePrefix("fd20:a1b:2c3d::/48")},
				})
				if err != nil {
					t.Fatal(err)
				}
				return issued
			}
			firstGrant, secondGrant := mint(fixture.vpc), mint(second)
			backend := &managedBackend{opened: make(chan *managedPacketSession, 10)}
			server, err := connectip.NewServer(connectip.Config{ResolveEndpoint: registry.Resolve,
				TLSConfig: &tls.Config{GetCertificate: registry.GetCertificate, MinVersion: tls.VersionTLS13,
					SessionTicketsDisabled: true}, Limits: connectip.Limits{MaxStreamsPerConn: 8},
				Admission: &managedAdmission{fixture: fixture}, Backend: backend})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM(secret.Data[corev1.TLSCertKey])
			var connections atomic.Int64
			transport := managedTransport(t, protocol, server, endpoint.Spec.Hostname, roots, &connections)
			open := func(grant Issued) *managedPacketSession {
				managedRequest(t, transport, protocol, endpoint.Spec.Hostname, grant.Credential, grant.VPC, http.StatusOK)
				return nextManagedSession(t, backend)
			}
			firstSession, secondSession := open(firstGrant), open(secondGrant)
			if firstSession.info.VPC == secondSession.info.VPC || firstSession.info.Claim == secondSession.info.Claim ||
				firstSession.info.Prefix != secondSession.info.Prefix {
				t.Fatal("streams must have separate VPC claims even with overlapping allocations")
			}
			for _, denied := range []string{secondGrant.VPC, tenantNS + "/third"} {
				managedRequest(t, transport, protocol, endpoint.Spec.Hostname,
					firstGrant.Credential, denied, http.StatusForbidden)
			}
			if err := fixture.grants.Disable(t.Context(), firstGrant.Connector); err != nil {
				t.Fatal(err)
			}
			requireManagedClosed(t, firstSession)
			requireManagedLive(t, secondSession)
			managedRequest(t, transport, protocol, endpoint.Spec.Hostname,
				firstGrant.Credential, firstGrant.VPC, http.StatusForbidden)
			firstGrant = mint(fixture.vpc)
			firstSession = open(firstGrant)
			if err := fixture.admin.Delete(t.Context(), second); err != nil {
				t.Fatal(err)
			}
			requireManagedClosed(t, secondSession)
			requireManagedLive(t, firstSession)
			second.ResourceVersion, second.UID = "", ""
			fixture.create(second)
			second.Status.VPC = "000000ghi"
			if err := fixture.admin.Status().Update(t.Context(), second); err != nil {
				t.Fatal(err)
			}
			managedRequest(t, transport, protocol, endpoint.Spec.Hostname,
				secondGrant.Credential, secondGrant.VPC, http.StatusForbidden)
			if _, err := fixture.grants.Rotate(t.Context(), secondGrant.Connector, time.Hour); err == nil {
				t.Fatal("same-name VPC recreation allowed stale grant rotation")
			}
			ref.UID = string(second.UID)
			if err := fixture.grants.ledgers().Init(t.Context(), ref, testCell, testConnectors, testPools); err != nil {
				t.Fatal(err)
			}
			secondGrant = mint(second)
			secondSession = open(secondGrant)
			requireManagedLive(t, firstSession)
			var unchanged galacticv1alpha1.MASQUEEndpoint
			if err := fixture.admin.Get(t.Context(), client.ObjectKeyFromObject(endpoint), &unchanged); err != nil {
				t.Fatal(err)
			}
			if unchanged.Spec != endpoint.Spec || unchanged.ResourceVersion != endpoint.ResourceVersion {
				t.Fatal("binding or VPC lifecycle changed shared registration/certificate")
			}
			endpoint.Spec.Revision++
			secret = managedCertificate(t, endpoint)
			applyManagedEndpoint(t, fixture, registry, endpoint, secret)
			requireManagedClosed(t, firstSession)
			requireManagedClosed(t, secondSession)
			certificate, err := registry.GetCertificate(&tls.ClientHelloInfo{ServerName: endpoint.Spec.Hostname})
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(certificate.Certificate[0])
			if hex.EncodeToString(digest[:]) != endpoint.Spec.CertificateRef.Revision {
				t.Fatal("wrong active certificate")
			}
			firstGrant = mint(fixture.vpc)
			firstSession = open(firstGrant)
			secondGrant = mint(second)
			secondSession = open(secondGrant)
			endpoint.Spec.Revision++
			endpoint.Spec.Enabled = false
			applyManagedEndpoint(t, fixture, registry, endpoint, secret)
			requireManagedClosed(t, firstSession)
			requireManagedClosed(t, secondSession)
			managedRequest(t, transport, protocol, endpoint.Spec.Hostname,
				firstGrant.Credential, firstGrant.VPC, http.StatusMisdirectedRequest)
			if connections.Load() != 1 {
				t.Fatalf("used %d transport connections, want exactly one", connections.Load())
			}
			if _, err := fixture.auth.Authorize(t.Context(), podID(testPodA), AuthorizeRequest{
				Credential: firstGrant.Credential, VPC: firstGrant.VPC,
				EndpointRef: &galacticv1alpha1.MASQUEEndpointReference{Namespace: endpoint.Namespace, Name: endpoint.Name},
				Nonce:       rand.Text(), Issued: fixture.clock(),
			}); !errors.Is(err, connectip.ErrForbidden) {
				t.Fatalf("disabled endpoint authority: %v", err)
			}
		})
	}
}
