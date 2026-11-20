package endpoints

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/connectip"
)

const CertificateRevisionAnnotation = "masque.galactic.datumapis.com/certificate-revision"
const MaxStaleness = 10 * time.Second

type entry struct {
	ref         galacticv1alpha1.MASQUEEndpointReference
	spec        galacticv1alpha1.MASQUEEndpointSpec
	certificate *tls.Certificate
	expires     time.Time
	checked     time.Time
	ctx         context.Context
	cancel      context.CancelFunc
	requests    sync.WaitGroup
}

type Registry struct {
	mutation          sync.Mutex
	mu                sync.Mutex
	entries           map[string]*entry
	now               func() time.Time
	legacyAuthority   string
	legacyHostname    string
	legacyCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

func NewRegistry() *Registry {
	return &Registry{entries: map[string]*entry{}, now: time.Now}
}

func NewRegistryWithLegacy(authority string,
	certificateSource func(*tls.ClientHelloInfo) (*tls.Certificate, error)) (*Registry, error) {
	hostname := authority
	if strings.Contains(authority, ":") {
		var port string
		var err error
		hostname, port, err = net.SplitHostPort(authority)
		if err != nil {
			return nil, errors.New("legacy authority must be a DNS hostname with optional port")
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return nil, errors.New("invalid legacy authority port")
		}
	}
	if hostname != strings.ToLower(hostname) || len(validation.IsDNS1123Subdomain(hostname)) != 0 ||
		!strings.Contains(hostname, ".") || certificateSource == nil {
		return nil, errors.New("legacy authority requires a canonical DNS hostname and certificate source")
	}
	registry := NewRegistry()
	registry.legacyAuthority, registry.legacyHostname, registry.legacyCertificate = authority, hostname, certificateSource
	if _, err := registry.GetCertificate(&tls.ClientHelloInfo{ServerName: hostname}); err != nil {
		return nil, err
	}
	return registry, nil
}

func ValidateSpec(spec galacticv1alpha1.MASQUEEndpointSpec) error {
	if spec.Provider == "" || spec.Revision <= 0 || spec.CertificateRef.Name == "" {
		return errors.New("endpoint identity, certificate and positive revision are required")
	}
	if spec.Hostname != strings.ToLower(spec.Hostname) || len(validation.IsDNS1123Subdomain(spec.Hostname)) != 0 ||
		!strings.Contains(spec.Hostname, ".") {
		return errors.New("hostname must be a canonical lowercase DNS name")
	}
	digest, err := hex.DecodeString(spec.CertificateRef.Revision)
	if err != nil || len(digest) != sha256.Size ||
		strings.ToLower(spec.CertificateRef.Revision) != spec.CertificateRef.Revision {
		return errors.New("certificate revision must be lowercase SHA256 leaf DER hex")
	}
	return nil
}

func certificate(spec galacticv1alpha1.MASQUEEndpointSpec, secret *corev1.Secret,
	now time.Time) (*tls.Certificate, error) {
	if secret.Type != corev1.SecretTypeTLS ||
		secret.Annotations[CertificateRevisionAnnotation] != spec.CertificateRef.Revision {
		return nil, errors.New("TLS Secret revision does not match registration")
	}
	pair, err := tls.X509KeyPair(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return nil, errors.New("invalid TLS key pair")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, errors.New("invalid leaf certificate")
	}
	digest := sha256.Sum256(leaf.Raw)
	if hex.EncodeToString(digest[:]) != spec.CertificateRef.Revision || leaf.VerifyHostname(spec.Hostname) != nil ||
		now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("certificate name, validity or content revision mismatch")
	}
	pair.Leaf = leaf
	return &pair, nil
}

func (registry *Registry) Apply(endpoint *galacticv1alpha1.MASQUEEndpoint, secret *corev1.Secret) error {
	spec := endpoint.Spec
	if spec.Hostname == registry.legacyHostname {
		return errors.New("hostname is reserved for the configured legacy authority")
	}
	ref := galacticv1alpha1.MASQUEEndpointReference{Namespace: endpoint.Namespace, Name: endpoint.Name}
	if ref.Namespace == "" || ref.Name == "" {
		return errors.New("named endpoint is required")
	}
	if err := ValidateSpec(spec); err != nil {
		return err
	}
	if !spec.Enabled {
		registry.Remove(spec.Hostname)
		return nil
	}
	registry.mutation.Lock()
	defer registry.mutation.Unlock()
	pair, err := certificate(spec, secret, registry.now())
	if err != nil {
		return err
	}
	registry.mu.Lock()
	previous := registry.entries[spec.Hostname]
	if previous != nil && (!SameIdentity(previous.spec, spec) || spec.Revision < previous.spec.Revision ||
		spec.Revision == previous.spec.Revision && previous.spec != spec) {
		registry.mu.Unlock()
		return errors.New("obsolete or conflicting registration")
	}
	if previous != nil && previous.ref != ref {
		registry.mu.Unlock()
		return errors.New("hostname already registered")
	}
	if previous != nil && previous.spec == spec {
		previous.checked = registry.now()
		registry.mu.Unlock()
		return nil
	}
	if previous != nil {
		delete(registry.entries, spec.Hostname)
		previous.cancel()
	}
	registry.mu.Unlock()
	if previous != nil {
		previous.requests.Wait()
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	registry.entries[spec.Hostname] = &entry{ref: ref, spec: spec, certificate: pair, expires: pair.Leaf.NotAfter,
		checked: registry.now(), ctx: ctx, cancel: cancel}
	return nil
}

func (registry *Registry) Remove(hostname string) {
	registry.mutation.Lock()
	defer registry.mutation.Unlock()
	registry.remove(hostname)
}

func (registry *Registry) remove(targetHostname string) {
	registry.mu.Lock()
	var removed []*entry
	for hostname, current := range registry.entries {
		if current.spec.Hostname == targetHostname {
			delete(registry.entries, hostname)
			current.cancel()
			removed = append(removed, current)
		}
	}
	registry.mu.Unlock()
	for _, current := range removed {
		current.requests.Wait()
	}
}

func (registry *Registry) Current(hostname string) (galacticv1alpha1.MASQUEEndpointSpec, bool) {
	registry.mutation.Lock()
	defer registry.mutation.Unlock()
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for _, current := range registry.entries {
		if current.spec.Hostname == hostname {
			return current.spec, true
		}
	}
	return galacticv1alpha1.MASQUEEndpointSpec{}, false
}

func (registry *Registry) valid(current *entry) bool {
	return current != nil && registry.now().Before(current.expires) && registry.now().Sub(current.checked) < MaxStaleness
}

func (registry *Registry) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.legacyCertificate != nil && hello.ServerName == registry.legacyHostname {
		pair, err := registry.legacyCertificate(hello)
		if err != nil {
			return nil, err
		}
		if pair == nil || len(pair.Certificate) == 0 {
			return nil, errors.New("legacy certificate unavailable")
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil || leaf.VerifyHostname(registry.legacyHostname) != nil ||
			registry.now().Before(leaf.NotBefore) || !registry.now().Before(leaf.NotAfter) {
			return nil, errors.New("legacy certificate name or validity mismatch")
		}
		return pair, nil
	}
	current := registry.entries[hello.ServerName]
	if !registry.valid(current) {
		return nil, errors.New("unknown or unavailable SNI")
	}
	return current.certificate, nil
}

func (registry *Registry) Resolve(request *http.Request) (context.Context, func(), error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.legacyCertificate != nil && request.Host == registry.legacyAuthority && request.TLS != nil &&
		request.TLS.ServerName == registry.legacyHostname {
		return request.Context(), func() {}, nil
	}
	hostname := strings.TrimSuffix(request.Host, ":443")
	current := registry.entries[hostname]
	if !registry.valid(current) || request.TLS == nil || request.TLS.ServerName != hostname {
		return nil, nil, errors.New("authority or SNI mismatch")
	}
	ctx, cancel := context.WithCancel(connectip.WithEndpoint(request.Context(), current.ref))
	stop := context.AfterFunc(current.ctx, cancel)
	current.requests.Add(1)
	return ctx, func() { stop(); cancel(); current.requests.Done() }, nil
}

func (registry *Registry) Expire() {
	registry.mutation.Lock()
	defer registry.mutation.Unlock()
	registry.mu.Lock()
	var expired []string
	for _, current := range registry.entries {
		if !registry.valid(current) {
			expired = append(expired, current.spec.Hostname)
		}
	}
	registry.mu.Unlock()
	for _, hostname := range expired {
		registry.remove(hostname)
	}
}

func (registry *Registry) RunExpiry(ctx context.Context) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			registry.Expire()
		}
	}
}

func FenceName(hostname string) string {
	return fmt.Sprintf("masque-endpoint-%x", sha256.Sum256([]byte(hostname)))
}
