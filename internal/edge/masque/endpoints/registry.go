package endpoints

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/connectip"
)

const CertificateRevisionAnnotation = "masque.galactic.datumapis.com/certificate-revision"
const EndpointUIDAnnotation = "masque.galactic.datumapis.com/endpoint-uid"
const MaxStaleness = 10 * time.Second

type entry struct {
	spec        galacticv1alpha1.MASQUEEndpointSpec
	certificate *tls.Certificate
	expires     time.Time
	checked     time.Time
	ctx         context.Context
	cancel      context.CancelFunc
	requests    sync.WaitGroup
}

type Registry struct {
	mutation sync.Mutex
	mu       sync.Mutex
	entries  map[string]*entry
	now      func() time.Time
}

func NewRegistry() *Registry {
	return &Registry{entries: map[string]*entry{}, now: time.Now}
}

func ValidateSpec(spec galacticv1alpha1.MASQUEEndpointSpec) error {
	if spec.EndpointUID == "" || spec.CustomerProjectUID == "" || spec.GatewayUID == "" || spec.NetworkUID == "" ||
		spec.Cell == "" || spec.Provider == "" || spec.Metro == "" || spec.VPCRef.Name == "" || spec.VPCRef.Namespace == "" ||
		spec.VPCRef.UID == "" || spec.Revision <= 0 || spec.CertificateRef.Name == "" {
		return errors.New("endpoint identity, VPC, certificate and positive revision are required")
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
		secret.Annotations[CertificateRevisionAnnotation] != spec.CertificateRef.Revision ||
		secret.Annotations[EndpointUIDAnnotation] != spec.EndpointUID {
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

func (registry *Registry) Apply(spec galacticv1alpha1.MASQUEEndpointSpec, secret *corev1.Secret) error {
	if err := ValidateSpec(spec); err != nil {
		return err
	}
	if !spec.Enabled {
		registry.Remove(spec.EndpointUID)
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
	if previous != nil && previous.spec.EndpointUID != spec.EndpointUID {
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
	registry.entries[spec.Hostname] = &entry{spec: spec, certificate: pair, expires: pair.Leaf.NotAfter,
		checked: registry.now(), ctx: ctx, cancel: cancel}
	return nil
}

func (registry *Registry) Remove(endpointUID string) {
	registry.mutation.Lock()
	defer registry.mutation.Unlock()
	registry.remove(endpointUID)
}

func (registry *Registry) remove(endpointUID string) {
	registry.mu.Lock()
	var removed []*entry
	for hostname, current := range registry.entries {
		if current.spec.EndpointUID == endpointUID {
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

func (registry *Registry) Current(endpointUID string) (galacticv1alpha1.MASQUEEndpointSpec, bool) {
	registry.mutation.Lock()
	defer registry.mutation.Unlock()
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for _, current := range registry.entries {
		if current.spec.EndpointUID == endpointUID {
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
	current := registry.entries[hello.ServerName]
	if !registry.valid(current) {
		return nil, errors.New("unknown or unavailable SNI")
	}
	return current.certificate, nil
}

func (registry *Registry) Resolve(request *http.Request) (context.Context, func(), error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	hostname := strings.TrimSuffix(request.Host, ":443")
	current := registry.entries[hostname]
	if !registry.valid(current) || request.TLS == nil || request.TLS.ServerName != hostname ||
		request.Header.Get(connectip.VPCHeader) != current.spec.VPCRef.Namespace+"/"+current.spec.VPCRef.Name {
		return nil, nil, errors.New("authority, SNI or VPC mismatch")
	}
	ctx, cancel := context.WithCancel(connectip.WithEndpoint(request.Context(), current.spec.MASQUEEndpointScope))
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
			expired = append(expired, current.spec.EndpointUID)
		}
	}
	registry.mu.Unlock()
	for _, endpointUID := range expired {
		registry.remove(endpointUID)
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

func FenceName(endpointUID string) string {
	return fmt.Sprintf("masque-endpoint-%x", sha256.Sum256([]byte(endpointUID)))
}
