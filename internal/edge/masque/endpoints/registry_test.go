package endpoints

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/connectip"
)

const testNamespace = "masque-system"
const testProvider = "masque"

func testEndpoint(t *testing.T, identity string, expires time.Time) (*galacticv1alpha1.MASQUEEndpoint, *corev1.Secret) {
	t.Helper()
	hostname := identity + ".connect.example"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(expires.UnixNano()), DNSNames: []string{hostname},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	revision := hex.EncodeToString(digest[:])
	endpoint := &galacticv1alpha1.MASQUEEndpoint{ObjectMeta: metav1.ObjectMeta{
		Name: identity, Namespace: testNamespace, UID: types.UID("registration-" + identity)},
		Spec: galacticv1alpha1.MASQUEEndpointSpec{
			MASQUEEndpointScope: galacticv1alpha1.MASQUEEndpointScope{
				EndpointUID: identity, CustomerProjectUID: "project-" + identity,
				GatewayUID: "gateway-" + identity, NetworkUID: "network-" + identity, Cell: "cell-a", Hostname: hostname},
			Metro: "metro-a", Provider: testProvider, Revision: 1, Enabled: true,
			VPCRef: galacticv1alpha1.MASQUEEndpointVPCReference{
				Namespace: "tenant", Name: identity, UID: "vpc-" + identity},
			CertificateRef: galacticv1alpha1.MASQUEEndpointCertificateReference{Name: identity + "-tls", Revision: revision},
		}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: endpoint.Spec.CertificateRef.Name, Namespace: endpoint.Namespace,
		Annotations: map[string]string{CertificateRevisionAnnotation: revision, EndpointUIDAnnotation: identity}},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{corev1.TLSCertKey: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey})}}
	return endpoint, secret
}

func request(spec galacticv1alpha1.MASQUEEndpointSpec) *http.Request {
	request := httptest.NewRequestWithContext(context.Background(), http.MethodConnect,
		"https://"+spec.Hostname+connectip.TemplatePath, nil)
	request.Host = spec.Hostname
	request.TLS = &tls.ConnectionState{ServerName: spec.Hostname}
	request.Header.Set(connectip.VPCHeader, spec.VPCRef.Namespace+"/"+spec.VPCRef.Name)
	return request
}

func TestRegistryRotationsAndRemoval(t *testing.T) {
	expires := time.Now().Add(2 * time.Hour)
	first, secret := testEndpoint(t, "first", expires)
	second, otherSecret := testEndpoint(t, "second", expires)
	registry := NewRegistry()
	for _, pair := range []struct {
		endpoint *galacticv1alpha1.MASQUEEndpoint
		secret   *corev1.Secret
	}{{first, secret}, {second, otherSecret}} {
		if err := registry.Apply(pair.endpoint.Spec, pair.secret); err != nil {
			t.Fatal(err)
		}
	}
	for _, expiry := range []time.Time{expires, expires.Add(-time.Hour)} {
		replacement, replacementSecret := testEndpoint(t, "first", expiry)
		replacement.Spec.Revision = first.Spec.Revision + 1
		ctx, release, err := registry.Resolve(request(first.Spec))
		if err != nil {
			t.Fatal(err)
		}
		applied := make(chan error, 1)
		go func() { applied <- registry.Apply(replacement.Spec, replacementSecret) }()
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatal("rotation did not revoke active request")
		}
		select {
		case <-applied:
			t.Fatal("rotation acknowledged before request stopped")
		default:
		}
		release()
		if err := <-applied; err != nil {
			t.Fatal(err)
		}
		cert, err := registry.GetCertificate(&tls.ClientHelloInfo{ServerName: first.Spec.Hostname})
		if err != nil || cert.Leaf.NotAfter.Unix() != expiry.Unix() {
			t.Fatalf("replacement not applied: %v", err)
		}
		first = replacement
	}
	registry.Remove(first.Spec.EndpointUID)
	if _, _, err := registry.Resolve(request(first.Spec)); err == nil {
		t.Fatal("removed authority accepted")
	}
	if _, err := registry.GetCertificate(&tls.ClientHelloInfo{ServerName: first.Spec.Hostname}); err == nil {
		t.Fatal("removed SNI accepted")
	}
	if _, err := registry.GetCertificate(&tls.ClientHelloInfo{ServerName: second.Spec.Hostname}); err != nil {
		t.Fatal("other tenant interrupted", err)
	}
}

func TestRegistryRejectsAuthorityAndBadCertificates(t *testing.T) {
	endpoint, secret := testEndpoint(t, "first", time.Now().Add(time.Hour))
	registry := NewRegistry()
	if err := registry.Apply(endpoint.Spec, secret); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*http.Request){
		func(req *http.Request) { req.Host = "unknown.connect.example" },
		func(req *http.Request) { req.TLS.ServerName = "other.connect.example" },
		func(req *http.Request) { req.Host += ":8443" },
		func(req *http.Request) { req.Header.Set(connectip.VPCHeader, "tenant/other") },
		func(req *http.Request) { req.TLS = nil },
	} {
		req := request(endpoint.Spec)
		mutate(req)
		if _, _, err := registry.Resolve(req); err == nil {
			t.Fatal("mismatched authority accepted")
		}
	}
	req := request(endpoint.Spec)
	req.Host += ":443"
	ctx, release, err := registry.Resolve(req)
	if err != nil {
		t.Fatal(err)
	}
	if got := connectip.EndpointFromContext(ctx); got == nil || *got != endpoint.Spec.MASQUEEndpointScope {
		t.Fatal("missing trusted scope")
	}
	release()
	for _, mutate := range []func(*corev1.Secret){
		func(secret *corev1.Secret) { secret.Annotations[EndpointUIDAnnotation] = "other" },
		func(secret *corev1.Secret) { secret.Annotations[CertificateRevisionAnnotation] = "wrong" },
		func(secret *corev1.Secret) { secret.Data[corev1.TLSPrivateKeyKey] = []byte("bad key") },
		func(secret *corev1.Secret) { secret.Type = corev1.SecretTypeOpaque },
	} {
		broken := secret.DeepCopy()
		mutate(broken)
		if err := registry.Apply(endpoint.Spec, broken); err == nil {
			t.Fatal("bad certificate accepted")
		}
	}
	expired, expiredSecret := testEndpoint(t, "expired", time.Now().Add(-time.Second))
	if err := registry.Apply(expired.Spec, expiredSecret); err == nil {
		t.Fatal("expired certificate accepted")
	}
}

func TestRegistryStalenessStopsSessions(t *testing.T) {
	endpoint, secret := testEndpoint(t, "first", time.Now().Add(time.Hour))
	registry := NewRegistry()
	now := time.Now()
	registry.now = func() time.Time { return now }
	if err := registry.Apply(endpoint.Spec, secret); err != nil {
		t.Fatal(err)
	}
	ctx, release, err := registry.Resolve(request(endpoint.Spec))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(MaxStaleness)
	if _, err := registry.GetCertificate(&tls.ClientHelloInfo{ServerName: endpoint.Spec.Hostname}); err == nil {
		t.Fatal("stale secret accepted")
	}
	stopped := make(chan struct{})
	go func() { registry.Expire(); close(stopped) }()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("stale session survived")
	}
	release()
	<-stopped
}

func testController(t *testing.T, objects ...client.Object) *Controller {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := galacticv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	instance := &galacticv1alpha1.EdgeInstance{ObjectMeta: metav1.ObjectMeta{
		Name: "ei-pod", Namespace: testNamespace, UID: "instance"},
		Spec: galacticv1alpha1.EdgeInstanceSpec{PodUID: "pod",
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: testProvider}}}
	objects = append(objects, instance)
	cellClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&galacticv1alpha1.MASQUEEndpoint{}).WithObjects(objects...).Build()
	return &Controller{Client: cellClient, Registry: NewRegistry(),
		Namespace: testNamespace, Provider: testProvider, Cell: "cell-a", PodUID: "pod"}
}

func TestControllerFencesRemovalAndRecreation(t *testing.T) {
	endpoint, secret := testEndpoint(t, "first", time.Now().Add(time.Hour))
	controller := testController(t, endpoint, secret)
	ctx := context.Background()
	if err := controller.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	var observed galacticv1alpha1.MASQUEEndpoint
	if err := controller.Client.Get(ctx, client.ObjectKeyFromObject(endpoint), &observed); err != nil {
		t.Fatal(err)
	}
	status := observed.Status.Instances[0]
	if status.AppliedRevision != 1 || status.AppliedCertificateRevision != endpoint.Spec.CertificateRef.Revision ||
		status.State != stateApplied || status.InstanceUID != "instance" {
		t.Fatalf("bad applied acknowledgment: %+v", status)
	}
	observed.Spec.Enabled = false
	observed.Spec.Revision++
	if err := controller.Client.Update(ctx, &observed); err != nil {
		t.Fatal(err)
	}
	if err := controller.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if err := controller.Client.Get(ctx, client.ObjectKeyFromObject(endpoint), &observed); err != nil {
		t.Fatal(err)
	}
	if !observed.Status.Instances[0].ForwardingStopped || observed.Status.Instances[0].AppliedRevision != 2 {
		t.Fatal("missing disabled acknowledgment")
	}
	if err := controller.Client.Delete(ctx, &observed); err != nil {
		t.Fatal(err)
	}
	if err := controller.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	endpoint.ResourceVersion = ""
	endpoint.UID = "new-registration"
	if err := controller.Client.Create(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	controller.Registry = NewRegistry()
	if err := controller.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := controller.Registry.Resolve(request(endpoint.Spec)); err == nil {
		t.Fatal("stale recreation bypassed durable tombstone")
	}
	if err := controller.Client.Get(ctx, client.ObjectKeyFromObject(endpoint), &observed); err != nil {
		t.Fatal(err)
	}
	observed.Spec.Revision = 3
	if err := controller.Client.Update(ctx, &observed); err != nil {
		t.Fatal(err)
	}
	if err := controller.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	_, release, err := controller.Registry.Resolve(request(endpoint.Spec))
	if err != nil {
		t.Fatal("new reactivation rejected", err)
	}
	release()
}

func TestControllerMissingSecretAndFailedRenewal(t *testing.T) {
	endpoint, secret := testEndpoint(t, "first", time.Now().Add(time.Hour))
	controller := testController(t, endpoint, secret)
	ctx := context.Background()
	if err := controller.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	var updated galacticv1alpha1.MASQUEEndpoint
	if err := controller.Client.Get(ctx, client.ObjectKeyFromObject(endpoint), &updated); err != nil {
		t.Fatal(err)
	}
	updated.Spec.Revision++
	updated.Spec.CertificateRef.Revision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := controller.Client.Update(ctx, &updated); err != nil {
		t.Fatal(err)
	}
	if err := controller.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if current, ok := controller.Registry.Current(endpoint.Spec.EndpointUID); !ok || current.Revision != 1 {
		t.Fatal("valid old certificate was lost")
	}
	if err := controller.Client.Get(ctx, client.ObjectKeyFromObject(endpoint), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.Instances[0].State != stateError || updated.Status.Instances[0].AppliedRevision != 1 {
		t.Fatal("failed renewal falsely acknowledged")
	}
	if err := controller.Client.Delete(ctx, secret); err != nil {
		t.Fatal(err)
	}
	if err := controller.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := controller.Registry.Current(endpoint.Spec.EndpointUID); ok {
		t.Fatal("removed Secret still active")
	}
}

func TestControllerPendingVersionedSecretRetainsValidatedCertificate(t *testing.T) {
	endpoint, secret := testEndpoint(t, "first", time.Now().Add(time.Hour))
	controller := testController(t, endpoint, secret)
	ctx := t.Context()
	if err := controller.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	var updated galacticv1alpha1.MASQUEEndpoint
	if err := controller.Client.Get(ctx, client.ObjectKeyFromObject(endpoint), &updated); err != nil {
		t.Fatal(err)
	}
	updated.Spec.Revision++
	updated.Spec.CertificateRef.Name += "-pending"
	if err := controller.Client.Update(ctx, &updated); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(MaxStaleness / 2)
	controller.Registry.now = func() time.Time { return now }
	if err := controller.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(MaxStaleness / 2)
	controller.Registry.Expire()
	if current, ok := controller.Registry.Current(endpoint.Spec.EndpointUID); !ok || current.Revision != 1 {
		t.Fatal("independently validated old certificate was lost during delivery")
	}
	if err := controller.Client.Delete(ctx, secret); err != nil {
		t.Fatal(err)
	}
	if err := controller.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := controller.Registry.Current(endpoint.Spec.EndpointUID); ok {
		t.Fatal("pending replacement hid active Secret removal")
	}
}

func TestControllerDuplicateRegistrationsFailClosed(t *testing.T) {
	for _, duplicateUID := range []bool{false, true} {
		endpoint, secret := testEndpoint(t, "first", time.Now().Add(time.Hour))
		duplicate, _ := testEndpoint(t, "duplicate", time.Now().Add(time.Hour))
		if duplicateUID {
			duplicate.Spec.EndpointUID = endpoint.Spec.EndpointUID
		} else {
			duplicate.Spec.Hostname = endpoint.Spec.Hostname
		}
		controller := testController(t, endpoint, secret)
		if err := controller.Sync(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := controller.Client.Create(t.Context(), duplicate); err != nil {
			t.Fatal(err)
		}
		if err := controller.Sync(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, ok := controller.Registry.Current(endpoint.Spec.EndpointUID); ok {
			t.Fatal("ambiguous registration remained active")
		}
	}
}
