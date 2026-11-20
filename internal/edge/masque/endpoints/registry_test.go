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
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/connectip"
)

const testNamespace = "masque-system"
const testProvider = "masque"
const testInstanceName = "ei-pod"

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
			Hostname: hostname,
			Provider: testProvider, Revision: 1, Enabled: true,
			CertificateRef: galacticv1alpha1.MASQUEEndpointCertificateReference{Name: identity + "-tls", Revision: revision},
		}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: endpoint.Spec.CertificateRef.Name, Namespace: endpoint.Namespace,
		Annotations: map[string]string{CertificateRevisionAnnotation: revision}},
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
	request.Header.Set(connectip.VPCHeader, "tenant/network")
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
		if err := registry.Apply(pair.endpoint, pair.secret); err != nil {
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
		go func() { applied <- registry.Apply(replacement, replacementSecret) }()
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
	registry.Remove(first.Spec.Hostname)
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
	if err := registry.Apply(endpoint, secret); err != nil {
		t.Fatal(err)
	}
	for _, selector := range []string{"tenant/first", "tenant/second"} {
		req := request(endpoint.Spec)
		req.Header.Set(connectip.VPCHeader, selector)
		_, release, err := registry.Resolve(req)
		if err != nil {
			t.Fatal("endpoint incorrectly constrained the per-request VPC", err)
		}
		release()
	}
	for _, mutate := range []func(*http.Request){
		func(req *http.Request) { req.Host = "unknown.connect.example" },
		func(req *http.Request) { req.TLS.ServerName = "other.connect.example" },
		func(req *http.Request) { req.Host += ":8443" },
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
	expected := galacticv1alpha1.MASQUEEndpointReference{Namespace: endpoint.Namespace, Name: endpoint.Name}
	if got := connectip.EndpointFromContext(ctx); got == nil || *got != expected {
		t.Fatal("missing trusted scope")
	}
	release()
	for _, mutate := range []func(*corev1.Secret){
		func(secret *corev1.Secret) { secret.Annotations[CertificateRevisionAnnotation] = "wrong" },
		func(secret *corev1.Secret) { secret.Data[corev1.TLSPrivateKeyKey] = []byte("bad key") },
		func(secret *corev1.Secret) { secret.Type = corev1.SecretTypeOpaque },
	} {
		broken := secret.DeepCopy()
		mutate(broken)
		if err := registry.Apply(endpoint, broken); err == nil {
			t.Fatal("bad certificate accepted")
		}
	}
	expired, expiredSecret := testEndpoint(t, "expired", time.Now().Add(-time.Second))
	if err := registry.Apply(expired, expiredSecret); err == nil {
		t.Fatal("expired certificate accepted")
	}
}

func TestRegistryStalenessStopsSessions(t *testing.T) {
	endpoint, secret := testEndpoint(t, "first", time.Now().Add(time.Hour))
	registry := NewRegistry()
	now := time.Now()
	registry.now = func() time.Time { return now }
	if err := registry.Apply(endpoint, secret); err != nil {
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
	if err := coordinationv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := galacticv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	instance := &galacticv1alpha1.EdgeInstance{ObjectMeta: metav1.ObjectMeta{
		Name: testInstanceName, Namespace: testNamespace, UID: "instance"},
		Spec: galacticv1alpha1.EdgeInstanceSpec{PodUID: "pod",
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: testProvider}}}
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: instance.Name, Namespace: instance.Namespace, UID: "lease",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: galacticv1alpha1.GroupVersion.String(),
				Kind: "EdgeInstance", Name: instance.Name, UID: instance.UID, Controller: ptr.To(true)}}},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: ptr.To("holder"),
			AcquireTime: ptr.To(metav1.NewMicroTime(time.Now().Add(-time.Minute)))},
	}
	objects = append(objects, instance, lease)
	cellClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&galacticv1alpha1.MASQUEEndpoint{}).WithObjects(objects...).Build()
	return &Controller{Client: cellClient, Registry: NewRegistry(),
		Namespace: testNamespace, Provider: testProvider, PodUID: "pod"}
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
		status.State != stateApplied || status.InstanceName != testInstanceName {
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
	if current, ok := controller.Registry.Current(endpoint.Spec.Hostname); !ok || current.Revision != 1 {
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
	if _, ok := controller.Registry.Current(endpoint.Spec.Hostname); ok {
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
	if current, ok := controller.Registry.Current(endpoint.Spec.Hostname); !ok || current.Revision != 1 {
		t.Fatal("independently validated old certificate was lost during delivery")
	}
	if err := controller.Client.Delete(ctx, secret); err != nil {
		t.Fatal(err)
	}
	if err := controller.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := controller.Registry.Current(endpoint.Spec.Hostname); ok {
		t.Fatal("pending replacement hid active Secret removal")
	}
}

func TestControllerDuplicateRegistrationsFailClosed(t *testing.T) {
	for _, foreignProvider := range []bool{false, true} {
		endpoint, secret := testEndpoint(t, "first", time.Now().Add(time.Hour))
		duplicate, _ := testEndpoint(t, "duplicate", time.Now().Add(time.Hour))
		duplicate.Spec.Hostname = endpoint.Spec.Hostname
		if foreignProvider {
			duplicate.Spec.Provider = "other"
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
		if _, ok := controller.Registry.Current(endpoint.Spec.Hostname); ok {
			t.Fatal("ambiguous registration remained active")
		}
	}
}

func TestFenceMissedRecreationAndNameReuse(t *testing.T) {
	endpoint, secret := testEndpoint(t, "first", time.Now().Add(time.Hour))
	controller := testController(t, endpoint, secret)
	if err := controller.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	recreated := endpoint.DeepCopy()
	recreated.UID = "new-incarnation"
	if err := controller.fence(t.Context(), recreated, false); err == nil {
		t.Fatal("same revision recreated registration accepted")
	}
	recreated.Spec.Revision++
	if err := controller.fence(t.Context(), recreated, false); err != nil {
		t.Fatal(err)
	}
	current, revoked, err := GrantRevision(t.Context(), controller.Client, endpoint.Namespace, endpoint.Spec.Hostname)
	if err != nil || current != 2 || revoked != 1 {
		t.Fatalf("bad recreation fence: %d %d %v", current, revoked, err)
	}
	changedHost := recreated.DeepCopy()
	changedHost.Spec.Hostname = "different.connect.example"
	if err := controller.fence(t.Context(), changedHost, false); err == nil {
		t.Fatal("same registration name changed its reserved hostname")
	}
	recreated.Name = "different-name"
	recreated.Spec.Revision++
	if err := controller.fence(t.Context(), recreated, false); err == nil {
		t.Fatal("different registration stole reserved hostname")
	}
}

func TestLegacyPlacementFencePreservesRevocations(t *testing.T) {
	for _, removed := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "removed"}[removed], func(t *testing.T) {
			endpoint, secret := testEndpoint(t, "first", time.Now().Add(time.Hour))
			endpoint.Spec.Revision = 5
			controller := testController(t, endpoint, secret)
			revokedRevision := int64(3)
			if removed {
				revokedRevision = 5
			}
			encoded, err := json.Marshal(Fence{Name: endpoint.Name, ObjectUID: string(endpoint.UID),
				Spec: endpoint.Spec, Removed: removed, RevokedRevision: revokedRevision})
			if err != nil {
				t.Fatal(err)
			}
			var legacy map[string]any
			if err := json.Unmarshal(encoded, &legacy); err != nil {
				t.Fatal(err)
			}
			legacy["spec"].(map[string]any)["cell"] = "previous-cell"
			legacy["spec"].(map[string]any)["metro"] = "previous-metro"
			encoded, err = json.Marshal(legacy)
			if err != nil {
				t.Fatal(err)
			}
			config := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
				Namespace: endpoint.Namespace, Name: FenceName(endpoint.Spec.Hostname),
				Labels: map[string]string{FenceLabel: testProvider}}, Data: map[string]string{"fence.json": string(encoded)}}
			if err := controller.Client.Create(t.Context(), config); err != nil {
				t.Fatal(err)
			}
			if err := controller.fence(t.Context(), endpoint, false); (err != nil) != removed {
				t.Fatalf("same revision legacy fence: removed=%v err=%v", removed, err)
			}
			stale := endpoint.DeepCopy()
			stale.Spec.Revision--
			if err := controller.fence(t.Context(), stale, false); err == nil {
				t.Fatal("legacy fence allowed revision rollback")
			}
			endpoint.Spec.Revision++
			if err := controller.fence(t.Context(), endpoint, false); err != nil {
				t.Fatal(err)
			}
			current, revoked, err := GrantRevision(t.Context(), controller.Client, endpoint.Namespace, endpoint.Spec.Hostname)
			if err != nil || current != 6 || revoked != revokedRevision {
				t.Fatalf("lost retained revisions: %d %d %v", current, revoked, err)
			}
		})
	}
}

func TestAcknowledgmentRequiresAcquisition(t *testing.T) {
	for _, boundary := range []string{"creation", "acquisition", "missing"} {
		t.Run(boundary, func(t *testing.T) {
			endpoint, secret := testEndpoint(t, "first", time.Now().Add(time.Hour))
			controller := testController(t, endpoint, secret)
			key := client.ObjectKey{Namespace: endpoint.Namespace, Name: testInstanceName}
			var instance galacticv1alpha1.EdgeInstance
			var lease coordinationv1.Lease
			if err := controller.Client.Get(t.Context(), key, &instance); err != nil {
				t.Fatal(err)
			}
			if err := controller.Client.Get(t.Context(), key, &lease); err != nil {
				t.Fatal(err)
			}
			switch boundary {
			case "creation":
				instance.CreationTimestamp = metav1.NewTime(time.Now().Add(time.Minute))
				if err := controller.Client.Update(t.Context(), &instance); err != nil {
					t.Fatal(err)
				}
			case "acquisition":
				lease.Spec.AcquireTime = ptr.To(metav1.NewMicroTime(time.Now().Add(time.Minute)))
				if err := controller.Client.Update(t.Context(), &lease); err != nil {
					t.Fatal(err)
				}
			case "missing":
				lease.Spec.AcquireTime = nil
				if err := controller.Client.Update(t.Context(), &lease); err != nil {
					t.Fatal(err)
				}
			}
			if err := controller.report(t.Context(), endpoint, nil); err == nil {
				t.Fatal("acknowledged without a strictly earlier membership acquisition")
			}
		})
	}
}

func TestEndpointSpecHasNoPlacement(t *testing.T) {
	endpoint, _ := testEndpoint(t, "schema", time.Now().Add(time.Hour))
	encoded, err := json.Marshal(endpoint.Spec)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	expected := []string{"hostname", "provider", "revision", "certificateRef", "enabled"}
	if len(fields) != len(expected) {
		t.Fatalf("unexpected registration fields: %s", encoded)
	}
	for _, field := range expected {
		if _, ok := fields[field]; !ok {
			t.Fatalf("missing %s in %s", field, encoded)
		}
	}
}

func TestIndependentProvidersInOneControlPlane(t *testing.T) {
	first, firstSecret := testEndpoint(t, "first", time.Now().Add(time.Hour))
	second, secondSecret := testEndpoint(t, "second", time.Now().Add(time.Hour))
	second.Spec.Provider = "second-provider"
	controller := testController(t, first, firstSecret, second, secondSecret)
	key := client.ObjectKey{Namespace: testNamespace, Name: testInstanceName}
	var instance galacticv1alpha1.EdgeInstance
	var lease coordinationv1.Lease
	if err := controller.Client.Get(t.Context(), key, &instance); err != nil {
		t.Fatal(err)
	}
	if err := controller.Client.Get(t.Context(), key, &lease); err != nil {
		t.Fatal(err)
	}
	instance.Name, instance.UID, instance.ResourceVersion = "ei-second-pod", "second-instance", ""
	instance.Spec.PodUID = "second-pod"
	instance.Spec.ProviderRef.Name = second.Spec.Provider
	if err := controller.Client.Create(t.Context(), &instance); err != nil {
		t.Fatal(err)
	}
	lease.Name, lease.UID, lease.ResourceVersion = instance.Name, "second-lease", ""
	lease.OwnerReferences[0].Name, lease.OwnerReferences[0].UID = instance.Name, instance.UID
	if err := controller.Client.Create(t.Context(), &lease); err != nil {
		t.Fatal(err)
	}
	other := &Controller{Client: controller.Client, Registry: NewRegistry(), Namespace: testNamespace,
		Provider: second.Spec.Provider, PodUID: instance.Spec.PodUID}
	for _, candidate := range []*Controller{controller, other} {
		if err := candidate.Sync(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	for _, pair := range []struct {
		own               *Controller
		endpoint, foreign *galacticv1alpha1.MASQUEEndpoint
	}{
		{controller, first, second}, {other, second, first},
	} {
		if _, ok := pair.own.Registry.Current(pair.endpoint.Spec.Hostname); !ok {
			t.Fatal("own endpoint not applied")
		}
		if _, ok := pair.own.Registry.Current(pair.foreign.Spec.Hostname); ok {
			t.Fatal("foreign endpoint applied")
		}
		var observed galacticv1alpha1.MASQUEEndpoint
		if err := controller.Client.Get(t.Context(), client.ObjectKeyFromObject(pair.endpoint), &observed); err != nil {
			t.Fatal(err)
		}
		if len(observed.Status.Instances) != 1 || observed.Status.Instances[0].InstanceName != "ei-"+pair.own.PodUID {
			t.Fatalf("foreign provider acknowledged endpoint: %+v", observed.Status)
		}
		ref := &galacticv1alpha1.MASQUEEndpointReference{Namespace: testNamespace, Name: pair.foreign.Name}
		if _, err := Resolve(t.Context(), controller.Client, testNamespace, pair.own.Provider, ref); err == nil {
			t.Fatal("authority resolved another provider's endpoint")
		}
	}
	if err := controller.Client.Delete(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []*Controller{controller, other} {
		if err := candidate.Sync(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := controller.Registry.Current(first.Spec.Hostname); ok {
		t.Fatal("deleted endpoint active")
	}
	if _, ok := other.Registry.Current(second.Spec.Hostname); !ok {
		t.Fatal("another provider's endpoint was removed")
	}
}
