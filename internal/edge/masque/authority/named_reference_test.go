package authority

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/edge/connectip"
)

func TestOldManagedRecordFailsClosed(t *testing.T) {
	grants, vpc := faultyGrants(t, func() error { return nil })
	issued, err := grants.Create(t.Context(), CreateRequest{VPC: vpc, Cell: testCell, Lifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	var secret corev1.Secret
	if err := grants.Client.Get(t.Context(), client.ObjectKey{
		Namespace: testNS, Name: RecordName(issued.Connector)}, &secret); err != nil {
		t.Fatal(err)
	}
	trailing := secret.DeepCopy()
	trailing.Data[recordKey] = append(trailing.Data[recordKey], []byte(` {}`)...)
	if _, err := decodeRecord(trailing); err == nil {
		t.Fatal("trailing record content accepted")
	}
	for _, field := range []string{"endpoint", "networkUID", "bindingUID"} {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(secret.Data[recordKey], &fields); err != nil {
			t.Fatal(err)
		}
		fields[field] = json.RawMessage(`null`)
		encoded, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		copied := secret.DeepCopy()
		copied.Data[recordKey] = encoded
		if _, err := decodeRecord(copied); err == nil {
			t.Fatalf("old managed field %s silently became a legacy grant", field)
		}
	}
}

func TestNamedServiceReceiptRejectsRecreation(t *testing.T) {
	fixture := startFixture(t)
	issued := fixture.connector()
	grant := fixture.authorize(podID(testPodA), issued.Credential, "namedReceipt123456")
	encoded, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(encoded)), "uid") {
		t.Fatalf("wire grant exposes UID: %s", encoded)
	}
	var wire Grant
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	provider := &Client{Reader: fixture.admin}
	if _, err := provider.resolveGrant(t.Context(), &wire); err != nil {
		t.Fatal(err)
	}
	service := fixture.service(grant)
	if err := fixture.admin.Delete(t.Context(), service); err != nil {
		t.Fatal(err)
	}
	service.UID, service.ResourceVersion = "", ""
	fixture.create(service)
	ref := ServiceRef{Namespace: service.Namespace, Name: service.Name}
	if _, err := fixture.auth.Refresh(t.Context(), podID(testPodA), grant.Authorization,
		grant.Revision, ref); !errors.Is(err, connectip.ErrForbidden) {
		t.Fatalf("copied receipt refreshed recreated service: %v", err)
	}
	err = fixture.auth.Retire(t.Context(), podID(testPodA), grant.Authorization, ref)
	if !errors.Is(err, connectip.ErrForbidden) {
		t.Fatalf("old receipt retired recreated service: %v", err)
	}
	if _, err := provider.resolveGrant(t.Context(), &wire); !errors.Is(err, connectip.ErrForbidden) {
		t.Fatalf("provider hydrated a copied stale receipt: %v", err)
	}
}
