// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/admission"
	"go.datum.net/galactic/internal/edge/connectip"
	"go.datum.net/galactic/internal/edge/masque"
)

const (
	testPodA     = "pod-a"
	testProvider = "masque"
	testVPCID    = "000000abc"
	vpcSelector  = tenantNS + "/" + vpcName
)

var providerSA = admission.ServiceAccount{Namespace: "edge", Name: "masque"}

func podID(uid string) admission.Identity {
	return admission.Identity{ServiceAccount: providerSA, PodUID: uid}
}

// fixture is a real API server with the CRDs, a VPC with a ledger, and an
// authority on a clock the test moves.
type fixture struct {
	t     *testing.T
	admin client.Client
	vpc   *cloudv1alpha1.VPC

	mu  sync.Mutex
	now time.Time

	grants Grants
	auth   *Authority
	logs   *syncBuffer
	// issued is when each nonce was first sent; a retry resends it.
	issued map[string]time.Time
}

func (f *fixture) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// syncBuffer is a bytes.Buffer safe for concurrent writers.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func startFixture(t *testing.T) *fixture {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("KUBEBUILDER_ASSETS not set in CI")
		}
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	te := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "..", "config", "crd")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := te.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = te.Stop() })
	admin, err := client.New(cfg, client.Options{Scheme: testScheme()})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, admin: admin, now: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC), logs: &syncBuffer{},
		issued: map[string]time.Time{}}
	ctx := context.Background()
	for _, ns := range []string{testNS, tenantNS} {
		f.create(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	}
	f.vpc = f.newVPC()
	log := slog.New(slog.NewJSONHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f.grants = Grants{Client: admin, Namespace: testNS, Now: f.clock}
	f.auth = &Authority{Client: admin, Namespace: testNS, Provider: testProvider, ProviderServiceAccount: providerSA,
		Cell: testCell, Now: f.clock, Log: log}
	ref := VPCRef{Namespace: tenantNS, Name: vpcName, UID: string(f.vpc.UID)}
	if err := f.auth.ledgers().Init(ctx, ref, testCell, testConnectors, testPools); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) newVPC() *cloudv1alpha1.VPC {
	f.t.Helper()
	v := &cloudv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Namespace: tenantNS, Name: vpcName},
		Spec:       cloudv1alpha1.VPCSpec{Networks: []cloudv1alpha1.Network{"fd20:a1b:2c3d::/48"}},
	}
	f.create(v)
	v.Status.VPC = testVPCID
	if err := f.admin.Status().Update(context.Background(), v); err != nil {
		f.t.Fatal(err)
	}
	return v
}

func (f *fixture) create(obj client.Object) {
	f.t.Helper()
	if err := f.admin.Create(context.Background(), obj); err != nil {
		f.t.Fatalf("create %T %s: %v", obj, obj.GetName(), err)
	}
}

func (f *fixture) connector() Issued {
	f.t.Helper()
	is, err := f.grants.Create(context.Background(), CreateRequest{
		VPC: VPCRef{Namespace: tenantNS, Name: vpcName}, Cell: testCell, Lifetime: MaxLifetime,
		Routes: []netip.Prefix{netip.MustParsePrefix("fd20:a1b:2c3d::/48")},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return is
}

// req is an Authorize call with nonce, issued when nonce was first used.
func (f *fixture) req(credential, vpc, nonce string) AuthorizeRequest {
	at, ok := f.issued[nonce]
	if !ok {
		at = f.clock()
		f.issued[nonce] = at
	}
	return AuthorizeRequest{Credential: credential, VPC: vpc, Nonce: nonce, Issued: at}
}

func (f *fixture) tryAuthorize(id admission.Identity, credential, nonce string) (Grant, error) {
	return f.auth.Authorize(context.Background(), id, f.req(credential, vpcSelector, nonce))
}

func (f *fixture) authorize(id admission.Identity, credential, nonce string) Grant {
	f.t.Helper()
	g, err := f.tryAuthorize(id, credential, nonce)
	if err != nil {
		f.t.Fatalf("Authorize: %v", err)
	}
	return g
}

// service returns g's incarnation, or nil once it is gone, even when a
// successor took its name.
func (f *fixture) service(g Grant) *galacticv1alpha1.EdgeService {
	f.t.Helper()
	var s galacticv1alpha1.EdgeService
	err := f.admin.Get(context.Background(), client.ObjectKey{Namespace: g.Service.Namespace, Name: g.Service.Name}, &s)
	if apierrors.IsNotFound(err) || (err == nil && string(s.UID) != g.Service.UID) {
		return nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return &s
}

// deadline is the validUntil a grant read starting now gets without a
// credential expiry.
func (f *fixture) deadline() time.Time {
	return f.clock().Add(DefaultTTL - DefaultIssuerSkew).Truncate(time.Second)
}

func expectErr(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s = %v, want %v", what, err, want)
	}
}

func TestAuthority(t *testing.T) { //nolint:gocyclo // one ordered scenario over one API server
	f := startFixture(t)
	ctx := context.Background()
	podA, podB := podID(testPodA), podID("pod-b")
	c1 := f.connector()
	g := f.authorize(podA, c1.Credential, "nonceA0000000001")

	t.Run("admits", func(t *testing.T) {
		s := f.service(g)
		if s == nil {
			t.Fatal("no EdgeService issued")
		}
		want := galacticv1alpha1.EdgeServiceSpec{
			ProviderRef:  galacticv1alpha1.EdgeProviderReference{Name: testProvider},
			VPCRef:       galacticv1alpha1.EdgeVPCReference{Name: vpcName, UID: string(f.vpc.UID)},
			Capabilities: []string{packetAccess, prefixReachability},
			Prefixes:     []string{c1.Prefix.String()}, ClientPool: "fd20:a1b:2c3d:10:2::100/120",
		}
		if s.Spec.ProviderRef != want.ProviderRef || s.Spec.VPCRef != want.VPCRef ||
			strings.Join(s.Spec.Capabilities, ",") != strings.Join(want.Capabilities, ",") ||
			strings.Join(s.Spec.Prefixes, ",") != c1.Prefix.String() || s.Spec.ClientPool != want.ClientPool {
			t.Fatalf("issued spec %+v, want %+v", s.Spec, want)
		}
		if !s.Spec.ValidUntil.Time.Equal(f.deadline()) || !g.NotAfter.Equal(f.deadline()) {
			t.Fatalf("validUntil %v, grant %v, want %v", s.Spec.ValidUntil, g.NotAfter, f.deadline())
		}
		if g.Connector != c1.Connector || g.Prefix != c1.Prefix || g.Revision != 1 || g.VPCID != testVPCID ||
			g.VPCUID != string(f.vpc.UID) || g.VPC != vpcSelector || g.Service.UID != string(s.UID) ||
			s.Annotations[AnnotationPod] != testPodA || g.Authorization == "" {
			t.Fatalf("grant %+v of service %+v", g, s.ObjectMeta)
		}
	})
	t.Run("retry keeps the original deadline", func(t *testing.T) {
		f.advance(3 * time.Second)
		r := f.authorize(podA, c1.Credential, "nonceA0000000001")
		if r.Service != g.Service || !r.NotAfter.Equal(g.NotAfter) {
			t.Fatalf("retry = %+v, want %+v unchanged", r, g)
		}
	})
	t.Run("same pod renews its current authorization", func(t *testing.T) {
		r := f.authorize(podA, c1.Credential, "nonceA0000000002")
		if r.Service != g.Service || !r.NotAfter.Equal(f.deadline()) {
			t.Fatalf("second request = %+v, want %+v renewed to %v", r, g.Service, f.deadline())
		}
	})
	t.Run("refresh renews", func(t *testing.T) {
		f.advance(5 * time.Second)
		r, err := f.auth.Refresh(ctx, podA, g.Authorization, g.Revision, g.Service)
		if err != nil || !r.NotAfter.Equal(f.deadline()) || r.Service != g.Service {
			t.Fatalf("Refresh = %+v, %v; want deadline %v", r, err, f.deadline())
		}
	})
	t.Run("refusals", func(t *testing.T) {
		otherSA := admission.Identity{ServiceAccount: admission.ServiceAccount{Namespace: "edge", Name: "x"},
			PodUID: testPodA}
		unbound := admission.Identity{ServiceAccount: providerSA}
		for name, tc := range map[string]struct {
			id               admission.Identity
			cred, vpc, nonce string
			want             error
		}{
			"unknown credential":  {podA, NewCredential(), vpcSelector, "nonceR0000000001", connectip.ErrUnauthenticated},
			"malformed":           {podA, "secret", vpcSelector, "nonceR0000000002", connectip.ErrUnauthenticated},
			"another VPC":         {podA, c1.Credential, tenantNS + "/other", "nonceR0000000003", connectip.ErrForbidden},
			"another VPC's name":  {podA, c1.Credential, "other/vpc", "nonceR0000000004", connectip.ErrForbidden},
			"not the provider SA": {otherSA, c1.Credential, vpcSelector, "nonceR0000000005", connectip.ErrUnauthenticated},
			"no pod":              {unbound, c1.Credential, vpcSelector, "nonceR0000000006", connectip.ErrUnauthenticated},
			"bad nonce":           {podA, c1.Credential, vpcSelector, "short", ErrInvalid},
		} {
			_, err := f.auth.Authorize(ctx, tc.id, f.req(tc.cred, tc.vpc, tc.nonce))
			expectErr(t, name, err, tc.want)
		}
		for name, at := range map[string]time.Time{
			"stale call": f.clock().Add(-RetryWindow - time.Second), "future call": f.clock().Add(time.Minute),
			"no issue time": {},
		} {
			_, err := f.auth.Authorize(ctx, podA, AuthorizeRequest{Credential: c1.Credential, VPC: vpcSelector,
				Nonce: "nonceS0000000001", Issued: at})
			expectErr(t, name, err, ErrInvalid)
		}
		for name, tc := range map[string]struct {
			id       admission.Identity
			revision int64
			ref      ServiceRef
		}{
			"another pod":      {podB, g.Revision, g.Service},
			"another revision": {podA, g.Revision + 1, g.Service},
			"another UID":      {podA, g.Revision, ServiceRef{g.Service.Namespace, g.Service.Name, "x"}},
			"unknown service":  {podA, g.Revision, ServiceRef{g.Service.Namespace, "masque-none", "x"}},
		} {
			_, err := f.auth.Refresh(ctx, tc.id, g.Authorization, tc.revision, tc.ref)
			expectErr(t, "Refresh from "+name, err, connectip.ErrForbidden)
		}
		if s := f.service(g); s == nil || retired(s) {
			t.Fatal("a refused stale Refresh retired the current authorization")
		}
	})
	t.Run("store unavailable issues nothing", func(t *testing.T) {
		broken := *f.auth
		broken.Client = failingClient{f.admin}
		_, err := broken.Authorize(ctx, podA, f.req(c1.Credential, vpcSelector, "nonceU0000000001"))
		expectErr(t, "Authorize", err, ErrUnavailable)
		before := f.service(g).Spec.ValidUntil
		_, err = broken.Refresh(ctx, podA, g.Authorization, g.Revision, g.Service)
		expectErr(t, "Refresh", err, ErrUnavailable)
		if s := f.service(g); !s.Spec.ValidUntil.Equal(before) || retired(s) {
			t.Fatalf("an unavailable store changed the authorization: %v", s.Spec.ValidUntil)
		}
	})

	var gb Grant
	t.Run("another pod takes over only after release", func(t *testing.T) {
		// Core still holds an address of pod A's service.
		s := f.service(g)
		s.Status.Allocations = []galacticv1alpha1.EdgeAllocation{{Address: "fd20:a1b:2c3d:10:2::101",
			Attachment: "edge/a", AttachmentUID: "u"}}
		if err := f.admin.Status().Update(ctx, s); err != nil {
			t.Fatal(err)
		}
		_, err := f.tryAuthorize(podB, c1.Credential, "nonceB0000000001")
		expectErr(t, "takeover while released is pending", err, ErrUnavailable)
		s = f.service(g)
		if !retired(s) || s.Spec.ValidUntil.After(f.clock()) {
			t.Fatalf("predecessor %v not retired and expired", s.Annotations)
		}
		_, err = f.auth.Refresh(ctx, podA, g.Authorization, g.Revision, g.Service)
		expectErr(t, "predecessor's Refresh", err, connectip.ErrForbidden)
		s.Status.Allocations = nil
		if err := f.admin.Status().Update(ctx, s); err != nil {
			t.Fatal(err)
		}
		// Within the retry window, a retry of the predecessor's call
		// finds its retired authorization; the takeover waits.
		_, err = f.tryAuthorize(podA, c1.Credential, "nonceA0000000001")
		expectErr(t, "the predecessor's retry within the window", err, connectip.ErrForbidden)
		_, err = f.tryAuthorize(podB, c1.Credential, "nonceB0000000001")
		expectErr(t, "takeover within the retry window", err, ErrUnavailable)
		f.advance(RetryWindow)
		gb = f.authorize(podB, c1.Credential, "nonceB0000000002")
		if f.service(g) != nil || gb.Service == g.Service || gb.Prefix != g.Prefix {
			t.Fatalf("takeover = %+v, want a new service for the same /96 with the old one deleted", gb)
		}
		_, err = f.tryAuthorize(podA, c1.Credential, "nonceA0000000001")
		expectErr(t, "the predecessor's retry after the window", err, ErrInvalid)
		if s := f.service(gb); s == nil || retired(s) {
			t.Fatal("a stale retry disturbed the successor")
		}
		if err := f.auth.Retire(ctx, podA, g.Authorization, g.Service); err != nil {
			t.Fatalf("retiring a deleted incarnation = %v, want success", err)
		}
		if s := f.service(gb); s == nil || retired(s) {
			t.Fatal("retiring a deleted incarnation touched its successor of the same name")
		}
	})
	t.Run("retired authorization never renews", func(t *testing.T) {
		if err := f.auth.Retire(ctx, podB, gb.Authorization, gb.Service); err != nil {
			t.Fatal(err)
		}
		_, err := f.auth.Refresh(ctx, podB, gb.Authorization, gb.Revision, gb.Service)
		expectErr(t, "Refresh", err, connectip.ErrForbidden)
		_, err = f.tryAuthorize(podB, c1.Credential, "nonceB0000000002")
		expectErr(t, "retried Authorize", err, connectip.ErrForbidden)
		if s := f.service(gb); s == nil || !retired(s) || s.Spec.ValidUntil.After(f.clock()) {
			t.Fatal("retired service not expired")
		}
	})

	var gr Grant
	var c1r Issued
	t.Run("rotation", func(t *testing.T) {
		f.advance(RetryWindow)
		g2 := f.authorize(podA, c1.Credential, "nonceA0000000003")
		var err error
		if c1r, err = f.grants.Rotate(ctx, c1.Connector, MaxLifetime); err != nil {
			t.Fatal(err)
		}
		if c1r.Revision != 2 || c1r.Prefix != c1.Prefix || c1r.Credential == c1.Credential {
			t.Fatalf("rotated %+v", c1r)
		}
		_, err = f.auth.Refresh(ctx, podA, g2.Authorization, g2.Revision, g2.Service)
		expectErr(t, "Refresh after rotation", err, connectip.ErrForbidden)
		if s := f.service(g2); s == nil || !retired(s) {
			t.Fatal("Refresh refused on rotation did not retire the authorization")
		}
		_, err = f.tryAuthorize(podA, c1.Credential, "nonceA0000000004")
		expectErr(t, "old credential", err, connectip.ErrUnauthenticated)
		_, err = f.tryAuthorize(podA, c1r.Credential, "nonceA0000000005")
		expectErr(t, "new revision while the old one is kept", err, ErrUnavailable)
		f.advance(RetryWindow)
		gr = f.authorize(podA, c1r.Credential, "nonceA0000000006")
		if gr.Revision != 2 || gr.Service == g2.Service || gr.Prefix != c1.Prefix {
			t.Fatalf("new revision's grant %+v", gr)
		}
	})
	t.Run("credential expiry caps the deadline", func(t *testing.T) {
		short, err := f.grants.Rotate(ctx, c1.Connector, 30*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.auth.Sweep(ctx); err != nil {
			t.Fatal(err)
		}
		if s := f.service(gr); s == nil || !retired(s) {
			t.Fatal("sweep left a rotated revision's authorization live")
		}
		f.advance(RetryWindow)
		gs := f.authorize(podA, short.Credential, "nonceA0000000007")
		if !gs.NotAfter.Equal(short.Expires) || !gs.NotAfter.Before(f.deadline()) {
			t.Fatalf("deadline %v, want the credential expiry %v", gs.NotAfter, short.Expires)
		}
		f.advance(21 * time.Second)
		_, err = f.auth.Refresh(ctx, podA, gs.Authorization, gs.Revision, gs.Service)
		expectErr(t, "Refresh past expiry", err, connectip.ErrForbidden)
		_, err = f.tryAuthorize(podA, short.Credential, "nonceA0000000008")
		expectErr(t, "expired credential", err, connectip.ErrUnauthenticated)
	})

	t.Run("revoking one connector leaves another", func(t *testing.T) {
		c2 := f.connector()
		g2 := f.authorize(podA, c2.Credential, "nonceC0000000001")
		cur, err := f.grants.Rotate(ctx, c1.Connector, MaxLifetime)
		if err != nil {
			t.Fatal(err)
		}
		f.advance(RetryWindow)
		g1 := f.authorize(podA, cur.Credential, "nonceA0000000009")
		if err := f.grants.Disable(ctx, c1.Connector); err != nil {
			t.Fatal(err)
		}
		if err := f.auth.Sweep(ctx); err != nil {
			t.Fatal(err)
		}
		if s := f.service(g1); s == nil || !retired(s) || s.Spec.ValidUntil.After(f.clock()) {
			t.Fatal("the sweep left a disabled connector's authorization live")
		}
		_, err = f.tryAuthorize(podA, cur.Credential, "nonceA0000000010")
		expectErr(t, "disabled connector", err, connectip.ErrForbidden)
		s := f.service(g2)
		if s == nil || retired(s) {
			t.Fatal("revoking one connector retired another's authorization")
		}
		if _, err := f.auth.Refresh(ctx, podA, g2.Authorization, g2.Revision, g2.Service); err != nil {
			t.Fatalf("the other connector's Refresh: %v", err)
		}

		t.Run("unrenewed authorization is swept", func(t *testing.T) {
			f.advance(DefaultTTL)
			if err := f.auth.Sweep(ctx); err != nil {
				t.Fatal(err)
			}
			if s := f.service(g2); s == nil || !retired(s) {
				t.Fatal("the sweep left an authorization past its validUntil unretired")
			}
			f.advance(RetryWindow)
			if err := f.auth.Sweep(ctx); err != nil {
				t.Fatal(err)
			}
			if f.service(g2) != nil || f.service(g1) != nil {
				t.Fatal("the sweep kept released authorizations past the retry window")
			}
		})
		t.Run("retired connector", func(t *testing.T) {
			if err := f.grants.Retire(ctx, c2.Connector); err != nil {
				t.Fatal(err)
			}
			l, _, err := f.auth.ledgers().Read(ctx, string(f.vpc.UID), testCell)
			if err != nil {
				t.Fatal(err)
			}
			if e, _ := l.Lookup(c2.Connector); !e.Retired {
				t.Fatalf("retired connector's entry %+v", e)
			}
			c3 := f.connector()
			if c3.Prefix == c1.Prefix || c3.Prefix == c2.Prefix {
				t.Fatalf("a new connector reused /96 %s", c3.Prefix)
			}
		})
	})

	t.Run("concurrent pods leave one successor", func(t *testing.T) {
		c5 := f.connector()
		for round := range 5 {
			reqs := map[string]AuthorizeRequest{}
			for _, pod := range []string{"pod-x", "pod-y", "pod-z"} {
				reqs[pod] = f.req(c5.Credential, vpcSelector, fmt.Sprintf("nonce%s%011d", pod[4:], round))
			}
			var wg sync.WaitGroup
			for pod, req := range reqs {
				wg.Go(func() { _, _ = f.auth.Authorize(ctx, podID(pod), req) })
			}
			wg.Wait()
			var list galacticv1alpha1.EdgeServiceList
			if err := f.admin.List(ctx, &list, client.MatchingLabels{LabelConnector: c5.Connector}); err != nil {
				t.Fatal(err)
			}
			live := 0
			for i := range list.Items {
				if !retired(&list.Items[i]) {
					live++
				}
			}
			if live > 1 {
				t.Fatalf("round %d: %d live incarnations of one connector", round, live)
			}
			f.advance(RetryWindow)
			if err := f.auth.Sweep(ctx); err != nil {
				t.Fatal(err)
			}
		}
	})

	t.Run("rotation racing an issue leaves nothing live", func(t *testing.T) {
		c6 := f.connector()
		racing := *f.auth
		racing.Client = hookClient{Client: f.admin, beforeCreate: func() {
			if _, err := f.grants.Rotate(ctx, c6.Connector, MaxLifetime); err != nil {
				t.Error(err)
			}
		}}
		_, err := racing.Authorize(ctx, podA, f.req(c6.Credential, vpcSelector, "nonceE0000000001"))
		expectErr(t, "Authorize racing a rotation", err, connectip.ErrForbidden)
		var s galacticv1alpha1.EdgeService
		if err := f.admin.Get(ctx, client.ObjectKey{Namespace: tenantNS, Name: ServiceName(c6.Connector)}, &s); err != nil ||
			!retired(&s) || s.Spec.ValidUntil.After(f.clock()) {
			t.Fatalf("incarnation issued across a rotation = %v, %v; want it retired", s.Annotations, err)
		}
	})
	t.Run("foreign service with the connector's labels", func(t *testing.T) {
		c7 := f.connector()
		foreign := &galacticv1alpha1.EdgeService{
			ObjectMeta: metav1.ObjectMeta{Namespace: tenantNS, Name: ServiceName(c7.Connector),
				Labels: map[string]string{LabelConnector: c7.Connector, LabelManagedBy: ManagedBy}},
			Spec: galacticv1alpha1.EdgeServiceSpec{
				ProviderRef:  galacticv1alpha1.EdgeProviderReference{Name: testProvider},
				VPCRef:       galacticv1alpha1.EdgeVPCReference{Name: vpcName, UID: string(f.vpc.UID)},
				Capabilities: []string{packetAccess},
			},
		}
		f.create(foreign)
		if err := f.auth.Sweep(ctx); err != nil {
			t.Fatal(err)
		}
		_, err := f.tryAuthorize(podA, c7.Credential, "nonceF0000000001")
		expectErr(t, "Authorize beside a foreign service", err, ErrUnavailable)
		f.advance(RetryWindow)
		if g7 := f.authorize(podA, c7.Credential, "nonceF0000000002"); g7.Service.UID == string(foreign.UID) {
			t.Fatal("the foreign service was adopted")
		}
	})

	t.Run("recreated ledger refuses a stale write", func(t *testing.T) {
		l := f.auth.ledgers()
		ref := VPCRef{Namespace: tenantNS, Name: vpcName, UID: string(f.vpc.UID)}
		if err := l.Init(ctx, ref, "cell-9", testConnectors, testPools); err == nil {
			t.Fatal("Init succeeded with ranges another cell's ledger holds")
		}
		other := netip.MustParsePrefix("fd20:a1b:2c3d:20:1::/80")
		otherPools := netip.MustParsePrefix("fd20:a1b:2c3d:20:2::/80")
		if err := l.Init(ctx, ref, "cell-9", other, otherPools); err != nil {
			t.Fatalf("Init of another cell with disjoint ranges: %v", err)
		}
		_, cm, err := l.Read(ctx, string(f.vpc.UID), testCell)
		if err != nil {
			t.Fatal(err)
		}
		stale := cm.DeepCopy()
		if err := f.admin.Delete(ctx, cm); err != nil {
			t.Fatal(err)
		}
		if err := l.Init(ctx, ref, testCell, testConnectors, testPools); err == nil {
			t.Fatal("Init succeeded while this cell's issued services hold allocations")
		}
		if err := f.admin.DeleteAllOf(ctx, &galacticv1alpha1.EdgeService{}, client.InNamespace(tenantNS),
			client.MatchingLabels{LabelManagedBy: ManagedBy}); err != nil {
			t.Fatal(err)
		}
		if err := l.Init(ctx, ref, testCell, testConnectors, testPools); err != nil {
			t.Fatal(err)
		}
		stale.Data = map[string]string{ledgerKey: "{}"}
		if err := f.admin.Update(ctx, stale); err == nil {
			t.Fatal("a write conditioned on the deleted ledger succeeded")
		}
		if _, _, err := l.Read(ctx, string(f.vpc.UID), testCell); err != nil {
			t.Fatalf("recreated ledger: %v", err)
		}
	})

	t.Run("recreated VPC", func(t *testing.T) {
		c4 := f.connector()
		g4 := f.authorize(podA, c4.Credential, "nonceD0000000001")
		if err := f.admin.Delete(ctx, f.vpc); err != nil {
			t.Fatal(err)
		}
		f.newVPC()
		_, err := f.tryAuthorize(podA, c4.Credential, "nonceD0000000002")
		expectErr(t, "Authorize", err, connectip.ErrForbidden)
		_, err = f.auth.Refresh(ctx, podA, g4.Authorization, g4.Revision, g4.Service)
		expectErr(t, "Refresh", err, connectip.ErrForbidden)
	})

	t.Run("credentials stay out of logs", func(t *testing.T) {
		logs := f.logs.String()
		for _, c := range []string{c1.Credential, c1r.Credential} {
			if strings.Contains(logs, c) {
				t.Fatal("a credential appears in the authority's logs")
			}
		}
	})
}

// hookClient runs beforeCreate ahead of every create.
type hookClient struct {
	client.Client
	beforeCreate func()
}

func (h hookClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	h.beforeCreate()
	return h.Client.Create(ctx, obj, opts...)
}

// failingClient fails every read, as an unavailable API server does.
type failingClient struct{ client.Client }

func (failingClient) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("API server unavailable")
}

func (failingClient) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("API server unavailable")
}

// TestOverHTTPS runs a Client against a Server on TLS 1.3 with a token
// reviewer standing in for the API server's TokenReview.
func TestOverHTTPS(t *testing.T) {
	f := startFixture(t)
	c1 := f.connector()
	logs := &syncBuffer{}
	srvLog := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f.auth.Log = srvLog
	reviewer := tokenReviewer{
		"pod-a-token": {Username: "system:serviceaccount:edge:masque",
			Extra: map[string]authenticationv1.ExtraValue{admission.PodUIDExtra: {testPodA}}},
		"unbound-token": {Username: "system:serviceaccount:edge:masque"},
	}
	ts := httptest.NewUnstartedServer((&Server{Authority: f.auth, Reviewer: reviewer, Log: srvLog}).Handler())
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	ts.StartTLS()
	defer ts.Close()
	dir := t.TempDir()
	caFile, tokenFile := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "token")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if err := os.WriteFile(caFile, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	writeToken := func(tok string) {
		if err := os.WriteFile(tokenFile, []byte(tok+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeToken("pod-a-token")
	c := &Client{URL: ts.URL, TokenFile: tokenFile, CAFile: caFile, Now: f.clock}
	ctx := context.Background()

	g, err := c.Authorize(ctx, c1.Credential, vpcSelector)
	if err != nil {
		t.Fatal(err)
	}
	if g.Connector != c1.Connector || g.Principal != c1.Connector || g.Prefix != c1.Prefix || g.VPC != vpcSelector ||
		g.VPCID != testVPCID || g.Revision != 1 || g.Authorization == "" || g.Service.UID == "" ||
		!g.NotAfter.Equal(f.deadline()) || len(g.Routes) != 1 {
		t.Fatalf("grant %+v", g)
	}
	f.advance(5 * time.Second)
	r, err := c.Refresh(ctx, g)
	if err != nil || !r.NotAfter.Equal(f.deadline()) {
		t.Fatalf("Refresh = %+v, %v", r, err)
	}
	if _, err := c.Authorize(ctx, NewCredential(), vpcSelector); !errors.Is(err, connectip.ErrUnauthenticated) {
		t.Fatalf("unknown credential = %v", err)
	}
	if _, err := c.Authorize(ctx, c1.Credential, "tenant/other"); !errors.Is(err, connectip.ErrForbidden) {
		t.Fatalf("another VPC = %v", err)
	}
	stale := g
	stale.Revision++
	if _, err := c.Refresh(ctx, stale); !errors.Is(err, connectip.ErrForbidden) {
		t.Fatalf("stale revision = %v", err)
	}
	for _, tok := range []string{"unbound-token", "unknown-token"} {
		writeToken(tok)
		if _, err := c.Refresh(ctx, g); !errors.Is(err, connectip.ErrUnauthenticated) {
			t.Fatalf("Refresh with %s = %v", tok, err)
		}
	}
	writeToken("pod-a-token")
	if err := c.Retire(ctx, g); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Refresh(ctx, g); !errors.Is(err, connectip.ErrForbidden) {
		t.Fatalf("Refresh after Retire = %v", err)
	}

	t.Run("untrusted server", func(t *testing.T) {
		other := httptest.NewTLSServer(nil)
		defer other.Close()
		u := &Client{URL: other.URL, TokenFile: tokenFile, CAFile: caFile, Now: f.clock}
		_, err := u.Authorize(ctx, c1.Credential, vpcSelector)
		if err == nil || errors.Is(err, connectip.ErrForbidden) || errors.Is(err, connectip.ErrUnauthenticated) {
			t.Fatalf("Authorize against an untrusted server = %v, want a retryable TLS error", err)
		}
	})
	if strings.Contains(logs.String(), c1.Credential) || strings.Contains(logs.String(), "pod-a-token") {
		t.Fatal("a credential or token appears in the server's logs")
	}
	var _ masque.Authorizer = c
}

// tokenReviewer authenticates the tokens it maps.
type tokenReviewer map[string]authenticationv1.UserInfo

func (r tokenReviewer) Review(_ context.Context, token string) (authenticationv1.UserInfo, error) {
	u, ok := r[token]
	if !ok {
		return authenticationv1.UserInfo{}, connectip.ErrUnauthenticated
	}
	return u, nil
}
