// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/admission"
	"go.datum.net/galactic/internal/edge/connectip"
)

// Errors the authority's decisions wrap. connectip.ErrUnauthenticated and
// connectip.ErrForbidden mark refusals; ErrUnavailable marks a decision the
// authority could not make now, which issues nothing.
var (
	ErrUnavailable = errors.New("authority unavailable")
	ErrInvalid     = errors.New("invalid request")
)

const (
	// LabelManagedBy marks the EdgeServices the authority issued.
	LabelManagedBy = "app.kubernetes.io/managed-by"
	// ManagedBy is LabelManagedBy's value.
	ManagedBy = "masque-authority"

	annotationPrefix = "masque.galactic.datumapis.com/"
	// AnnotationAuthorization is an issued EdgeService's authorization ID.
	AnnotationAuthorization = annotationPrefix + "authorization"
	// AnnotationPod is the UID of the provider pod the authorization is
	// bound to.
	AnnotationPod = annotationPrefix + "pod-uid"
	// AnnotationRevision is the credential revision it was issued under.
	AnnotationRevision = annotationPrefix + "revision"
	// AnnotationNonce is the nonce of the Authorize call that issued it.
	AnnotationNonce = annotationPrefix + "nonce"
	// AnnotationAllocation is the ledger allocation it grants.
	AnnotationAllocation = annotationPrefix + "allocation"
	// AnnotationRetired marks a retired authorization, which is never
	// renewed again.
	AnnotationRetired = annotationPrefix + "retired"
	// AnnotationRetiredAt is when the authorization was retired.
	AnnotationRetiredAt = annotationPrefix + "retired-at"
	// AnnotationCell is the cell of the authority that issued it.
	AnnotationCell = annotationPrefix + "cell"

	// packetAccess and prefixReachability are the capabilities an issued
	// EdgeService grants.
	packetAccess       = "PacketAccess"
	prefixReachability = "PrefixReachability"

	// DefaultTTL is how long after a grant read's start an issued
	// validUntil may be, before IssuerSkew is subtracted.
	DefaultTTL = 30 * time.Second
	// DefaultIssuerSkew is the issuer clock allowance subtracted from TTL.
	DefaultIssuerSkew = 2 * time.Second
	// RetryWindow is how long after it was issued an Authorize call is
	// accepted. A retired authorization is kept at least this long, so a
	// retry of the call that issued it finds it and is refused.
	RetryWindow = 10 * time.Second
	// maxCallerSkew is how far ahead of the authority's clock a call's
	// issue time may be.
	maxCallerSkew = 2 * time.Second
)

// nonceRE is the form of an Authorize nonce.
var nonceRE = regexp.MustCompile(`^[A-Za-z0-9]{16,64}$`)

// ServiceRef identifies an issued EdgeService.
type ServiceRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

// Grant is an issued authorization, as the provider receives it.
type Grant struct {
	Authorization string         `json:"authorization"`
	Connector     string         `json:"connector"`
	Allocation    string         `json:"allocation"`
	VPC           string         `json:"vpc"`
	VPCUID        string         `json:"vpcUID"`
	VPCID         string         `json:"vpcID"`
	Service       ServiceRef     `json:"service"`
	Prefix        netip.Prefix   `json:"prefix"`
	Routes        []netip.Prefix `json:"routes"`
	Revision      int64          `json:"revision"`
	NotAfter      time.Time      `json:"notAfter"`
}

// Authority decides Authorize, Refresh and Retire calls of the provider pods
// of one EdgeProvider in one cell, and sweeps revoked authorizations.
type Authority struct {
	// Client reads without a cache: every decision rests on fresh reads.
	Client client.Client
	// Namespace holds the grant record Secrets and ledger ConfigMaps.
	Namespace string
	// Provider is the EdgeProvider the issued services grant.
	Provider string
	// ProviderServiceAccount is the only ServiceAccount whose pods may
	// call.
	ProviderServiceAccount admission.ServiceAccount
	// Cell is this authority's cell.
	Cell string
	// TTL and IssuerSkew bound an issued validUntil; zero means the
	// defaults.
	TTL, IssuerSkew time.Duration
	Now             func() time.Time
	Log             *slog.Logger
}

func (a *Authority) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Authority) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}

func (a *Authority) ledgers() Ledgers {
	return Ledgers{Client: a.Client, Namespace: a.Namespace, Now: a.now}
}

// deadline is the validUntil of a grant read that started at start: the
// credential's expiry or start plus TTL less IssuerSkew, whichever is
// earlier, rounded down to the second an EdgeService can carry.
func (a *Authority) deadline(start time.Time, r *Record) time.Time {
	ttl, skew := a.TTL, a.IssuerSkew
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if skew == 0 {
		skew = DefaultIssuerSkew
	}
	until := start.Add(ttl - skew)
	if r.Expires.Before(until) {
		until = r.Expires
	}
	return until.UTC().Truncate(time.Second)
}

// caller refuses an identity that is not a pod of the provider's
// ServiceAccount.
func (a *Authority) caller(id admission.Identity) error {
	if id.PodUID == "" || id.ServiceAccount != a.ProviderServiceAccount {
		return fmt.Errorf("%w: %s is not the provider's ServiceAccount", connectip.ErrUnauthenticated,
			id.ServiceAccount)
	}
	return nil
}

// Authorize authenticates req's credential, authorizes it for req's VPC
// selector and returns the connector's grant, bound to the calling pod. A
// call issued more than RetryWindow ago is refused. A retry with the same
// nonce returns the grant the first call issued, with its original
// deadline, and never a new one. A pod that already holds a current grant
// of the same credential revision gets that grant renewed. Any other grant
// of the connector is retired first, and a new one is issued only once core
// released its attachments.
//
// It returns an error wrapping connectip.ErrUnauthenticated for an unknown
// or expired credential or a caller that is not a provider pod,
// connectip.ErrForbidden for a disabled connector, another VPC or cell, a
// recreated VPC or a retired allocation or authorization, ErrInvalid for a
// malformed request, and ErrUnavailable when it cannot decide now.
func (a *Authority) Authorize(ctx context.Context, id admission.Identity, req AuthorizeRequest) (Grant, error) {
	if err := a.caller(id); err != nil {
		return Grant{}, err
	}
	vpc, nonce := req.VPC, req.Nonce
	if !nonceRE.MatchString(nonce) {
		return Grant{}, fmt.Errorf("%w: malformed nonce", ErrInvalid)
	}
	start := a.now()
	if req.Issued.Before(start.Add(-RetryWindow)) || req.Issued.After(start.Add(maxCallerSkew)) {
		return Grant{}, fmt.Errorf("%w: call issued at %v is outside the retry window", ErrInvalid, req.Issued)
	}
	r, err := a.match(ctx, req.Credential)
	if err != nil {
		return Grant{}, err
	}
	if err := a.current(r, start); err != nil {
		return Grant{}, err
	}
	if vpc != r.VPC.Selector() {
		return Grant{}, fmt.Errorf("%w: connector %s may not use VPC %q", connectip.ErrForbidden, r.Connector, vpc)
	}
	vpcID, err := a.vpc(ctx, r.VPC)
	if err != nil {
		return Grant{}, err
	}
	e, err := a.allocation(ctx, r)
	if err != nil {
		return Grant{}, err
	}
	var list galacticv1alpha1.EdgeServiceList
	if err := a.Client.List(ctx, &list, client.InNamespace(r.VPC.Namespace),
		client.MatchingLabels{LabelConnector: r.Connector, LabelManagedBy: ManagedBy}); err != nil {
		return Grant{}, fmt.Errorf("%w: list services of connector %s: %w", ErrUnavailable, r.Connector, err)
	}
	for i := range list.Items {
		s := &list.Items[i]
		if s.Annotations[AnnotationNonce] == nonce && s.Annotations[AnnotationPod] == id.PodUID {
			if retired(s) || expired(s, a.now()) ||
				s.Annotations[AnnotationRevision] != strconv.FormatInt(r.Revision, 10) ||
				s.Annotations[AnnotationAllocation] != e.Allocation {
				return Grant{}, fmt.Errorf("%w: authorization %s is retired, expired or stale", connectip.ErrForbidden,
					s.Annotations[AnnotationAuthorization])
			}
			return a.grant(s, r, e, vpcID)
		}
	}
	for i := range list.Items {
		s := &list.Items[i]
		if !retired(s) && s.Annotations[AnnotationPod] == id.PodUID &&
			s.Annotations[AnnotationRevision] == strconv.FormatInt(r.Revision, 10) && !expired(s, a.now()) {
			if err := a.renew(ctx, s, a.deadline(start, r)); err != nil {
				return Grant{}, err
			}
			return a.grant(s, r, e, vpcID)
		}
	}
	// Every other incarnation of the connector ends before a new one
	// exists: its pool is the new one's, and pools of one VPC may not
	// overlap.
	draining := 0
	for i := range list.Items {
		s := &list.Items[i]
		if !retired(s) {
			if err := a.retire(ctx, s, "superseded"); err != nil {
				return Grant{}, err
			}
		}
		if released, err := a.reap(ctx, s); err != nil || !released {
			draining++
		}
	}
	if draining > 0 {
		return Grant{}, fmt.Errorf("%w: connector %s's previous authorization is still being released",
			ErrUnavailable, r.Connector)
	}
	return a.issue(ctx, id, r, e, vpcID, nonce, a.deadline(start, r))
}

// match returns the record whose digest is credential's, comparing every
// record in constant time.
func (a *Authority) match(ctx context.Context, credential string) (*Record, error) {
	if !wellFormed(credential) {
		return nil, fmt.Errorf("%w: malformed credential", connectip.ErrUnauthenticated)
	}
	digest := Digest(credential)
	var list corev1.SecretList
	if err := a.Client.List(ctx, &list, client.InNamespace(a.Namespace),
		client.MatchingLabels{LabelGrant: yes}); err != nil {
		return nil, fmt.Errorf("%w: list grant records: %w", ErrUnavailable, err)
	}
	var found *Record
	for i := range list.Items {
		r, err := decodeRecord(&list.Items[i])
		if err != nil {
			a.log().Warn("skipping malformed grant record", "secret", list.Items[i].Name, "error", err)
			continue
		}
		if sameDigest(r.Digest, digest) {
			found = r
		}
	}
	if found == nil {
		return nil, fmt.Errorf("%w: unknown credential", connectip.ErrUnauthenticated)
	}
	return found, nil
}

// current refuses a record that cannot authorize anything at now.
func (a *Authority) current(r *Record, now time.Time) error {
	switch {
	case !now.Before(r.Expires):
		return fmt.Errorf("%w: connector %s's credential expired", connectip.ErrUnauthenticated, r.Connector)
	case !r.Enabled:
		return fmt.Errorf("%w: connector %s is disabled", connectip.ErrForbidden, r.Connector)
	case r.Cell != a.Cell:
		return fmt.Errorf("%w: connector %s belongs to cell %s", connectip.ErrForbidden, r.Connector, r.Cell)
	}
	return nil
}

// vpc reads the record's VPC and returns its base62 identifier. It refuses
// a VPC deleted or recreated since the record was written.
func (a *Authority) vpc(ctx context.Context, ref VPCRef) (string, error) {
	var v cloudv1alpha1.VPC
	switch err := a.Client.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, &v); {
	case apierrors.IsNotFound(err):
		return "", fmt.Errorf("%w: VPC %s no longer exists", connectip.ErrForbidden, ref.Selector())
	case err != nil:
		return "", fmt.Errorf("%w: read VPC %s: %w", ErrUnavailable, ref.Selector(), err)
	case string(v.UID) != ref.UID || !v.DeletionTimestamp.IsZero():
		return "", fmt.Errorf("%w: VPC %s was replaced or is being deleted", connectip.ErrForbidden, ref.Selector())
	case v.Status.VPC == "":
		return "", fmt.Errorf("%w: VPC %s has no fabric identifier yet", ErrUnavailable, ref.Selector())
	}
	return v.Status.VPC, nil
}

// allocation returns the record's ledger entry, refusing a retired or
// missing one.
func (a *Authority) allocation(ctx context.Context, r *Record) (Entry, error) {
	l, _, err := a.ledgers().Read(ctx, r.VPC.UID, r.Cell)
	if err != nil {
		return Entry{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	e, ok := l.Lookup(r.Connector)
	switch {
	case !ok:
		return Entry{}, fmt.Errorf("%w: connector %s has no allocation", connectip.ErrForbidden, r.Connector)
	case e.Retired:
		return Entry{}, fmt.Errorf("%w: connector %s's allocation is retired", connectip.ErrForbidden, r.Connector)
	}
	return e, nil
}

// authorizationID derives the authorization ID of an Authorize call, so a
// retry of it names the same EdgeService.
func authorizationID(connector string, revision int64, pod, nonce string) string {
	sum := sha256.Sum256([]byte(connector + "\x00" + strconv.FormatInt(revision, 10) + "\x00" + pod + "\x00" + nonce))
	return hex.EncodeToString(sum[:12])
}

// ServiceName is the name of connector's EdgeService. A connector has at
// most one incarnation at a time, so concurrent issuers contend for one name
// and only one create succeeds; the UID tells successive incarnations apart.
func ServiceName(connector string) string { return "masque-" + connector }

// issue creates the EdgeService of a new authorization incarnation.
func (a *Authority) issue(ctx context.Context, id admission.Identity, r *Record, e Entry, vpcID, nonce string,
	until time.Time) (Grant, error) {
	auth := authorizationID(r.Connector, r.Revision, id.PodUID, nonce)
	s := &galacticv1alpha1.EdgeService{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.VPC.Namespace, Name: ServiceName(r.Connector),
			Labels: map[string]string{LabelConnector: r.Connector, LabelManagedBy: ManagedBy},
			Annotations: map[string]string{
				AnnotationAuthorization: auth, AnnotationPod: id.PodUID, AnnotationNonce: nonce,
				AnnotationRevision: strconv.FormatInt(r.Revision, 10), AnnotationAllocation: e.Allocation,
				AnnotationCell: a.Cell,
			},
		},
		Spec: galacticv1alpha1.EdgeServiceSpec{
			ProviderRef:   galacticv1alpha1.EdgeProviderReference{Name: a.Provider},
			VPCRef:        galacticv1alpha1.EdgeVPCReference{Name: r.VPC.Name, UID: r.VPC.UID},
			Capabilities:  []string{packetAccess, prefixReachability},
			Prefixes:      []string{e.Prefix.String()},
			ClientPool:    e.Pool.String(),
			ValidUntil:    &metav1.Time{Time: until},
			TrafficPolicy: r.TrafficPolicy,
		},
	}
	if err := a.Client.Create(ctx, s); err != nil {
		return Grant{}, fmt.Errorf("%w: create EdgeService %s/%s: %w", ErrUnavailable, s.Namespace, s.Name, err)
	}
	if err := a.unchanged(ctx, s, r); err != nil {
		return Grant{}, err
	}
	a.log().Info("authorization issued", "authorization", auth, "connector", r.Connector, "revision", r.Revision,
		"podRef", id.PodUID, "serviceName", s.Namespace+"/"+s.Name, "serviceUID", s.UID, "validUntil", until)
	return a.grant(s, r, e, vpcID)
}

// grant is the Grant of issued service s.
func (a *Authority) grant(s *galacticv1alpha1.EdgeService, r *Record, e Entry, vpcID string) (Grant, error) {
	if s.Spec.ValidUntil == nil {
		return Grant{}, fmt.Errorf("%w: EdgeService %s/%s has no validUntil", ErrUnavailable, s.Namespace, s.Name)
	}
	return Grant{
		Authorization: s.Annotations[AnnotationAuthorization], Connector: r.Connector, Allocation: e.Allocation,
		VPC: r.VPC.Selector(), VPCUID: r.VPC.UID, VPCID: vpcID,
		Service: ServiceRef{Namespace: s.Namespace, Name: s.Name, UID: string(s.UID)},
		Prefix:  e.Prefix, Routes: r.Routes, Revision: r.Revision, NotAfter: s.Spec.ValidUntil.Time,
	}, nil
}

// Refresh revalidates the authorization auth of the calling pod, issued
// under credential revision revision as EdgeService ref, and renews its
// validUntil from this call's grant read. It never accepts a new credential
// revision and never renews an authorization that expired or was retired.
// A refusal retires the authorization. It returns the errors Authorize
// does.
func (a *Authority) Refresh(ctx context.Context, id admission.Identity, auth string, revision int64,
	ref ServiceRef) (Grant, error) {
	if err := a.caller(id); err != nil {
		return Grant{}, err
	}
	start := a.now()
	s, err := a.service(ctx, id, auth, ref)
	if err != nil {
		return Grant{}, err
	}
	if s.Annotations[AnnotationRevision] != strconv.FormatInt(revision, 10) {
		return Grant{}, fmt.Errorf("%w: authorization %s was not issued under revision %d", connectip.ErrForbidden,
			auth, revision)
	}
	if retired(s) || expired(s, start) {
		if err := a.retire(ctx, s, "expired"); err != nil {
			a.log().Warn("could not retire an expired authorization", "authorization", auth, "error", err)
		}
		return Grant{}, fmt.Errorf("%w: authorization %s is retired or expired", connectip.ErrForbidden, auth)
	}
	g, err := a.revalidate(ctx, s, revision, start)
	if err != nil {
		if !errors.Is(err, ErrUnavailable) {
			if rerr := a.retire(ctx, s, err.Error()); rerr != nil {
				a.log().Warn("could not retire a refused authorization", "authorization", auth, "error", rerr)
			}
		}
		return Grant{}, err
	}
	return g, nil
}

// revalidate rereads the record, VPC and allocation of issued service s and
// renews its validUntil.
func (a *Authority) revalidate(ctx context.Context, s *galacticv1alpha1.EdgeService, revision int64,
	start time.Time) (Grant, error) {
	connector := s.Labels[LabelConnector]
	r, _, err := readRecord(ctx, a.Client, a.Namespace, connector)
	switch {
	case apierrors.IsNotFound(err):
		return Grant{}, fmt.Errorf("%w: connector %s has no grant record", connectip.ErrForbidden, connector)
	case err != nil:
		return Grant{}, fmt.Errorf("%w: read grant record of %s: %w", ErrUnavailable, connector, err)
	}
	if err := a.current(r, start); err != nil {
		return Grant{}, err
	}
	if r.Revision != revision || r.VPC.UID != s.Spec.VPCRef.UID {
		return Grant{}, fmt.Errorf("%w: connector %s's grant changed", connectip.ErrForbidden, connector)
	}
	vpcID, err := a.vpc(ctx, r.VPC)
	if err != nil {
		return Grant{}, err
	}
	e, err := a.allocation(ctx, r)
	if err != nil {
		return Grant{}, err
	}
	if e.Allocation != s.Annotations[AnnotationAllocation] || len(s.Spec.Prefixes) != 1 ||
		s.Spec.Prefixes[0] != e.Prefix.String() || s.Spec.ClientPool != e.Pool.String() {
		return Grant{}, fmt.Errorf("%w: connector %s's allocation changed", connectip.ErrForbidden, connector)
	}
	if err := a.renew(ctx, s, a.deadline(start, r)); err != nil {
		return Grant{}, err
	}
	if err := a.unchanged(ctx, s, r); err != nil {
		return Grant{}, err
	}
	return a.grant(s, r, e, vpcID)
}

// unchanged rereads the record s was just issued or renewed under, and
// retires s if the record changed since r was read: a rotation, disable or
// deletion that raced the write never leaves s live.
func (a *Authority) unchanged(ctx context.Context, s *galacticv1alpha1.EdgeService, r *Record) error {
	cur, _, err := readRecord(ctx, a.Client, a.Namespace, r.Connector)
	if err == nil && cur.Revision == r.Revision && cur.Enabled && sameDigest(cur.Digest, r.Digest) {
		return nil
	}
	if rerr := a.retire(ctx, s, "grant changed during issue"); rerr != nil {
		a.log().Warn("could not retire an authorization whose grant changed", "serviceName", s.Name, "error", rerr)
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("%w: reread grant record of %s: %w", ErrUnavailable, r.Connector, err)
	}
	return fmt.Errorf("%w: connector %s's grant changed", connectip.ErrForbidden, r.Connector)
}

// service reads the issued EdgeService ref and checks it is authorization
// auth of the calling pod.
func (a *Authority) service(ctx context.Context, id admission.Identity, auth string,
	ref ServiceRef) (*galacticv1alpha1.EdgeService, error) {
	var s galacticv1alpha1.EdgeService
	switch err := a.Client.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, &s); {
	case apierrors.IsNotFound(err):
		return nil, fmt.Errorf("%w: authorization %s no longer exists", connectip.ErrForbidden, auth)
	case err != nil:
		return nil, fmt.Errorf("%w: read EdgeService %s/%s: %w", ErrUnavailable, ref.Namespace, ref.Name, err)
	case string(s.UID) != ref.UID || s.Labels[LabelManagedBy] != ManagedBy ||
		s.Annotations[AnnotationAuthorization] != auth || s.Annotations[AnnotationPod] != id.PodUID ||
		!s.DeletionTimestamp.IsZero():
		return nil, fmt.Errorf("%w: EdgeService %s/%s is not authorization %s of this pod", connectip.ErrForbidden,
			ref.Namespace, ref.Name, auth)
	}
	return &s, nil
}

// renew sets s's validUntil to until, conditioned on the resourceVersion
// read, so a concurrent retirement wins.
func (a *Authority) renew(ctx context.Context, s *galacticv1alpha1.EdgeService, until time.Time) error {
	if s.Spec.ValidUntil != nil && s.Spec.ValidUntil.Time.Equal(until) {
		return nil
	}
	s.Spec.ValidUntil = &metav1.Time{Time: until}
	if err := a.Client.Update(ctx, s); err != nil {
		return fmt.Errorf("%w: renew EdgeService %s/%s: %w", ErrUnavailable, s.Namespace, s.Name, err)
	}
	return nil
}

// Retire ends the authorization auth of the calling pod, issued as
// EdgeService ref: it is never renewed again, and its validUntil is set in
// the past so core revokes what it admitted. Retiring a retired or deleted
// authorization succeeds.
func (a *Authority) Retire(ctx context.Context, id admission.Identity, auth string, ref ServiceRef) error {
	if err := a.caller(id); err != nil {
		return err
	}
	var cur galacticv1alpha1.EdgeService
	err := a.Client.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, &cur)
	if apierrors.IsNotFound(err) || (err == nil && string(cur.UID) != ref.UID) {
		// The incarnation is already gone.
		return nil
	}
	s, err := a.service(ctx, id, auth, ref)
	if err != nil {
		return err
	}
	return a.retire(ctx, s, "retired by the provider")
}

// retire marks s retired and moves its validUntil into the past, retrying
// from a fresh read after a conflict.
func (a *Authority) retire(ctx context.Context, s *galacticv1alpha1.EdgeService, reason string) error {
	for range conflictRetries {
		if retired(s) {
			return nil
		}
		if s.Annotations == nil {
			s.Annotations = map[string]string{}
		}
		s.Annotations[AnnotationRetired] = yes
		s.Annotations[AnnotationRetiredAt] = a.now().UTC().Format(time.RFC3339Nano)
		past := a.now().Add(-time.Minute).UTC().Truncate(time.Second)
		if s.Spec.ValidUntil == nil || s.Spec.ValidUntil.After(past) {
			s.Spec.ValidUntil = &metav1.Time{Time: past}
		}
		err := a.Client.Update(ctx, s)
		if err == nil {
			a.log().Info("authorization retired", "authorization", s.Annotations[AnnotationAuthorization],
				"connector", s.Labels[LabelConnector], "serviceName", s.Namespace+"/"+s.Name, "reason", reason)
			return nil
		}
		if !apierrors.IsConflict(err) {
			return fmt.Errorf("%w: retire EdgeService %s/%s: %w", ErrUnavailable, s.Namespace, s.Name, err)
		}
		uid := s.UID
		if err := a.Client.Get(ctx, client.ObjectKeyFromObject(s), s); err != nil || s.UID != uid {
			return fmt.Errorf("%w: reread EdgeService %s/%s: %w", ErrUnavailable, s.Namespace, s.Name, err)
		}
	}
	return fmt.Errorf("%w: EdgeService %s/%s kept changing", ErrUnavailable, s.Namespace, s.Name)
}

// reap deletes retired service s once it was retired for RetryWindow and
// core holds no client pool address for it, conditioned on its UID. It
// reports whether s is gone.
func (a *Authority) reap(ctx context.Context, s *galacticv1alpha1.EdgeService) (bool, error) {
	if !retired(s) || len(s.Status.Allocations) > 0 {
		return false, nil
	}
	at, err := time.Parse(time.RFC3339Nano, s.Annotations[AnnotationRetiredAt])
	if err == nil && a.now().Before(at.Add(RetryWindow)) {
		return false, nil
	}
	err = a.Client.Delete(ctx, s, client.Preconditions{UID: &s.UID})
	if err != nil && !apierrors.IsNotFound(err) {
		return false, err
	}
	return true, nil
}

// Sweep retires every issued authorization whose grant record is gone,
// disabled, expired or at another revision, or whose validUntil passed
// unrenewed, and deletes retired ones core has released. It returns the
// errors it met.
func (a *Authority) Sweep(ctx context.Context) error {
	var records corev1.SecretList
	if err := a.Client.List(ctx, &records, client.InNamespace(a.Namespace),
		client.MatchingLabels{LabelGrant: yes}); err != nil {
		return fmt.Errorf("list grant records: %w", err)
	}
	byConnector := map[string]*Record{}
	for i := range records.Items {
		if r, err := decodeRecord(&records.Items[i]); err == nil {
			byConnector[r.Connector] = r
		}
	}
	var services galacticv1alpha1.EdgeServiceList
	if err := a.Client.List(ctx, &services, client.MatchingLabels{LabelManagedBy: ManagedBy}); err != nil {
		return fmt.Errorf("list issued EdgeServices: %w", err)
	}
	now := a.now()
	var errs []error
	for i := range services.Items {
		s := &services.Items[i]
		if s.Spec.ProviderRef.Name != a.Provider || s.Annotations[AnnotationCell] != a.Cell {
			continue
		}
		if !retired(s) {
			r := byConnector[s.Labels[LabelConnector]]
			reason := ""
			switch {
			case r == nil:
				reason = "grant record deleted"
			case a.current(r, now) != nil:
				reason = "grant disabled or expired"
			case strconv.FormatInt(r.Revision, 10) != s.Annotations[AnnotationRevision]:
				reason = "credential rotated"
			case expired(s, now):
				reason = "not renewed"
			}
			if reason == "" {
				continue
			}
			if err := a.retire(ctx, s, reason); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		if _, err := a.reap(ctx, s); err != nil {
			errs = append(errs, fmt.Errorf("delete EdgeService %s/%s: %w", s.Namespace, s.Name, err))
		}
	}
	return errors.Join(errs...)
}

// RunSweeps runs Sweep every interval until ctx ends.
func (a *Authority) RunSweeps(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := a.Sweep(ctx); err != nil && ctx.Err() == nil {
			a.log().Warn("sweep failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func retired(s *galacticv1alpha1.EdgeService) bool { return s.Annotations[AnnotationRetired] == yes }

func expired(s *galacticv1alpha1.EdgeService, now time.Time) bool {
	return s.Spec.ValidUntil == nil || !now.Before(s.Spec.ValidUntil.Time)
}
