// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package auth authenticates a caller of Worker's API, as
// docs/worker/contract.md "Transport, identity and access" requires:
//
//  1. The call carries a projected ServiceAccount token with audience
//     galactic-worker. TokenReview validates it; the result is cached until
//     the token expires.
//  2. The token is bound to a pod on this node.
//  3. The connecting process (SO_PEERCRED) runs in that pod.
//  4. A static allowlist names the capabilities the ServiceAccount may use.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	authenticationv1 "k8s.io/api/authentication/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/refusal"
)

// Extra keys the API server sets on a token bound to a pod.
const (
	ExtraPodUID   = "authentication.kubernetes.io/pod-uid"
	ExtraPodName  = "authentication.kubernetes.io/pod-name"
	ExtraNodeName = "authentication.kubernetes.io/node-name"
)

const serviceAccountPrefix = "system:serviceaccount:"

// Caller is an authenticated client.
type Caller struct {
	// ServiceAccount is "namespace/name". It is the claim owner: a client
	// that restarts keeps ownership of its claims.
	ServiceAccount string
	PodUID         string
	PodName        string
	// Capabilities are the capabilities the allowlist grants.
	Capabilities []string
	// EgressShardClaims reports that the allowlist lets the caller name an
	// EgressShard as a veth_pair claim's attachment.
	EgressShardClaims bool
}

// Allowed reports whether the caller may use capability.
func (c Caller) Allowed(capability string) bool {
	return slices.Contains(c.Capabilities, capability)
}

// TokenReviewer authenticates a bearer token for the Worker audience.
type TokenReviewer interface {
	Review(ctx context.Context, token string) (authenticationv1.UserInfo, error)
}

// KubeTokenReviewer reviews tokens with the API server's TokenReview.
type KubeTokenReviewer struct {
	Client client.Client
}

// Review implements TokenReviewer. A token not issued for the Worker
// audience is refused.
func (k KubeTokenReviewer) Review(ctx context.Context, token string) (authenticationv1.UserInfo, error) {
	tr := &authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{
		Token: token, Audiences: []string{workerv1alpha1.TokenAudience},
	}}
	if err := k.Client.Create(ctx, tr); err != nil {
		return authenticationv1.UserInfo{}, fmt.Errorf("review token: %w", err)
	}
	if !tr.Status.Authenticated || !slices.Contains(tr.Status.Audiences, workerv1alpha1.TokenAudience) {
		return authenticationv1.UserInfo{}, fmt.Errorf("token not authenticated for %s", workerv1alpha1.TokenAudience)
	}
	return tr.Status.User, nil
}

// Authenticator runs the authentication chain for one call.
type Authenticator struct {
	Reviewer  TokenReviewer
	Pods      PodResolver
	Allowlist *Allowlist
	// Node is this node's name; a token bound to a pod elsewhere is refused.
	Node string
	// Now is the clock, time.Now when nil.
	Now func() time.Time

	mu    sync.Mutex
	cache map[[sha256.Size]byte]cached
}

type cached struct {
	user    authenticationv1.UserInfo
	expires time.Time
}

const (
	maxCached = 1024
	// fallbackTTL bounds caching of a token whose expiry cannot be read.
	fallbackTTL = time.Minute
)

func (a *Authenticator) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Authenticate returns the caller of the call in ctx, or a refusal.
func (a *Authenticator) Authenticate(ctx context.Context) (Caller, error) {
	token := bearer(ctx)
	if token == "" {
		return Caller{}, refusal.New(codes.Unauthenticated, workerv1alpha1.ReasonNoIdentity,
			"no bearer token; send a projected ServiceAccount token with audience "+workerv1alpha1.TokenAudience, nil)
	}
	user, err := a.review(ctx, token)
	if err != nil {
		return Caller{}, err
	}
	sa, ok := strings.CutPrefix(user.Username, serviceAccountPrefix)
	if !ok {
		return Caller{}, refusal.New(codes.Unauthenticated, workerv1alpha1.ReasonNoIdentity,
			"token is not a ServiceAccount token", nil)
	}
	ns, name, ok := strings.Cut(sa, ":")
	if !ok {
		return Caller{}, refusal.New(codes.Unauthenticated, workerv1alpha1.ReasonNoIdentity,
			"malformed ServiceAccount username", nil)
	}
	podUID := extra(user, ExtraPodUID)
	if podUID == "" {
		return Caller{}, refusal.New(codes.Unauthenticated, workerv1alpha1.ReasonNoIdentity,
			"token is not bound to a pod", nil)
	}
	if node := extra(user, ExtraNodeName); node != a.Node {
		return Caller{}, refusal.New(codes.Unauthenticated, workerv1alpha1.ReasonNoIdentity,
			fmt.Sprintf("token is bound to a pod on node %q, not this node", node), nil)
	}
	peerInfo, ok := PeerFromContext(ctx)
	if !ok {
		return Caller{}, refusal.New(codes.Unauthenticated, workerv1alpha1.ReasonNoIdentity,
			"connection carries no peer credentials", nil)
	}
	peerPod, err := a.Pods.PodUID(peerInfo.PID)
	if err != nil || peerPod != podUID {
		return Caller{}, refusal.New(codes.Unauthenticated, workerv1alpha1.ReasonNoIdentity,
			"the connecting process does not run in the token's pod", nil)
	}
	c := Caller{ServiceAccount: ns + "/" + name, PodUID: podUID, PodName: extra(user, ExtraPodName)}
	caps, listed := a.Allowlist.Capabilities(c.ServiceAccount)
	if !listed {
		return Caller{}, refusal.New(codes.PermissionDenied, workerv1alpha1.ReasonCapabilityNotAllowed,
			"ServiceAccount "+c.ServiceAccount+" is not in the allowlist", nil)
	}
	c.Capabilities = caps
	c.EgressShardClaims = a.Allowlist.EgressShardClaims(c.ServiceAccount)
	return c, nil
}

// review returns the token's user from the cache or from TokenReview.
func (a *Authenticator) review(ctx context.Context, token string) (authenticationv1.UserInfo, error) {
	key := sha256.Sum256([]byte(token))
	now := a.now()
	exp, hasExp := tokenExpiry(token)
	if hasExp && !now.Before(exp) {
		return authenticationv1.UserInfo{}, refusal.New(codes.Unauthenticated, workerv1alpha1.ReasonIdentityExpired,
			"token has expired; read the projected token again", nil)
	}
	a.mu.Lock()
	if c, ok := a.cache[key]; ok && now.Before(c.expires) {
		a.mu.Unlock()
		return c.user, nil
	}
	a.mu.Unlock()

	user, err := a.Reviewer.Review(ctx, token)
	if err != nil {
		return authenticationv1.UserInfo{}, refusal.New(codes.Unauthenticated, workerv1alpha1.ReasonNoIdentity,
			"token review refused the token", nil)
	}
	if !hasExp {
		exp = now.Add(fallbackTTL)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cache == nil {
		a.cache = map[[sha256.Size]byte]cached{}
	}
	if len(a.cache) >= maxCached {
		for k, c := range a.cache {
			if !now.Before(c.expires) {
				delete(a.cache, k)
			}
		}
		if len(a.cache) >= maxCached {
			clear(a.cache)
		}
	}
	a.cache[key] = cached{user: user, expires: exp}
	return user, nil
}

// bearer returns the bearer token of the call, or "".
func bearer(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx)
	for _, v := range md.Get("authorization") {
		if t, ok := strings.CutPrefix(v, "Bearer "); ok {
			return strings.TrimSpace(t)
		}
	}
	return ""
}

func extra(u authenticationv1.UserInfo, key string) string {
	if v := u.Extra[key]; len(v) == 1 {
		return v[0]
	}
	return ""
}

// tokenExpiry reads the exp claim of a JWT without verifying it. It only
// bounds how long a TokenReview result is cached and refuses a token that
// has visibly expired; TokenReview remains the only check of validity.
func tokenExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(b, &claims) != nil || claims.Exp == 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}
