// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/edge/admission"
	"go.datum.net/galactic/internal/edge/connectip"
)

const (
	// DefaultAudience is the token audience provider pods present.
	DefaultAudience = "masque-authority"
	// requestTimeout bounds one call, API reads and writes included.
	requestTimeout = 2 * time.Second
	// maxBody bounds a request body.
	maxBody = 8 << 10
)

// API paths.
const (
	PathAuthorize = "/v1/authorize"
	PathRefresh   = "/v1/refresh"
	PathRetire    = "/v1/retire"
)

// AuthorizeRequest is the body of an Authorize call.
type AuthorizeRequest struct {
	Credential string `json:"credential"`
	VPC        string `json:"vpc"`
	// Nonce identifies the call: its retries send the same nonce and
	// issue time.
	Nonce string `json:"nonce"`
	// Issued is when the caller first sent the call.
	Issued time.Time `json:"issued"`
}

// RefreshRequest is the body of a Refresh call.
type RefreshRequest struct {
	Authorization string     `json:"authorization"`
	Revision      int64      `json:"revision"`
	Service       ServiceRef `json:"service"`
}

// RetireRequest is the body of a Retire call.
type RetireRequest struct {
	Authorization string     `json:"authorization"`
	Service       ServiceRef `json:"service"`
}

// errorBody is the body of a refused or failed call.
type errorBody struct {
	Error string `json:"error"`
}

// TokenReviewer authenticates a bearer token.
type TokenReviewer interface {
	// Review returns the user the token authenticates, or an error.
	Review(ctx context.Context, token string) (authenticationv1.UserInfo, error)
}

// KubeTokenReviewer reviews tokens with the API server's TokenReview for
// Audience.
type KubeTokenReviewer struct {
	Client   client.Client
	Audience string
}

// Review implements TokenReviewer. A token not issued for Audience is
// refused.
func (k KubeTokenReviewer) Review(ctx context.Context, token string) (authenticationv1.UserInfo, error) {
	tr := &authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{
		Token: token, Audiences: []string{k.Audience},
	}}
	if err := k.Client.Create(ctx, tr); err != nil {
		return authenticationv1.UserInfo{}, fmt.Errorf("%w: review token: %w", ErrUnavailable, err)
	}
	if !tr.Status.Authenticated || !slices.Contains(tr.Status.Audiences, k.Audience) {
		return authenticationv1.UserInfo{}, fmt.Errorf("%w: token not authenticated for %s",
			connectip.ErrUnauthenticated, k.Audience)
	}
	return tr.Status.User, nil
}

// Server serves an Authority over HTTP. Run it behind TLS.
type Server struct {
	Authority *Authority
	Reviewer  TokenReviewer
	Log       *slog.Logger
}

// Handler returns the server's routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+PathAuthorize, s.handle(func(ctx context.Context, id admission.Identity,
		dec *json.Decoder) (any, error) {
		var req AuthorizeRequest
		if err := dec.Decode(&req); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		return s.Authority.Authorize(ctx, id, req)
	}))
	mux.HandleFunc("POST "+PathRefresh, s.handle(func(ctx context.Context, id admission.Identity,
		dec *json.Decoder) (any, error) {
		var req RefreshRequest
		if err := dec.Decode(&req); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		return s.Authority.Refresh(ctx, id, req.Authorization, req.Revision, req.Service)
	}))
	mux.HandleFunc("POST "+PathRetire, s.handle(func(ctx context.Context, id admission.Identity,
		dec *json.Decoder) (any, error) {
		var req RetireRequest
		if err := dec.Decode(&req); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		return struct{}{}, s.Authority.Retire(ctx, id, req.Authorization, req.Service)
	}))
	return mux
}

// handle authenticates the calling pod, bounds the call and writes call's
// result or error. Request bodies, which may carry a credential, are never
// logged.
func (s *Server) handle(call func(context.Context, admission.Identity, *json.Decoder) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		res, err := s.call(ctx, r, call)
		if err != nil {
			code := status(err)
			s.log().Info("call refused", "path", r.URL.Path, "status", code, "error", err)
			writeJSON(w, code, errorBody{Error: http.StatusText(code)})
			return
		}
		writeJSON(w, http.StatusOK, res)
	}
}

func (s *Server) call(ctx context.Context, r *http.Request,
	call func(context.Context, admission.Identity, *json.Decoder) (any, error)) (any, error) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return nil, fmt.Errorf("%w: no bearer token", connectip.ErrUnauthenticated)
	}
	user, err := s.Reviewer.Review(ctx, token)
	if err != nil {
		return nil, err
	}
	id, err := admission.IdentityFromUserInfo(user)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", connectip.ErrUnauthenticated, err)
	}
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBody))
	dec.DisallowUnknownFields()
	return call(ctx, id, dec)
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// status is the HTTP status of a call's error.
func status(err error) int {
	switch {
	case errors.Is(err, connectip.ErrUnauthenticated):
		return http.StatusUnauthorized
	case errors.Is(err, connectip.ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, ErrInvalid):
		return http.StatusBadRequest
	default:
		return http.StatusServiceUnavailable
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
