// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"go.datum.net/galactic/internal/edge/connectip"
	"go.datum.net/galactic/internal/edge/masque"
)

// authorizeAttempts bounds how often Authorize sends one call, with one
// nonce, after a transport failure.
const authorizeAttempts = 2

// maxResponse bounds an answer the client reads: a grant with MaxRoutes
// routes fits well within it.
const maxResponse = 64 << 10

// Client is the provider side of the authority: a masque.Authorizer that
// calls a Server over HTTPS as the pod its ServiceAccount token is bound to.
type Client struct {
	// URL is the authority's base URL, https://host:port.
	URL string
	// TokenFile holds the pod's projected ServiceAccount token for the
	// authority's audience. It is reread on every call, so a rotated token
	// is used once the kubelet writes it.
	TokenFile string
	// CAFile holds the PEM roots the authority's certificate must chain to.
	// It is reread when it changes, so roots rotate without a restart.
	CAFile string
	// Timeout bounds one call; zero means two seconds.
	Timeout time.Duration
	// Now stamps Authorize calls; nil means time.Now.
	Now func() time.Time

	mu        sync.Mutex
	transport *http.Transport
	caStamp   string
}

var _ masque.Authorizer = (*Client)(nil)

// Authorize implements masque.Authorizer.
func (c *Client) Authorize(ctx context.Context, credential, vpc string) (masque.Grant, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	req := AuthorizeRequest{Credential: credential, VPC: vpc, Nonce: rand.Text(), Issued: now()}
	var g Grant
	var err error
	for range authorizeAttempts {
		var sent bool
		sent, err = c.call(ctx, PathAuthorize, req, &g)
		if err == nil {
			return toGrant(&g), nil
		}
		if sent || ctx.Err() != nil {
			break
		}
	}
	return masque.Grant{}, err
}

// Refresh implements masque.Authorizer.
func (c *Client) Refresh(ctx context.Context, g masque.Grant) (masque.Grant, error) {
	var out Grant
	_, err := c.call(ctx, PathRefresh, RefreshRequest{
		Authorization: g.Authorization, Revision: g.Revision, Service: fromServiceRef(g.Service),
	}, &out)
	if err != nil {
		return masque.Grant{}, err
	}
	return toGrant(&out), nil
}

// Retire implements masque.Authorizer.
func (c *Client) Retire(ctx context.Context, g masque.Grant) error {
	_, err := c.call(ctx, PathRetire, RetireRequest{
		Authorization: g.Authorization, Service: fromServiceRef(g.Service),
	}, &struct{}{})
	return err
}

// call posts body to path and decodes a successful answer into out. It
// reports whether the server answered. A 401 wraps
// connectip.ErrUnauthenticated and a 403 connectip.ErrForbidden; any other
// failure is retryable.
func (c *Client) call(ctx context.Context, path string, body, out any) (bool, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = requestTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	token, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return false, fmt.Errorf("read the authority token: %w", err)
	}
	transport, err := c.currentTransport()
	if err != nil {
		return false, err
	}
	b, err := json.Marshal(body)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.URL, "/")+path,
		bytes.NewReader(b))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return false, fmt.Errorf("call the authority: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	r := io.LimitReader(resp.Body, maxResponse)
	switch resp.StatusCode {
	case http.StatusOK:
		if err := json.NewDecoder(r).Decode(out); err != nil {
			return true, fmt.Errorf("decode the authority's answer: %w", err)
		}
		return true, nil
	case http.StatusUnauthorized:
		return true, fmt.Errorf("authority: %w", connectip.ErrUnauthenticated)
	case http.StatusForbidden:
		return true, fmt.Errorf("authority: %w", connectip.ErrForbidden)
	default:
		return true, fmt.Errorf("authority answered %s", resp.Status)
	}
}

// currentTransport returns a TLS 1.3 transport trusting the roots in CAFile,
// rebuilt when the file changed.
func (c *Client) currentTransport() (*http.Transport, error) {
	fi, err := os.Stat(c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("stat the authority CA: %w", err)
	}
	stamp := fmt.Sprintf("%d/%d", fi.ModTime().UnixNano(), fi.Size())
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.transport != nil && stamp == c.caStamp {
		return c.transport, nil
	}
	pem, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read the authority CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("the authority CA file holds no certificate")
	}
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	c.transport = &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	c.caStamp = stamp
	return c.transport, nil
}

func toGrant(g *Grant) masque.Grant {
	return masque.Grant{
		Connector: g.Connector, Principal: g.Connector, VPC: g.VPC, VPCUID: g.VPCUID, VPCID: g.VPCID,
		Service: masque.ServiceRef{Namespace: g.Service.Namespace, Name: g.Service.Name, UID: g.Service.UID},
		Prefix:  g.Prefix, Routes: g.Routes, NotAfter: g.NotAfter, Authorization: g.Authorization,
		Revision: g.Revision,
	}
}

func fromServiceRef(s masque.ServiceRef) ServiceRef {
	return ServiceRef{Namespace: s.Namespace, Name: s.Name, UID: s.UID}
}
