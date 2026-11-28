// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"net"
	"net/http"
	"net/url"

	"k8s.io/client-go/rest"
)

// dialAPIThroughSocket makes every connection cfg opens go to the unix socket
// at path instead of cfg.Host's address. It changes only the dialer: the host,
// CA, TLS server name and credentials stay as they are, so TLS still runs end
// to end with the API server, which the socket's proxy reaches by forwarding
// bytes. The proxy never sees plaintext or adds credentials, and the API
// server still authenticates the sidecar's own ServiceAccount.
//
// The socket is dialed per connection, so one that appears after startup is
// picked up on client-go's next retry.
//
// It also disables any HTTP proxy from the environment. client-go falls back
// to HTTPS_PROXY when cfg.Proxy is nil, and a proxy there would make the
// socket's peer an HTTP CONNECT proxy rather than the API server.
func dialAPIThroughSocket(cfg *rest.Config, path string) {
	var d net.Dialer
	cfg.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return d.DialContext(ctx, "unix", path)
	}
	cfg.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
}
