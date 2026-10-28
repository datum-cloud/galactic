// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package certreload serves a TLS certificate from files that are rewritten
// in place, such as a mounted Secret that cert-manager renews.
package certreload

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Reloader serves the certificate in CertFile and KeyFile, reloading it
// when either file changes.
type Reloader struct {
	CertFile, KeyFile string

	mu    sync.Mutex
	stamp string
	cert  *tls.Certificate
}

// GetCertificate implements tls.Config.GetCertificate. It rereads the pair
// when either file's modification time or size changed since the last load.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	var stamp strings.Builder
	for _, p := range []string{r.CertFile, r.KeyFile} {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&stamp, "%d/%d;", fi.ModTime().UnixNano(), fi.Size())
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cert != nil && r.stamp == stamp.String() {
		return r.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(r.CertFile, r.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load the server certificate: %w", err)
	}
	r.cert, r.stamp = &cert, stamp.String()
	return r.cert, nil
}
