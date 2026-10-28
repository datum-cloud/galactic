// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
)

// credentialBytes is the number of random bytes in a bearer credential.
const credentialBytes = 32

// NewCredential returns a new bearer credential: 32 random bytes, base64url
// encoded without padding.
func NewCredential() string {
	b := make([]byte, credentialBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error.
	return base64.RawURLEncoding.EncodeToString(b)
}

// Digest returns the hex SHA-256 digest of credential, the only form in
// which the authority stores it.
func Digest(credential string) string {
	sum := sha256.Sum256([]byte(credential))
	return hex.EncodeToString(sum[:])
}

// wellFormed reports whether credential could be one NewCredential issued.
func wellFormed(credential string) bool {
	b, err := base64.RawURLEncoding.DecodeString(credential)
	return err == nil && len(b) == credentialBytes
}

// sameDigest compares two digests in constant time.
func sameDigest(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
