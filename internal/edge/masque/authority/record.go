// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

const (
	// LabelGrant marks a Secret of the authority's namespace as a grant
	// record.
	LabelGrant = "masque.galactic.datumapis.com/grant"
	// LabelConnector names the connector of a grant record or of an
	// EdgeService the authority issued.
	LabelConnector = "masque.galactic.datumapis.com/connector"
	// recordKey is the Secret data key holding a record.
	recordKey = "grant.json"
	// MaxLifetime is the longest a credential may stay valid.
	MaxLifetime = 24 * time.Hour
	// MaxRoutes bounds a record's allowed destinations.
	MaxRoutes = 64
	// yes is the value of a set marker label or annotation.
	yes = "true"
)

// VPCRef identifies a VPC: its namespace and name, and the UID that pins
// the object.
type VPCRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

// Selector is the value a CONNECT-IP request names the VPC by:
// namespace/name.
func (v VPCRef) Selector() string { return v.Namespace + "/" + v.Name }

// Record is one connector's grant, as the operator approved it.
type Record struct {
	// Connector is the connector's immutable UUID.
	Connector string `json:"connector"`
	// Cell is the only cell whose authority honors the record.
	Cell string `json:"cell"`
	// VPC is the only VPC the connector may use.
	VPC VPCRef `json:"vpc"`
	// Revision is the credential revision. Rotating or disabling the
	// credential increments it.
	Revision int64 `json:"revision"`
	// Digest is the hex SHA-256 digest of the current credential.
	Digest string `json:"digest"`
	// Expires is when the current credential stops being valid.
	Expires time.Time `json:"expires"`
	// Enabled is false once the operator revoked the connector.
	Enabled bool `json:"enabled"`
	// Routes are the gVPC destinations the connector may reach, advertised
	// to the client.
	Routes []netip.Prefix `json:"routes,omitempty"`
	// TrafficPolicy is copied into every EdgeService the record yields.
	TrafficPolicy *galacticv1alpha1.TrafficPolicyBindingSpec `json:"trafficPolicy,omitempty"`
}

// RecordName is the name of connector's grant record Secret.
func RecordName(connector string) string { return "masque-grant-" + connector }

// validate reports the first malformed field of r.
func (r *Record) validate() error {
	if _, err := uuid.Parse(r.Connector); err != nil || r.Connector != uuid.MustParse(r.Connector).String() {
		return fmt.Errorf("connector %q is not a lowercase UUID", r.Connector)
	}
	if r.Cell == "" || r.VPC.Namespace == "" || r.VPC.Name == "" || r.VPC.UID == "" {
		return errors.New("cell and VPC namespace, name and UID are required")
	}
	if b, err := hex.DecodeString(r.Digest); err != nil || len(b) != 32 {
		return errors.New("digest is not a hex SHA-256 digest")
	}
	if r.Expires.IsZero() || r.Revision < 1 {
		return errors.New("expiry and a positive revision are required")
	}
	if len(r.Routes) > MaxRoutes {
		return fmt.Errorf("%d routes exceed the limit of %d", len(r.Routes), MaxRoutes)
	}
	for _, p := range r.Routes {
		if !p.IsValid() || !p.Addr().Is6() || p.Addr().Is4In6() || p != p.Masked() {
			return fmt.Errorf("route %s is not a masked IPv6 prefix", p)
		}
	}
	return nil
}

// decodeRecord reads the record of a grant Secret.
func decodeRecord(s *corev1.Secret) (*Record, error) {
	var r Record
	if err := json.Unmarshal(s.Data[recordKey], &r); err != nil {
		return nil, fmt.Errorf("decode grant record %s: %w", s.Name, err)
	}
	if err := r.validate(); err != nil {
		return nil, fmt.Errorf("grant record %s: %w", s.Name, err)
	}
	if s.Name != RecordName(r.Connector) || s.Labels[LabelConnector] != r.Connector {
		return nil, fmt.Errorf("grant record %s is not named for connector %s", s.Name, r.Connector)
	}
	return &r, nil
}

// encodeRecord stores r in s.
func encodeRecord(s *corev1.Secret, r *Record) error {
	if err := r.validate(); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	s.Name = RecordName(r.Connector)
	if s.Labels == nil {
		s.Labels = map[string]string{}
	}
	s.Labels[LabelGrant] = yes
	s.Labels[LabelConnector] = r.Connector
	s.Type = corev1.SecretTypeOpaque
	s.Data = map[string][]byte{recordKey: b}
	return nil
}

// readRecord reads connector's record from namespace through reader. It
// returns the Secret too, for a conditional update.
func readRecord(ctx context.Context, reader client.Reader, namespace, connector string) (*Record, *corev1.Secret,
	error) {
	var s corev1.Secret
	if err := reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: RecordName(connector)}, &s); err != nil {
		return nil, nil, err
	}
	r, err := decodeRecord(&s)
	return r, &s, err
}
