// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// Grants provisions connector grant records in Namespace for an operator.
// Client must read without a cache.
type Grants struct {
	Client    client.Client
	Namespace string
	Now       func() time.Time
}

// Issued is a credential as issued to an operator: the only time the
// credential itself is returned.
type Issued struct {
	Connector  string       `json:"connector"`
	Credential string       `json:"credential"`
	Revision   int64        `json:"revision"`
	VPC        string       `json:"vpc"`
	Prefix     netip.Prefix `json:"prefix"`
	Expires    time.Time    `json:"expires"`
}

// CreateRequest describes a new connector.
type CreateRequest struct {
	// VPC is the VPC's namespace and name; its UID is read from the API.
	VPC  VPCRef
	Cell string
	// Connector is the connector's UUID; empty means a new random one.
	Connector string
	// Lifetime is how long the credential is valid, at most MaxLifetime.
	Lifetime      time.Duration
	Routes        []netip.Prefix
	TrafficPolicy *galacticv1alpha1.TrafficPolicyBindingSpec
}

func (g Grants) ledgers() Ledgers {
	return Ledgers(g)
}

// expiry returns now plus lifetime, refusing a lifetime outside
// (0, MaxLifetime].
func (g Grants) expiry(lifetime time.Duration) (time.Time, error) {
	if lifetime <= 0 || lifetime > MaxLifetime {
		return time.Time{}, fmt.Errorf("lifetime %v is not within (0, %v]", lifetime, MaxLifetime)
	}
	return g.Now().Add(lifetime).UTC().Truncate(time.Second), nil
}

// Create allocates the connector's /96 in the ledger of its VPC and cell,
// writes its grant record with a new credential and returns that
// credential. It refuses a connector that already has a record.
func (g Grants) Create(ctx context.Context, req CreateRequest) (Issued, error) {
	expires, err := g.expiry(req.Lifetime)
	if err != nil {
		return Issued{}, err
	}
	if req.Connector == "" {
		req.Connector = uuid.NewString()
	}
	var vpc cloudv1alpha1.VPC
	if err := g.Client.Get(ctx, client.ObjectKey{Namespace: req.VPC.Namespace, Name: req.VPC.Name}, &vpc); err != nil {
		return Issued{}, fmt.Errorf("read VPC %s: %w", req.VPC.Selector(), err)
	}
	if req.VPC.UID != "" && req.VPC.UID != string(vpc.UID) {
		return Issued{}, fmt.Errorf("VPC %s has UID %s, not %s", req.VPC.Selector(), vpc.UID, req.VPC.UID)
	}
	req.VPC.UID = string(vpc.UID)
	cred := NewCredential()
	r := &Record{
		Connector: req.Connector, Cell: req.Cell, VPC: req.VPC, Revision: 1, Digest: Digest(cred),
		Expires: expires, Enabled: true, Routes: req.Routes, TrafficPolicy: req.TrafficPolicy,
	}
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: g.Namespace}}
	if err := encodeRecord(s, r); err != nil {
		return Issued{}, err
	}
	e, err := g.ledgers().Allocate(ctx, r.VPC.UID, r.Cell, r.Connector)
	if err != nil {
		return Issued{}, fmt.Errorf("allocate connector %s: %w", r.Connector, err)
	}
	if err := g.Client.Create(ctx, s); err != nil {
		return Issued{}, fmt.Errorf("create grant record %s: %w", s.Name, err)
	}
	return Issued{Connector: r.Connector, Credential: cred, Revision: r.Revision, VPC: r.VPC.Selector(),
		Prefix: e.Prefix, Expires: expires}, nil
}

// Rotate replaces the connector's credential with a new one valid for
// lifetime, under the next revision, and returns it. Authorizations issued
// under the old revision are no longer renewed, and the old credential
// admits nothing.
func (g Grants) Rotate(ctx context.Context, connector string, lifetime time.Duration) (Issued, error) {
	expires, err := g.expiry(lifetime)
	if err != nil {
		return Issued{}, err
	}
	cred := NewCredential()
	var out Issued
	var vpcUID, cell string
	err = g.update(ctx, connector, func(r *Record) error {
		if !r.Enabled {
			return errors.New("connector is disabled")
		}
		r.Revision++
		r.Digest, r.Expires = Digest(cred), expires
		out = Issued{Connector: r.Connector, Credential: cred, Revision: r.Revision, VPC: r.VPC.Selector(),
			Expires: expires}
		vpcUID, cell = r.VPC.UID, r.Cell
		return nil
	})
	if err != nil {
		return Issued{}, err
	}
	// The new credential is committed: return it even when the prefix,
	// which is informational, cannot be read.
	if l, _, err := g.ledgers().Read(ctx, vpcUID, cell); err == nil {
		if e, ok := l.Lookup(connector); ok {
			out.Prefix = e.Prefix
		}
	}
	return out, nil
}

// Disable revokes the connector under the next revision: its credential
// admits nothing and its authorizations are no longer renewed.
func (g Grants) Disable(ctx context.Context, connector string) error {
	return g.update(ctx, connector, func(r *Record) error {
		if r.Enabled {
			r.Enabled = false
			r.Revision++
		}
		return nil
	})
}

// Retire disables the connector and tombstones its allocation, so its /96
// and attachment pool are never allocated again.
func (g Grants) Retire(ctx context.Context, connector string) error {
	if err := g.Disable(ctx, connector); err != nil {
		return err
	}
	r, _, err := readRecord(ctx, g.Client, g.Namespace, connector)
	if err != nil {
		return err
	}
	return g.ledgers().Retire(ctx, r.VPC.UID, r.Cell, connector)
}

// update applies change to a fresh read of the connector's record and
// writes it back conditioned on the read's UID and resourceVersion.
func (g Grants) update(ctx context.Context, connector string, change func(*Record) error) error {
	r, s, err := readRecord(ctx, g.Client, g.Namespace, connector)
	if err != nil {
		return fmt.Errorf("read grant record of %s: %w", connector, err)
	}
	if err := change(r); err != nil {
		return fmt.Errorf("connector %s: %w", connector, err)
	}
	if err := encodeRecord(s, r); err != nil {
		return err
	}
	if err := g.Client.Update(ctx, s); err != nil {
		return fmt.Errorf("update grant record of %s: %w", connector, err)
	}
	return nil
}
