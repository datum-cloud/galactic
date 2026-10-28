// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package authority

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

const (
	// LabelLedger marks a ConfigMap of the authority's namespace as an
	// allocation ledger.
	LabelLedger = "masque.galactic.datumapis.com/ledger"
	// ledgerKey is the ConfigMap data key holding a ledger.
	ledgerKey = "ledger.json"
	// MaxEntries is the most entries, retired ones included, one ledger
	// holds.
	MaxEntries = 256
	// maxLedgerBytes bounds a ledger's encoded size.
	maxLedgerBytes = 256 << 10
	// rangeBits is the size of the connector and pool ranges a ledger
	// allocates from.
	rangeBits = 80
	// conflictRetries bounds how often a ledger write is retried from a
	// fresh read after a conflict.
	conflictRetries = 5
)

// ErrLedgerMissing is returned when a VPC and cell have no ledger. A missing
// ledger is an operator recovery event: nothing is allocated until it is
// restored.
var ErrLedgerMissing = errors.New("allocation ledger does not exist")

// Ledger is the durable record of every connector allocation of one VPC in
// one cell.
type Ledger struct {
	VPC  VPCRef `json:"vpc"`
	Cell string `json:"cell"`
	// Connectors is the /80 connector /96s are allocated from.
	Connectors netip.Prefix `json:"connectors"`
	// Pools is the /80 attachment /120 pools are allocated from.
	Pools netip.Prefix `json:"pools"`
	// Entries are in allocation order. An entry is never removed.
	Entries []Entry `json:"entries"`
}

// Entry is one connector's allocation.
type Entry struct {
	Connector  string       `json:"connector"`
	Allocation string       `json:"allocation"`
	Prefix     netip.Prefix `json:"prefix"`
	Pool       netip.Prefix `json:"pool"`
	Created    time.Time    `json:"created"`
	// Retired entries are tombstones: their prefix and pool are never
	// allocated again.
	Retired bool `json:"retired,omitempty"`
}

// Lookup returns connector's entry.
func (l *Ledger) Lookup(connector string) (Entry, bool) {
	for _, e := range l.Entries {
		if e.Connector == connector {
			return e, true
		}
	}
	return Entry{}, false
}

// LedgerName is the name of the ledger ConfigMap of vpcUID in cell.
func LedgerName(vpcUID, cell string) string { return "masque-ledger-" + vpcUID + "-" + cell }

// Ledgers reads and writes allocation ledgers in Namespace. Client must read
// without a cache.
type Ledgers struct {
	Client    client.Client
	Namespace string
	Now       func() time.Time
}

// Init creates the ledger of vpc in cell, allocating connector /96s from
// connectors and attachment pools from pools. Both must be masked,
// disjoint IPv6 /80s inside one of the VPC's networks, and vpc's UID must be
// the live VPC's. It refuses to replace an existing ledger, to create one
// while an EdgeService the authority issued for the VPC in cell exists, and
// to create one whose ranges overlap those of any other ledger of the VPC.
func (s Ledgers) Init(ctx context.Context, vpc VPCRef, cell string, connectors, pools netip.Prefix) error {
	if errs := validation.IsDNS1123Label(cell); len(errs) > 0 {
		return fmt.Errorf("cell %q: %v", cell, errs)
	}
	var obj cloudv1alpha1.VPC
	if err := s.Client.Get(ctx, client.ObjectKey{Namespace: vpc.Namespace, Name: vpc.Name}, &obj); err != nil {
		return fmt.Errorf("read VPC %s: %w", vpc.Selector(), err)
	}
	if vpc.UID == "" {
		vpc.UID = string(obj.UID)
	}
	if string(obj.UID) != vpc.UID {
		return fmt.Errorf("VPC %s has UID %s, not %s", vpc.Selector(), obj.UID, vpc.UID)
	}
	for _, p := range []netip.Prefix{connectors, pools} {
		if !p.IsValid() || !p.Addr().Is6() || p.Addr().Is4In6() || p.Bits() != rangeBits || p != p.Masked() {
			return fmt.Errorf("range %s is not a masked IPv6 /%d", p, rangeBits)
		}
		if !inNetworks(obj.Spec.Networks, p) {
			return fmt.Errorf("range %s is outside VPC %s's networks", p, vpc.Selector())
		}
	}
	if connectors.Overlaps(pools) {
		return fmt.Errorf("connector range %s overlaps pool range %s", connectors, pools)
	}
	// A recreated ledger restarts its allocations; it must not hand out a
	// /96 or pool an issued service still holds.
	var issued galacticv1alpha1.EdgeServiceList
	if err := s.Client.List(ctx, &issued, client.InNamespace(vpc.Namespace),
		client.MatchingLabels{LabelManagedBy: ManagedBy}); err != nil {
		return fmt.Errorf("list issued EdgeServices: %w", err)
	}
	for _, svc := range issued.Items {
		if svc.Spec.VPCRef.UID == vpc.UID && svc.Annotations[AnnotationCell] == cell {
			return fmt.Errorf("EdgeService %s/%s still holds an allocation of VPC %s; delete it first",
				svc.Namespace, svc.Name, vpc.Selector())
		}
	}
	// Cells of one VPC must not be handed overlapping ranges.
	var ledgers corev1.ConfigMapList
	if err := s.Client.List(ctx, &ledgers, client.InNamespace(s.Namespace),
		client.MatchingLabels{LabelLedger: yes}); err != nil {
		return fmt.Errorf("list ledgers: %w", err)
	}
	for _, other := range ledgers.Items {
		var ol Ledger
		if err := json.Unmarshal([]byte(other.Data[ledgerKey]), &ol); err != nil {
			return fmt.Errorf("decode ledger %s: %w", other.Name, err)
		}
		if ol.VPC.UID != vpc.UID || ol.Cell == cell {
			continue
		}
		for _, p := range []netip.Prefix{connectors, pools} {
			if p.Overlaps(ol.Connectors) || p.Overlaps(ol.Pools) {
				return fmt.Errorf("range %s overlaps a range of the ledger of VPC %s in cell %s",
					p, vpc.Selector(), ol.Cell)
			}
		}
	}
	l := &Ledger{VPC: vpc, Cell: cell, Connectors: connectors, Pools: pools, Entries: []Entry{}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Namespace: s.Namespace, Name: LedgerName(vpc.UID, cell),
		Labels: map[string]string{LabelLedger: yes},
	}}
	if err := encodeLedger(cm, l); err != nil {
		return err
	}
	if err := s.Client.Create(ctx, cm); err != nil {
		return fmt.Errorf("create ledger %s: %w", cm.Name, err)
	}
	return nil
}

// holding returns every ledger with an entry for connector.
func (s Ledgers) holding(ctx context.Context, connector string) ([]*Ledger, error) {
	var cms corev1.ConfigMapList
	if err := s.Client.List(ctx, &cms, client.InNamespace(s.Namespace),
		client.MatchingLabels{LabelLedger: yes}); err != nil {
		return nil, fmt.Errorf("list ledgers: %w", err)
	}
	var out []*Ledger
	for _, cm := range cms.Items {
		var l Ledger
		if err := json.Unmarshal([]byte(cm.Data[ledgerKey]), &l); err != nil {
			return nil, fmt.Errorf("decode ledger %s: %w", cm.Name, err)
		}
		if _, ok := l.Lookup(connector); ok {
			out = append(out, &l)
		}
	}
	return out, nil
}

// inNetworks reports whether p lies inside one of networks.
func inNetworks(networks []cloudv1alpha1.Network, p netip.Prefix) bool {
	for _, n := range networks {
		np, err := netip.ParsePrefix(string(n))
		if err == nil && np.Addr().Is6() && np.Bits() <= p.Bits() && np.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// Read returns the ledger of vpcUID in cell and its ConfigMap. It returns
// ErrLedgerMissing when there is none.
func (s Ledgers) Read(ctx context.Context, vpcUID, cell string) (*Ledger, *corev1.ConfigMap, error) {
	var cm corev1.ConfigMap
	err := s.Client.Get(ctx, client.ObjectKey{Namespace: s.Namespace, Name: LedgerName(vpcUID, cell)}, &cm)
	if apierrors.IsNotFound(err) {
		return nil, nil, fmt.Errorf("%w: VPC %s in cell %s", ErrLedgerMissing, vpcUID, cell)
	}
	if err != nil {
		return nil, nil, err
	}
	var l Ledger
	if err := json.Unmarshal([]byte(cm.Data[ledgerKey]), &l); err != nil {
		return nil, nil, fmt.Errorf("decode ledger %s: %w", cm.Name, err)
	}
	if l.VPC.UID != vpcUID || l.Cell != cell {
		return nil, nil, fmt.Errorf("ledger %s is for VPC %s in cell %s", cm.Name, l.VPC.UID, l.Cell)
	}
	return &l, &cm, nil
}

// Allocate returns connector's allocation in the ledger of vpcUID in cell,
// adding one when the connector has none. A new allocation takes the next
// /96 and /120 no entry ever held. It refuses a retired connector and a
// full ledger.
func (s Ledgers) Allocate(ctx context.Context, vpcUID, cell, connector string) (Entry, error) {
	var out Entry
	err := s.update(ctx, vpcUID, cell, func(l *Ledger) (bool, error) {
		if e, ok := l.Lookup(connector); ok {
			if e.Retired {
				return false, fmt.Errorf("connector %s is retired", connector)
			}
			out = e
			return false, nil
		}
		if len(l.Entries) >= MaxEntries {
			return false, fmt.Errorf("ledger is full at %d entries", MaxEntries)
		}
		n := uint64(len(l.Entries) + 1)
		out = Entry{
			Connector: connector, Allocation: uuid.NewString(),
			Prefix:  netip.PrefixFrom(withIndex(l.Connectors.Addr(), n<<32), 96),
			Pool:    netip.PrefixFrom(withIndex(l.Pools.Addr(), n<<8), 120),
			Created: s.Now().UTC().Truncate(time.Second),
		}
		l.Entries = append(l.Entries, out)
		return true, nil
	})
	return out, err
}

// Retire marks connector's allocation retired. Its /96 and pool stay
// tombstoned. Retiring a retired or unknown connector does nothing.
func (s Ledgers) Retire(ctx context.Context, vpcUID, cell, connector string) error {
	return s.update(ctx, vpcUID, cell, func(l *Ledger) (bool, error) {
		for i := range l.Entries {
			if l.Entries[i].Connector == connector && !l.Entries[i].Retired {
				l.Entries[i].Retired = true
				return true, nil
			}
		}
		return false, nil
	})
}

// update applies change to a fresh read of the ledger and writes it back
// conditioned on the read's UID and resourceVersion, retrying from a fresh
// read after a conflict. change reports whether it modified the ledger.
func (s Ledgers) update(ctx context.Context, vpcUID, cell string, change func(*Ledger) (bool, error)) error {
	for range conflictRetries {
		l, cm, err := s.Read(ctx, vpcUID, cell)
		if err != nil {
			return err
		}
		changed, err := change(l)
		if err != nil || !changed {
			return err
		}
		if err := encodeLedger(cm, l); err != nil {
			return err
		}
		// Update carries the read's UID and resourceVersion, so a ledger
		// changed or recreated since conflicts.
		err = s.Client.Update(ctx, cm)
		if !apierrors.IsConflict(err) {
			return err
		}
	}
	return fmt.Errorf("ledger %s kept changing", LedgerName(vpcUID, cell))
}

// withIndex returns base with n added to its low 64 bits.
func withIndex(base netip.Addr, n uint64) netip.Addr {
	b := base.As16()
	lo := uint64(0)
	for i := 8; i < 16; i++ {
		lo = lo<<8 | uint64(b[i])
	}
	lo += n
	for i := 15; i >= 8; i-- {
		b[i] = byte(lo)
		lo >>= 8
	}
	return netip.AddrFrom16(b)
}

// encodeLedger stores l in cm.
func encodeLedger(cm *corev1.ConfigMap, l *Ledger) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if len(b) > maxLedgerBytes {
		return fmt.Errorf("ledger would be %d bytes, over the %d limit", len(b), maxLedgerBytes)
	}
	cm.Data = map[string]string{ledgerKey: string(b)}
	return nil
}
