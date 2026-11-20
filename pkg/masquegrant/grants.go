// Package masquegrant exposes the cell-scoped grant ledger to trusted brokers.
// Callers must provision a ledger explicitly; minting never initializes one.
package masquegrant

import (
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/edge/masque/authority"
)

// CreateRequest identifies a connector, UID-pinned VPC and optional managed
// endpoint. Managed grants require issuer-resolved NetworkUID and BindingUID;
// the shared endpoint itself is independent of every VPC and network binding.
type CreateRequest = authority.CreateRequest

// Issued contains the credential and retained connector allocation.
type Issued = authority.Issued

// VPCRef identifies the cell-local VPC by name and UID.
type VPCRef = authority.VPCRef

// Grants manages credentials without releasing retained connector allocations.
type Grants = authority.Grants

// Ledgers exposes the existing administrative ledger operations for bootstrap.
type Ledgers = authority.Ledgers

// New constructs a grant client. It does not initialize a ledger.
func New(cellClient client.Client, namespace string) Grants {
	return Grants{Client: cellClient, Namespace: namespace, Now: time.Now}
}

// NewLedgers constructs an explicit administrative bootstrap client.
func NewLedgers(cellClient client.Client, namespace string) Ledgers {
	return Ledgers{Client: cellClient, Namespace: namespace, Now: time.Now}
}
