// Package masquegrant exposes the cell-scoped grant ledger to trusted brokers.
// Callers must provision a ledger explicitly; minting never initializes one.
package masquegrant

import (
	"context"
	"net/netip"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/masque/authority"
)

type EndpointRef = galacticv1alpha1.MASQUEEndpointReference

type VPCRef struct {
	Namespace string
	Name      string
}

func (ref VPCRef) Selector() string { return ref.Namespace + "/" + ref.Name }

type CreateRequest struct {
	EndpointRef   *EndpointRef
	VPC           VPCRef
	Cell          string
	Connector     string
	Lifetime      time.Duration
	Routes        []netip.Prefix
	TrafficPolicy *galacticv1alpha1.TrafficPolicyBindingSpec
}

type Issued = authority.Issued

type Grants struct{ grants authority.Grants }

type Ledgers struct{ ledgers authority.Ledgers }

func New(cellClient client.Client, namespace string) Grants {
	return Grants{grants: authority.Grants{Client: cellClient, Namespace: namespace, Now: time.Now}}
}

func NewLedgers(cellClient client.Client, namespace string) Ledgers {
	return Ledgers{ledgers: authority.Ledgers{Client: cellClient, Namespace: namespace, Now: time.Now}}
}

func (grants Grants) Create(ctx context.Context, request CreateRequest) (Issued, error) {
	return grants.grants.Create(ctx, authority.CreateRequest{EndpointRef: request.EndpointRef,
		VPC: authority.VPCRef{Namespace: request.VPC.Namespace, Name: request.VPC.Name}, Cell: request.Cell,
		Connector: request.Connector, Lifetime: request.Lifetime,
		Routes: request.Routes, TrafficPolicy: request.TrafficPolicy})
}

func (grants Grants) Rotate(ctx context.Context, connector string, lifetime time.Duration) (Issued, error) {
	return grants.grants.Rotate(ctx, connector, lifetime)
}

func (grants Grants) Disable(ctx context.Context, connector string) error {
	return grants.grants.Disable(ctx, connector)
}

func (grants Grants) Retire(ctx context.Context, connector string) error {
	return grants.grants.Retire(ctx, connector)
}

func (ledgers Ledgers) Init(ctx context.Context, vpc VPCRef, cell string, connectors, pools netip.Prefix) error {
	return ledgers.ledgers.Init(ctx, authority.VPCRef{Namespace: vpc.Namespace, Name: vpc.Name}, cell, connectors, pools)
}
