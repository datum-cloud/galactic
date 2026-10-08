// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package identity names fabric-api's mTLS identities and authorizes them.
//
// Every certificate carries exactly one URI SAN in the fabric-api trust
// domain:
//
//	spiffe://fabric-api.datumapis.com/cell/<cell>/gateway
//	spiffe://fabric-api.datumapis.com/cell/<cell>/ns/<namespace>/pod/<pod>
//	spiffe://fabric-api.datumapis.com/cell/<cell>/operator/<name>
//
// The first is the cell gateway's client identity. The second is a node
// sidecar's server identity: it names the pod rather than the node because
// cert-manager's csi-driver can template a pod's name but not its node's, and
// the gateway binds pod to node through the API when it snapshots the cell's
// fabric-router pods. The third is an operator debug client. The trust
// bundle is per cell, so the cell segment is checked as well as the chain.
package identity

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// TrustDomain is the SPIFFE trust domain of every fabric-api identity.
const TrustDomain = "fabric-api.datumapis.com"

// Role is what an identity is allowed to be.
type Role string

// Roles.
const (
	RoleGateway  Role = "gateway"
	RoleNode     Role = "node"
	RoleOperator Role = "operator"
)

// ID is a parsed fabric-api identity.
type ID struct {
	Cell string
	Role Role
	// Namespace and Name are the pod for RoleNode; Name is the operator for
	// RoleOperator; both are empty for RoleGateway.
	Namespace string
	Name      string
}

// segment is a DNS-label-like path segment.
var segment = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// Gateway returns cell's gateway identity.
func Gateway(cell string) ID { return ID{Cell: cell, Role: RoleGateway} }

// Node returns the identity of the sidecar in pod namespace/name of cell.
func Node(cell, namespace, pod string) ID {
	return ID{Cell: cell, Role: RoleNode, Namespace: namespace, Name: pod}
}

// Operator returns an operator identity in cell.
func Operator(cell, name string) ID { return ID{Cell: cell, Role: RoleOperator, Name: name} }

// URI renders the identity as its URI SAN.
func (id ID) URI() string {
	base := "spiffe://" + TrustDomain + "/cell/" + id.Cell
	switch id.Role {
	case RoleGateway:
		return base + "/gateway"
	case RoleNode:
		return base + "/ns/" + id.Namespace + "/pod/" + id.Name
	case RoleOperator:
		return base + "/operator/" + id.Name
	}
	return base
}

func (id ID) String() string { return id.URI() }

// Parse parses a fabric-api URI SAN.
func Parse(s string) (ID, error) {
	u, err := url.Parse(s)
	if err != nil {
		return ID{}, err
	}
	if u.Scheme != "spiffe" || u.Host != TrustDomain || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return ID{}, fmt.Errorf("%q is not a %s identity", s, TrustDomain)
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	for _, p := range parts {
		if !segment.MatchString(p) {
			return ID{}, fmt.Errorf("%q has an invalid path segment %q", s, p)
		}
	}
	if len(parts) < 3 || parts[0] != "cell" {
		return ID{}, fmt.Errorf("%q has no cell", s)
	}
	id := ID{Cell: parts[1]}
	switch rest := parts[2:]; {
	case len(rest) == 1 && rest[0] == string(RoleGateway):
		id.Role = RoleGateway
	case len(rest) == 4 && rest[0] == "ns" && rest[2] == "pod":
		id.Role, id.Namespace, id.Name = RoleNode, rest[1], rest[3]
	case len(rest) == 2 && rest[0] == string(RoleOperator):
		id.Role, id.Name = RoleOperator, rest[1]
	default:
		return ID{}, fmt.Errorf("%q is not a gateway, node or operator identity", s)
	}
	return id, nil
}

// FromCertificate returns the single fabric-api identity in cert's URI SANs.
func FromCertificate(cert *x509.Certificate) (ID, error) {
	var found []ID
	for _, u := range cert.URIs {
		if u.Scheme != "spiffe" || u.Host != TrustDomain {
			continue
		}
		id, err := Parse(u.String())
		if err != nil {
			return ID{}, err
		}
		found = append(found, id)
	}
	if len(found) != 1 {
		return ID{}, fmt.Errorf("certificate has %d %s identities, want 1", len(found), TrustDomain)
	}
	return found[0], nil
}
