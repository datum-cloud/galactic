// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"sigs.k8s.io/yaml"

	"go.datum.net/galactic/internal/edge/connectip"
	"go.datum.net/galactic/internal/edge/masque"
	"go.datum.net/galactic/internal/edge/masque/authority"
)

// Config is the fixture's configuration file.
type Config struct {
	// Provider is the EdgeProvider this pod runs as.
	Provider string `json:"provider"`
	// Authority is the host[:port] clients send as :authority.
	Authority string `json:"authority"`
	// Listen is the UDP address the HTTP/3 server listens on.
	Listen string `json:"listen"`
	// Services are the EdgeServices the pod attaches to, one PacketAccess
	// attachment each.
	Services []Service `json:"services"`
	// Connectors are the CONNECT-IP clients the fixture admits.
	Connectors []Connector `json:"connectors"`
	// GrantAuthority, when set, authorizes requests through a MASQUE grant
	// authority instead of Services and Connectors, which must then be
	// empty.
	GrantAuthority *GrantAuthority `json:"grantAuthority,omitempty"`

	mu sync.Mutex
	// retired holds the IDs of connectors whose grant was retired; the
	// fixture refuses them until it restarts.
	retired map[string]bool
}

// Service is one EdgeService grant. A provider cannot read an EdgeService,
// so the deployer copies its UID, its VPC's UID and its VPC's base62
// identifier from the grant.
type Service struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
	VPCUID    string `json:"vpcUID"`
	VPCID     string `json:"vpcID"`
	// VPC is the Galactic-VPC header value that selects this service.
	VPC string `json:"vpc"`
}

// Connector is one test client: a static bearer credential bound to one
// service and one /96.
type Connector struct {
	// ID is the connector's immutable identity.
	ID string `json:"id"`
	// Credential is the bearer token the client presents. It exists only
	// for this fixture's test connectors.
	Credential string `json:"credential"`
	// Service is the namespace/name of the entry of Services the
	// connector belongs to.
	Service string `json:"service"`
	// Prefix is the connector's /96, inside its service's grant.
	Prefix netip.Prefix `json:"prefix"`
	// Routes are the destinations advertised to the client.
	Routes []netip.Prefix `json:"routes"`
}

// GrantAuthority locates a MASQUE grant authority.
type GrantAuthority struct {
	// URL is the authority's https:// base URL.
	URL string `json:"url"`
	// CAFile holds the roots the authority's certificate chains to.
	CAFile string `json:"caFile"`
	// TokenFile holds the pod's projected ServiceAccount token for the
	// authority's audience.
	TokenFile string `json:"tokenFile"`
}

// Key is how a connector names the service: its namespace and name.
func (s Service) Key() string { return s.Namespace + "/" + s.Name }

// LoadConfig reads and validates the configuration file at path.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, c.Validate()
}

// Validate reports the first invalid field.
func (c *Config) Validate() error {
	if c.Provider == "" || c.Authority == "" || c.Listen == "" {
		return errors.New("provider, authority and listen are required")
	}
	if c.GrantAuthority != nil {
		return c.validateGrantAuthority()
	}
	services := map[string]bool{}
	for _, s := range c.Services {
		if s.Namespace == "" || s.Name == "" || s.UID == "" || s.VPCUID == "" || s.VPCID == "" || s.VPC == "" {
			return fmt.Errorf("service %q: namespace, name, uid, vpcUID, vpcID and vpc are required", s.Name)
		}
		if services[s.Key()] {
			return fmt.Errorf("service %q is listed twice", s.Key())
		}
		services[s.Key()] = true
	}
	ids, creds := map[string]bool{}, map[string]bool{}
	prefixes := map[string]bool{}
	for _, cn := range c.Connectors {
		switch {
		case cn.ID == "" || cn.Credential == "":
			return errors.New("every connector needs an id and a credential")
		case ids[cn.ID] || creds[cn.Credential]:
			return fmt.Errorf("connector %q: id or credential is not unique", cn.ID)
		case !services[cn.Service]:
			return fmt.Errorf("connector %q names unknown service %q", cn.ID, cn.Service)
		case !cn.Prefix.Addr().Is6() || cn.Prefix.Addr().Is4In6() || cn.Prefix.Bits() != 96 ||
			cn.Prefix != cn.Prefix.Masked():
			return fmt.Errorf("connector %q: prefix %s is not a masked IPv6 /96", cn.ID, cn.Prefix)
		case prefixes[cn.Service+"/"+cn.Prefix.String()]:
			return fmt.Errorf("connector %q: prefix %s is already used in service %q", cn.ID, cn.Prefix, cn.Service)
		}
		for _, r := range cn.Routes {
			if !r.IsValid() || r != r.Masked() {
				return fmt.Errorf("connector %q: route %s is not a masked prefix", cn.ID, r)
			}
		}
		ids[cn.ID], creds[cn.Credential] = true, true
		prefixes[cn.Service+"/"+cn.Prefix.String()] = true
	}
	return nil
}

// Authorizer is the fixture's masque.Authorizer: the grant authority when
// one is configured, and the static connectors otherwise.
func (c *Config) Authorizer() masque.Authorizer {
	if g := c.GrantAuthority; g != nil {
		return &authority.Client{URL: g.URL, CAFile: g.CAFile, TokenFile: g.TokenFile}
	}
	return c
}

// validateGrantAuthority reports why the grant authority configuration is
// unusable.
func (c *Config) validateGrantAuthority() error {
	g := c.GrantAuthority
	switch {
	case !strings.HasPrefix(g.URL, "https://") || g.CAFile == "" || g.TokenFile == "":
		return errors.New("grantAuthority needs an https:// url, a caFile and a tokenFile")
	case len(c.Services) > 0 || len(c.Connectors) > 0:
		return errors.New("services and connectors come from the grant authority when it is set")
	}
	return nil
}

// grantTTL is how long a fixture grant authorizes forwarding after each
// request. The fixture's credentials are test credentials with no expiry of
// their own.
const grantTTL = time.Hour

// Authorize implements masque.Authorizer over the configured connectors:
// each is a static bearer credential bound to one service's VPC and one
// /96.
func (c *Config) Authorize(_ context.Context, credential, vpc string) (masque.Grant, error) {
	var found *Connector
	for i := range c.Connectors {
		if subtle.ConstantTimeCompare([]byte(c.Connectors[i].Credential), []byte(credential)) == 1 {
			found = &c.Connectors[i]
		}
	}
	if found == nil {
		return masque.Grant{}, connectip.ErrUnauthenticated
	}
	return c.grant(found, vpc)
}

// grant returns cn's grant for vpc, refusing a retired connector or another
// VPC.
func (c *Config) grant(cn *Connector, vpc string) (masque.Grant, error) {
	c.mu.Lock()
	retired := c.retired[cn.ID]
	c.mu.Unlock()
	if retired {
		return masque.Grant{}, connectip.ErrForbidden
	}
	found := cn
	var svc Service
	for _, s := range c.Services {
		if s.Key() == found.Service {
			svc = s
		}
	}
	if svc.VPC != vpc {
		return masque.Grant{}, connectip.ErrForbidden
	}
	return masque.Grant{
		Connector: found.ID, Principal: found.ID, VPC: svc.VPC, VPCUID: svc.VPCUID, VPCID: svc.VPCID,
		Service: masque.ServiceRef{Namespace: svc.Namespace, Name: svc.Name, UID: svc.UID},
		Prefix:  found.Prefix, Routes: found.Routes, NotAfter: time.Now().Add(grantTTL),
	}, nil
}

// Refresh implements masque.Authorizer: it renews g for another grantTTL
// while its connector is configured unchanged and not retired.
func (c *Config) Refresh(_ context.Context, g masque.Grant) (masque.Grant, error) {
	for i := range c.Connectors {
		if c.Connectors[i].ID == g.Connector {
			return c.grant(&c.Connectors[i], g.VPC)
		}
	}
	return masque.Grant{}, connectip.ErrForbidden
}

// Retire implements masque.Authorizer: the connector is refused from now
// on.
func (c *Config) Retire(_ context.Context, g masque.Grant) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.retired == nil {
		c.retired = map[string]bool{}
	}
	c.retired[g.Connector] = true
	return nil
}
