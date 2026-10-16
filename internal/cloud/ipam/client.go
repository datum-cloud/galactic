/*
Copyright © 2026 Datum Technology, Inc. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Package ipam reaches the platform's address management service.
//
// Every request names the tenancy it is made for, so nothing can allocate
// without saying on whose behalf. Two tenancies exist: a consumer's own
// project, and the platform itself.
package ipam

import (
	"errors"
	"fmt"
	"net/url"
	"sync"

	ipamv1alpha1 "go.miloapis.com/ipam/pkg/apis/ipam/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// resourceManagerGroup is the API group whose project path addresses one
// project's control plane. It is a constant rather than an import so that
// reaching IPAM does not pull the whole resource manager API surface in for the
// sake of one string.
const resourceManagerGroup = "resourcemanager.miloapis.com"

// ClientFactory returns a client bound to one tenancy.
type ClientFactory interface {
	// ClientForProject reaches IPAM on a consumer's behalf, inside their own
	// project. What it allocates is theirs, counts against their quota, and is
	// unique only among their own allocations.
	ClientForProject(project string) (client.Client, error)

	// ClientForPlatform reaches IPAM on the platform's own behalf, for values
	// that must be unique across every consumer and must not be gated on one
	// enabling the address service or draw on their quota.
	//
	// A network's fabric identity is the case this exists for: uniqueness per
	// project is not uniqueness, and a consumer never asked for the value and
	// cannot see it.
	//
	// IPAM has no platform tenancy of its own, so today this is one project
	// control plane the platform owns. The seam is here so that when it gains
	// one, nothing above this line changes.
	ClientForPlatform() (client.Client, error)
}

// NewClientFactory builds tenancy-scoped clients from one connection. The
// clients are uncached, because a cache would watch every project served.
//
// platformProject names the control plane platform-owned allocations are made
// in. Empty means the deployment allocates nothing platform-scoped.
func NewClientFactory(base *rest.Config, scheme *runtime.Scheme, platformProject string) (ClientFactory, error) {
	if base == nil {
		return nil, errors.New("a rest config is required")
	}
	return &projectPathClientFactory{
		base:            base,
		scheme:          scheme,
		platformProject: platformProject,
		clients:         map[string]client.Client{},
	}, nil
}

type projectPathClientFactory struct {
	base            *rest.Config
	scheme          *runtime.Scheme
	platformProject string

	mu      sync.Mutex
	clients map[string]client.Client
}

func (f *projectPathClientFactory) ClientForPlatform() (client.Client, error) {
	if f.platformProject == "" {
		return nil, ErrNoPlatformTenancy
	}
	return f.ClientForProject(f.platformProject)
}

func (f *projectPathClientFactory) ClientForProject(project string) (client.Client, error) {
	if project == "" {
		return nil, ErrNoProject
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if existing, ok := f.clients[project]; ok {
		return existing, nil
	}

	cfg, err := f.configForProject(project)
	if err != nil {
		return nil, err
	}

	cl, err := client.New(cfg, client.Options{Scheme: f.scheme})
	if err != nil {
		return nil, fmt.Errorf("build IPAM client for project %q: %w", project, err)
	}

	f.clients[project] = cl
	return cl, nil
}

// configForProject addresses the base connection at one project's control
// plane. The path names the project, so the platform authorizes this
// operator's own identity against that project rather than trusting a
// caller-supplied parent. Any path the base host already carries is replaced,
// not extended.
func (f *projectPathClientFactory) configForProject(project string) (*rest.Config, error) {
	cfg := rest.CopyConfig(f.base)

	host, err := url.Parse(cfg.Host)
	if err != nil {
		return nil, fmt.Errorf("parse IPAM host %q: %w", cfg.Host, err)
	}
	host.Path = fmt.Sprintf("/apis/%s/v1alpha1/projects/%s/control-plane", resourceManagerGroup, project)
	cfg.Host = host.String()

	return cfg, nil
}

// Scheme is the scheme a tenancy-scoped IPAM client is built with.
func Scheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := ipamv1alpha1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	return scheme, nil
}

// ErrNoProject says a request named no project, which is never a default.
var ErrNoProject = errors.New("no project")

// ErrNoPlatformTenancy says the deployment named no place for the platform to
// allocate what it owns, so it allocates none of it.
var ErrNoPlatformTenancy = errors.New("no platform tenancy is configured")
