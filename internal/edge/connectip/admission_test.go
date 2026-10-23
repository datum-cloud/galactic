// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// testAdmission is a process-local fixture, not a production claim authority.
// It deliberately permits the same prefix in different gVPCs.
type testAdmission struct {
	mu     sync.Mutex
	next   uint64
	leases map[string]map[netip.Prefix]*testLease
}

func newTestAdmission() *testAdmission {
	return &testAdmission{leases: make(map[string]map[netip.Prefix]*testLease)}
}

func (a *testAdmission) Admit(_ context.Context, token, vpc string) (Lease, error) {
	principal := ""
	switch token {
	case tokenAlice:
		principal = principalAlice
	case tokenBob:
		principal = "bob"
	default:
		return nil, ErrUnauthenticated
	}
	if vpc != vpcGreen && (vpc != vpcBlue || principal != principalAlice) {
		return nil, ErrForbidden
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.leases[vpc] == nil {
		a.leases[vpc] = make(map[netip.Prefix]*testLease)
	}
	for i := 1; i < 65536; i++ {
		prefix := netip.MustParsePrefix(fmt.Sprintf("fd00:a::%x:0:0/96", i))
		if _, exists := a.leases[vpc][prefix]; exists {
			continue
		}
		a.next++
		lease := &testLease{
			authority: a, done: make(chan struct{}),
			info: SessionInfo{ID: a.next, Principal: principal, VPC: vpc, Prefix: prefix,
				Connector: fmt.Sprintf("connector-%d", a.next), Attachment: "attachment-" + vpc,
				Claim: fmt.Sprintf("claim-%d", a.next), Epoch: 1},
		}
		a.leases[vpc][prefix] = lease
		return lease, nil
	}
	return nil, errors.New("test prefix pool exhausted")
}

// waitReleased waits until the lease for info's prefix in its gVPC is
// released.
func (a *testAdmission) waitReleased(t *testing.T, info SessionInfo) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		_, held := a.leases[info.VPC][info.Prefix]
		a.mu.Unlock()
		if !held {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("lease %s in %s was not released", info.Prefix, info.VPC)
}

type testLease struct {
	authority *testAdmission
	info      SessionInfo
	done      chan struct{}
	once      sync.Once
}

func (l *testLease) Info() SessionInfo     { return l.info }
func (*testLease) Routes() []netip.Prefix  { return []netip.Prefix{testRoute} }
func (l *testLease) Done() <-chan struct{} { return l.done }
func (l *testLease) Close() error {
	l.once.Do(func() {
		close(l.done)
		l.authority.mu.Lock()
		defer l.authority.mu.Unlock()
		if l.authority.leases[l.info.VPC][l.info.Prefix] == l {
			delete(l.authority.leases[l.info.VPC], l.info.Prefix)
		}
	})
	return nil
}

func TestDelegatedPrefixSubdivisions(t *testing.T) {
	env := startServer(t, nil)
	cc := newClientConn(t, env.dialQUIC(t))
	s := open(t, cc, env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	for i, addr := range []string{"fd00:a::1:0:1", "fd00:a::1:1234:5678", "fd00:a::1:ffff:ffff"} {
		s.address = netip.MustParseAddr(addr)
		reply := ping(t, s, 100+i, 256)
		if reply.dst != s.address {
			t.Fatalf("return destination = %s, want %s", reply.dst, s.address)
		}
	}
	other := open(t, cc, env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	if firstPrefix.Contains(other.address) {
		t.Fatal("two active requests received overlapping grants")
	}
	ping(t, other, 200, 256)
}

func TestLeaseRevocationEndsSession(t *testing.T) {
	authority := newTestAdmission()
	env := startServer(t, func(c *Config) { c.Admission = authority })
	s := open(t, newClientConn(t, env.dialQUIC(t)), env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	backend := env.backend.nextOpened(t)
	ping(t, s, 201, 256)
	authority.mu.Lock()
	lease := authority.leases[vpcBlue][firstPrefix]
	authority.mu.Unlock()
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	backend.waitClosed(t)
}

type admissionFunc func(context.Context, string, string) (Lease, error)

func (f admissionFunc) Admit(ctx context.Context, token, vpc string) (Lease, error) {
	return f(ctx, token, vpc)
}

type alteredLease struct {
	Lease
	info SessionInfo
}

func (l alteredLease) Info() SessionInfo { return l.info }

func TestInvalidGrantsReleaseWithoutOpeningBackend(t *testing.T) {
	tests := []struct {
		name  string
		alter func(*SessionInfo)
	}{
		{"WrongVPC", func(i *SessionInfo) { i.VPC = vpcGreen }},
		{"SingleAddress", func(i *SessionInfo) { i.Prefix = netip.PrefixFrom(firstClient, 128) }},
		{"HostBits", func(i *SessionInfo) { i.Prefix = netip.PrefixFrom(firstClient, 96) }},
		{"MissingClaim", func(i *SessionInfo) { i.Claim = "" }},
		{"MissingAttachment", func(i *SessionInfo) { i.Attachment = "" }},
		{"MissingConnector", func(i *SessionInfo) { i.Connector = "" }},
		{"MissingEpoch", func(i *SessionInfo) { i.Epoch = 0 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authority := newTestAdmission()
			env := startServer(t, func(c *Config) {
				c.Admission = admissionFunc(func(ctx context.Context, token, vpc string) (Lease, error) {
					l, err := authority.Admit(ctx, token, vpc)
					if err != nil {
						return nil, err
					}
					info := l.Info()
					tt.alter(&info)
					return alteredLease{Lease: l, info: info}, nil
				})
			})
			cc := newClientConn(t, env.dialQUIC(t))
			conn, rsp, err := cc.Dial(env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
			if err == nil {
				_ = conn.Close()
				t.Fatal("invalid grant accepted")
			}
			if rsp == nil || rsp.StatusCode != 503 {
				t.Fatalf("response = %v, %v", rsp, err)
			}
			if len(env.backend.all()) != 0 {
				t.Fatal("opened backend for invalid grant")
			}
			authority.mu.Lock()
			defer authority.mu.Unlock()
			if len(authority.leases[vpcBlue]) != 0 {
				t.Fatal("rejected grant leaked its lease")
			}
		})
	}
}

type failingBackend struct{}

func (failingBackend) Open(context.Context, SessionInfo) (BackendSession, error) {
	return nil, errors.New("attachment unavailable")
}

func TestBackendSetupFailureReleasesLease(t *testing.T) {
	authority := newTestAdmission()
	env := startServer(t, func(c *Config) { c.Admission = authority; c.Backend = failingBackend{} })
	cc := newClientConn(t, env.dialQUIC(t))
	conn, rsp, err := cc.Dial(env.newRequest(t, authHeaders(tokenAlice, vpcBlue)))
	if err == nil {
		_ = conn.Close()
		t.Fatal("unavailable backend accepted")
	}
	if rsp == nil || rsp.StatusCode != 503 {
		t.Fatalf("response = %v, %v", rsp, err)
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if len(authority.leases[vpcBlue]) != 0 {
		t.Fatal("failed setup leaked its prefix claim")
	}
}
