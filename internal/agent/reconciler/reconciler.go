// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package reconciler is the agent's central event loop. It owns the
// in-memory state described in PLAN-bgp-cutover.md and translates
// CNI Register/Deregister events, VPCAttachment cache events, and
// inbound BGP UPDATEs into BGP origination calls and kernel route
// installations.
package reconciler

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	agentbgp "go.datum.net/galactic/internal/agent/bgp"
	agentcache "go.datum.net/galactic/internal/agent/cache"
	"go.datum.net/galactic/pkg/common/util"
)

// BGPClient is the surface the reconciler uses against the BGP server.
// Defined as an interface so unit tests can stand in a fake.
type BGPClient interface {
	Originate(ctx context.Context, key agentbgp.PathKey, prefix *net.IPNet, rd, rt string, nextHop, serviceSID net.IP) error
	Withdraw(ctx context.Context, key agentbgp.PathKey) error
}

// EgressProgrammer installs and removes kernel egress routes. The real
// implementation is internal/agent/program. Interface for testability.
type EgressProgrammer interface {
	Add(vpcHex, attachHex string, prefix *net.IPNet, segments []net.IP) error
	Delete(vpcHex, attachHex string, prefix *net.IPNet) error
}

// IngressProgrammer installs and removes the END.DT46 decap entry for
// a service SID. Interface; the real implementation calls into
// internal/agent/srv6/routeingress with the explicit hex→base62
// conversion.
type IngressProgrammer interface {
	Add(serviceSID *net.IPNet, vpcB62, attachB62 string) error
	Delete(serviceSID *net.IPNet, vpcB62, attachB62 string) error
}

// AttachmentLookup is the cache surface the reconciler uses.
type AttachmentLookup interface {
	Lookup(vpcHex, attachHex string) (agentcache.AttachmentInfo, bool)
	FindByRT(rt string) []agentcache.AttachmentInfo
}

// Config holds reconciler dependencies.
type Config struct {
	BGP       BGPClient
	Egress    EgressProgrammer
	Ingress   IngressProgrammer
	Cache     AttachmentLookup
	NodeNext  net.IP        // BGP next-hop for paths this agent originates
	StalledAt time.Duration // emit BGPOriginationStalled after this long in pending; 0 disables
}

// Reconciler is the event loop. Construct with New and drive via the
// Push* methods plus AttachmentEvents/ReceiveEvents/SessionEvents
// channels.
type Reconciler struct {
	cfg Config

	mu               sync.Mutex
	pending          map[attachKey]pendingRegister
	active           map[originationKey]activeOrigination
	ingress          map[attachKey]net.IP // attachKey -> serviceSID
	receivedRoutes   map[receivedKey]receivedRoute
	programmedKernel map[attachKey]map[string]struct{} // inner key = prefix.String()
}

type attachKey struct{ vpcHex, attachHex string }
type originationKey struct {
	vpcHex, attachHex string
	prefix            string
}
type receivedKey struct{ prefix, rd string }

type pendingRegister struct{ receivedAt time.Time }

type activeOrigination struct {
	prefix     *net.IPNet
	rd         string
	rt         string
	nextHop    net.IP
	serviceSID net.IP
}

type receivedRoute struct {
	rts        []string
	nextHop    net.IP
	serviceSID net.IP
}

// New constructs a Reconciler with the given config.
func New(cfg Config) *Reconciler {
	return &Reconciler{
		cfg:              cfg,
		pending:          map[attachKey]pendingRegister{},
		active:           map[originationKey]activeOrigination{},
		ingress:          map[attachKey]net.IP{},
		receivedRoutes:   map[receivedKey]receivedRoute{},
		programmedKernel: map[attachKey]map[string]struct{}{},
	}
}

// Run drains the cache, BGP receive, and BGP session-state channels
// until ctx is canceled. CNI register/deregister are pushed via the
// OnRegister/OnDeregister methods directly.
func (r *Reconciler) Run(
	ctx context.Context,
	cacheEvents <-chan agentcache.Event,
	receiveEvents <-chan agentbgp.ReceivedRoute,
	sessionEvents <-chan agentbgp.SessionEvent,
) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev := <-cacheEvents:
			r.handleAttachmentEvent(ctx, ev)
		case ev := <-receiveEvents:
			r.handleReceivedRoute(ctx, ev)
		case ev := <-sessionEvents:
			r.handleSession(ctx, ev)
		}
	}
}

// OnRegister handles a CNI Register call. The reconciler does not
// store pod prefixes here — they come from the cache at originate
// time. (See PLAN-bgp-cutover.md "Prefix sourcing.")
func (r *Reconciler) OnRegister(ctx context.Context, vpcHex, attachHex string) {
	key := attachKey{vpcHex, attachHex}

	r.mu.Lock()
	r.pending[key] = pendingRegister{receivedAt: time.Now()}
	r.mu.Unlock()

	r.tryOriginate(ctx, key)
}

// OnDeregister tears down all reconciler state for the attachment.
func (r *Reconciler) OnDeregister(ctx context.Context, vpcHex, attachHex string) {
	key := attachKey{vpcHex, attachHex}

	r.mu.Lock()
	delete(r.pending, key)

	// Withdraw originated paths.
	for k, v := range r.active {
		if k.vpcHex == vpcHex && k.attachHex == attachHex {
			_ = r.cfg.BGP.Withdraw(ctx, agentbgp.PathKey{
				VPCHex: k.vpcHex, AttachHex: k.attachHex, Prefix: k.prefix,
			})
			delete(r.active, k)
			_ = v
		}
	}

	// Remove ingress decap. SID is sourced from r.ingress, not the
	// cache — the cache may already have processed the delete.
	if sid, found := r.ingress[key]; found {
		vpcB62, errVPC := util.HexToBase62(vpcHex)
		attachB62, errAttach := util.HexToBase62(attachHex)
		if errVPC != nil || errAttach != nil {
			log.Printf("reconciler: hex->base62 failed for %v during deregister: vpc=%v attach=%v", key, errVPC, errAttach)
		} else if err := r.cfg.Ingress.Delete(netSIDNetwork(sid), vpcB62, attachB62); err != nil {
			log.Printf("reconciler: routeingress.Delete: %v", err)
		}
		delete(r.ingress, key)
	}

	// Tear down kernel egress routes.
	if prefixes, found := r.programmedKernel[key]; found {
		for prefixStr := range prefixes {
			if err := r.cfg.Egress.Delete(vpcHex, attachHex, mustParseCIDR(prefixStr)); err != nil {
				log.Printf("reconciler: egress.Delete %s: %v", prefixStr, err)
			}
		}
		delete(r.programmedKernel, key)
	}
	r.mu.Unlock()
}

func (r *Reconciler) handleAttachmentEvent(ctx context.Context, ev agentcache.Event) {
	info := ev.Current
	key := attachKey{info.VPCHex, info.AttachHex}

	if ev.Type != agentcache.EventDelete && info.Ready {
		r.tryOriginate(ctx, key)
		r.replayReceivedFor(info.RouteTarget, info)
		return
	}

	// Status went away (delete or not-ready). Tear down origination
	// and ingress; keep pending in place. programmedKernel is driven
	// by local bookkeeping, not by the cache — see plan.
	r.mu.Lock()
	for k := range r.active {
		if k.vpcHex == info.VPCHex && k.attachHex == info.AttachHex {
			_ = r.cfg.BGP.Withdraw(ctx, agentbgp.PathKey{
				VPCHex: k.vpcHex, AttachHex: k.attachHex, Prefix: k.prefix,
			})
			delete(r.active, k)
		}
	}
	if sid, found := r.ingress[key]; found {
		vpcB62, errVPC := util.HexToBase62(info.VPCHex)
		attachB62, errAttach := util.HexToBase62(info.AttachHex)
		if errVPC == nil && errAttach == nil {
			if err := r.cfg.Ingress.Delete(netSIDNetwork(sid), vpcB62, attachB62); err != nil {
				log.Printf("reconciler: routeingress.Delete on status loss: %v", err)
			}
		}
		delete(r.ingress, key)
	}
	if prefixes, found := r.programmedKernel[key]; found {
		for prefixStr := range prefixes {
			if err := r.cfg.Egress.Delete(info.VPCHex, info.AttachHex, mustParseCIDR(prefixStr)); err != nil {
				log.Printf("reconciler: egress.Delete on status loss %s: %v", prefixStr, err)
			}
		}
		delete(r.programmedKernel, key)
	}
	r.mu.Unlock()
}

func (r *Reconciler) handleReceivedRoute(_ context.Context, ev agentbgp.ReceivedRoute) {
	rk := receivedKey{prefix: ev.Prefix.String(), rd: ev.RouteDistinguisher}

	r.mu.Lock()
	if ev.IsWithdraw {
		delete(r.receivedRoutes, rk)
	} else {
		r.receivedRoutes[rk] = receivedRoute{
			rts:        append([]string(nil), ev.RouteTargets...),
			nextHop:    ev.NextHop,
			serviceSID: ev.ServiceSID,
		}
	}
	r.mu.Unlock()

	for _, rt := range ev.RouteTargets {
		matches := r.cfg.Cache.FindByRT(rt)
		for _, info := range matches {
			if !info.Ready {
				continue
			}
			key := attachKey{info.VPCHex, info.AttachHex}
			if ev.IsWithdraw {
				if err := r.cfg.Egress.Delete(info.VPCHex, info.AttachHex, ev.Prefix); err != nil {
					log.Printf("reconciler: egress.Delete: %v", err)
				}
				r.mu.Lock()
				if set, ok := r.programmedKernel[key]; ok {
					delete(set, ev.Prefix.String())
				}
				r.mu.Unlock()
			} else {
				if err := r.cfg.Egress.Add(info.VPCHex, info.AttachHex, ev.Prefix, []net.IP{ev.ServiceSID}); err != nil {
					log.Printf("reconciler: egress.Add: %v", err)
					continue
				}
				r.mu.Lock()
				if r.programmedKernel[key] == nil {
					r.programmedKernel[key] = map[string]struct{}{}
				}
				r.programmedKernel[key][ev.Prefix.String()] = struct{}{}
				r.mu.Unlock()
			}
		}
	}
}

func (r *Reconciler) handleSession(ctx context.Context, ev agentbgp.SessionEvent) {
	if ev.State != agentbgp.SessionStateEstablished {
		return
	}
	// Replay all active originations. The BGP layer rebuilds the UUID
	// map; we just walk our local snapshot and re-call Originate.
	r.mu.Lock()
	snapshot := make(map[originationKey]activeOrigination, len(r.active))
	for k, v := range r.active {
		snapshot[k] = v
	}
	r.mu.Unlock()

	for k, v := range snapshot {
		if err := r.cfg.BGP.Originate(
			ctx,
			agentbgp.PathKey{VPCHex: k.vpcHex, AttachHex: k.attachHex, Prefix: k.prefix},
			v.prefix, v.rd, v.rt, v.nextHop, v.serviceSID,
		); err != nil {
			log.Printf("reconciler: re-originate %v on session-up: %v", k, err)
		}
	}
}

// tryOriginate is the convergence point: succeeds iff pending[key] is
// set AND the cache has a ready attachment with non-empty SID/RT/RD.
// On success it installs ingress decap and originates one BGP path
// per pod prefix.
func (r *Reconciler) tryOriginate(ctx context.Context, key attachKey) {
	r.mu.Lock()
	_, isPending := r.pending[key]
	r.mu.Unlock()
	if !isPending {
		return
	}
	info, ok := r.cfg.Cache.Lookup(key.vpcHex, key.attachHex)
	if !ok || !info.Ready {
		return // wait for the next informer event
	}

	vpcB62, err := util.HexToBase62(info.VPCHex)
	if err != nil {
		log.Printf("reconciler: HexToBase62 vpc %q: %v", info.VPCHex, err)
		return
	}
	attachB62, err := util.HexToBase62(info.AttachHex)
	if err != nil {
		log.Printf("reconciler: HexToBase62 attach %q: %v", info.AttachHex, err)
		return
	}

	sid := net.ParseIP(info.ServiceSID)
	if sid == nil {
		log.Printf("reconciler: ServiceSID %q parse failed for %v", info.ServiceSID, key)
		return
	}

	// Idempotent ingress install.
	r.mu.Lock()
	_, ingressInstalled := r.ingress[key]
	r.mu.Unlock()
	if !ingressInstalled {
		if err := r.cfg.Ingress.Add(netSIDNetwork(sid), vpcB62, attachB62); err != nil {
			log.Printf("reconciler: routeingress.Add: %v", err)
			return
		}
		r.mu.Lock()
		r.ingress[key] = sid
		r.mu.Unlock()
	}

	// Originate one path per pod prefix.
	for _, prefixStr := range info.PodPrefixes {
		prefix := mustParseCIDR(podPrefixToHostMask(prefixStr))
		oKey := originationKey{vpcHex: key.vpcHex, attachHex: key.attachHex, prefix: prefix.String()}

		r.mu.Lock()
		_, alreadyActive := r.active[oKey]
		r.mu.Unlock()
		if alreadyActive {
			continue
		}

		err := r.cfg.BGP.Originate(ctx,
			agentbgp.PathKey{VPCHex: key.vpcHex, AttachHex: key.attachHex, Prefix: prefix.String()},
			prefix, info.RouteDistinguisher, info.RouteTarget, r.cfg.NodeNext, sid,
		)
		if err != nil {
			log.Printf("reconciler: bgp.Originate: %v", err)
			continue
		}
		r.mu.Lock()
		r.active[oKey] = activeOrigination{
			prefix:     prefix,
			rd:         info.RouteDistinguisher,
			rt:         info.RouteTarget,
			nextHop:    r.cfg.NodeNext,
			serviceSID: sid,
		}
		r.mu.Unlock()
	}
}

// replayReceivedFor walks receivedRoutes for entries whose RT list
// contains rt and which are NOT already in programmedKernel for this
// attachment, then programs them. Used by the catch-up path when a
// local attachment's status fills in after a remote BGP UPDATE
// already arrived.
func (r *Reconciler) replayReceivedFor(rt string, info agentcache.AttachmentInfo) {
	if rt == "" || !info.Ready {
		return
	}
	key := attachKey{info.VPCHex, info.AttachHex}

	r.mu.Lock()
	candidates := make([]struct {
		prefixStr  string
		serviceSID net.IP
	}, 0)
	for rk, rr := range r.receivedRoutes {
		hit := false
		for _, candRT := range rr.rts {
			if candRT == rt {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		if set, ok := r.programmedKernel[key]; ok {
			if _, already := set[rk.prefix]; already {
				continue
			}
		}
		candidates = append(candidates, struct {
			prefixStr  string
			serviceSID net.IP
		}{rk.prefix, rr.serviceSID})
	}
	r.mu.Unlock()

	for _, c := range candidates {
		prefix := mustParseCIDR(c.prefixStr)
		if err := r.cfg.Egress.Add(info.VPCHex, info.AttachHex, prefix, []net.IP{c.serviceSID}); err != nil {
			log.Printf("reconciler: replay egress.Add: %v", err)
			continue
		}
		r.mu.Lock()
		if r.programmedKernel[key] == nil {
			r.programmedKernel[key] = map[string]struct{}{}
		}
		r.programmedKernel[key][c.prefixStr] = struct{}{}
		r.mu.Unlock()
	}
}

// PendingCount returns len(pending). Exposed for the metrics gauge.
func (r *Reconciler) PendingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

// ActiveCount returns len(active). Exposed for the metrics gauge.
func (r *Reconciler) ActiveCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.active)
}

// ReceivedCount returns the number of remote VPN paths in the inbound
// cache. Exposed for the metrics gauge.
func (r *Reconciler) ReceivedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.receivedRoutes)
}

// ProgrammedKernelCount returns the total number of (attachment,
// prefix) pairs installed in local VRFs. Exposed for the metrics gauge.
func (r *Reconciler) ProgrammedKernelCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, set := range r.programmedKernel {
		n += len(set)
	}
	return n
}

// netSIDNetwork wraps a single IPv6 address as a /128 IPNet — the form
// routeingress.Add expects.
func netSIDNetwork(ip net.IP) *net.IPNet {
	return &net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}
}

// podPrefixToHostMask converts a Spec.Interface.Addresses entry like
// "10.0.0.5/24" into the /32 host route ("10.0.0.5/32") that BGP
// advertises. The underlay subnet mask is irrelevant — what matters is
// reaching the specific pod IP.
func podPrefixToHostMask(s string) string {
	ip, _, err := net.ParseCIDR(s)
	if err != nil {
		// Tolerate bare addresses too.
		ip = net.ParseIP(s)
		if ip == nil {
			return s
		}
	}
	if ip.To4() != nil {
		return fmt.Sprintf("%s/32", ip.String())
	}
	return fmt.Sprintf("%s/128", ip.String())
}

func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		// Caller-controlled inputs that have already been parsed
		// elsewhere; return a valid empty net to avoid a panic in
		// production. The error path is logged at the caller.
		return &net.IPNet{}
	}
	return n
}
