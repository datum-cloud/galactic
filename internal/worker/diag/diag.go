// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package diag is galactic-worker's operator view of a node: what each
// capability, VPC scope, claim and destination is doing and why. Worker
// writes a Snapshot to a root-only file under its state directory after
// state changes, and `galactic-worker inspect` prints it, joined with the
// live ownership fence, so an operator sees it without a client identity and
// without a network port.
package diag

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"go.datum.net/galactic/internal/ownership"
)

// DefaultPath is where Worker writes the snapshot. It is not under the
// socket directory, which clients mount.
const DefaultPath = "/var/lib/galactic-worker/status.json"

// Snapshot is Worker's view of the node at one time.
type Snapshot struct {
	Time time.Time `json:"time"`
	Node string    `json:"node"`
	// Owner is the fence owner ID of the Worker incarnation that wrote it.
	Owner        string       `json:"owner"`
	Capabilities []Capability `json:"capabilities"`
	Scopes       []Scope      `json:"scopes"`
}

// Capability is one capability's readiness.
type Capability struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Message   string `json:"message,omitempty"`
}

// Scope is one VPC scope.
type Scope struct {
	VPC string `json:"vpc"`
	// Fence is the scope's ownership record when the snapshot was written.
	// inspect replaces it with the live record.
	Fence ownership.Record `json:"fence"`
	// Resyncing is set from Worker's start until the scope's first snapshot
	// commit; Repair after a failed commit until one succeeds.
	Resyncing bool `json:"resyncing,omitempty"`
	Repair    bool `json:"repair,omitempty"`
	// LastDrift is the last time Worker found and repaired host state that
	// changed under it in this scope.
	LastDrift *Drift  `json:"lastDrift,omitempty"`
	Claims    []Claim `json:"claims,omitempty"`
}

// Drift is one repair of host state that changed under Worker.
type Drift struct {
	Time   time.Time `json:"time"`
	Module string    `json:"module"`
	// Detail names the first difference the module found.
	Detail string `json:"detail"`
}

// Claim is one claim's status.
type Claim struct {
	// Key is node/VPC/attachment UID.
	Key string `json:"key"`
	// Owner is the ServiceAccount that holds the claim.
	Owner              string      `json:"owner"`
	Handoff            string      `json:"handoff"`
	Generation         uint64      `json:"generation"`
	ObservedGeneration uint64      `json:"observedGeneration"`
	Conditions         []Condition `json:"conditions,omitempty"`
	// Withdrawal names what is being removed while the claim withdraws.
	Withdrawal        string        `json:"withdrawal,omitempty"`
	Destinations      []Destination `json:"destinations,omitempty"`
	HandoffInterfaces []string      `json:"handoffInterfaces,omitempty"`
}

// Condition is one claim condition.
type Condition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// Destination is one destination's status.
type Destination struct {
	ID string `json:"id"`
	// Locality is local or fabric once resolved, the module that delivers
	// it.
	Locality     string `json:"locality,omitempty"`
	Capability   string `json:"capability,omitempty"`
	Resolved     bool   `json:"resolved"`
	Programmed   bool   `json:"programmed"`
	Ready        bool   `json:"ready"`
	ForwardReady bool   `json:"forwardReady"`
	ReturnReady  bool   `json:"returnReady"`
	Reason       string `json:"reason,omitempty"`
	Message      string `json:"message,omitempty"`
}

// Write writes s to path atomically, readable only by its owner.
func Write(path string, s Snapshot) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".status-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Read reads a snapshot.
func Read(path string) (Snapshot, error) {
	var s Snapshot
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("diag: decode %s: %w", path, err)
	}
	return s, nil
}

// Join returns s with each scope's fence record replaced by fence's live
// one, and with every scope the fence holds that s lacks, such as one a
// handback left or another writer owns.
func Join(s Snapshot, fence *ownership.Authority) (Snapshot, error) {
	if fence == nil {
		return s, nil
	}
	names, err := fence.Scopes()
	if err != nil {
		return s, err
	}
	byVPC := map[string]int{}
	for i, sc := range s.Scopes {
		byVPC[sc.VPC] = i
	}
	var errs []error
	for _, name := range names {
		vpc, ok := strings.CutPrefix(name, "vpc-")
		if !ok {
			continue
		}
		rec, err := fence.Peek(name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if i, ok := byVPC[vpc]; ok {
			s.Scopes[i].Fence = rec
			continue
		}
		s.Scopes = append(s.Scopes, Scope{VPC: vpc, Fence: rec})
	}
	slices.SortFunc(s.Scopes, func(a, b Scope) int { return strings.Compare(a.VPC, b.VPC) })
	return s, errors.Join(errs...)
}

// Print writes s for an operator. now dates the snapshot.
func Print(w io.Writer, s Snapshot, now time.Time) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	p := &printer{w: tw}
	if s.Time.IsZero() {
		p.f("No Worker status snapshot: Worker is not running, or has not written one yet.\n")
	} else {
		p.f("Node %s, Worker %s, status written %s ago\n", s.Node, s.Owner,
			now.Sub(s.Time).Round(time.Second))
	}
	if len(s.Capabilities) > 0 {
		p.f("\nCAPABILITY\tAVAILABLE\tREASON\tMESSAGE\n")
		for _, c := range s.Capabilities {
			p.f("%s\t%t\t%s\t%s\n", c.Name, c.Available, dash(c.Reason), c.Message)
		}
	}
	p.f("\nVPC\tOWNER\tGENERATION\tPENDING\tTRANSITIONING\tCLAIMS\tNOTE\n")
	for _, sc := range s.Scopes {
		owner, note := scopeOwner(sc, s.Owner)
		p.f("%s\t%s\t%d\t%t\t%t\t%d\t%s\n", sc.VPC, owner, sc.Fence.Generation, sc.Fence.Pending,
			sc.Fence.Transitioning, len(sc.Claims), note)
	}
	for _, sc := range s.Scopes {
		if d := sc.LastDrift; d != nil {
			p.f("\nVPC %s: %s repaired drift %s ago: %s\n", sc.VPC, d.Module,
				now.Sub(d.Time).Round(time.Second), d.Detail)
		}
	}
	for _, sc := range s.Scopes {
		for _, c := range sc.Claims {
			printClaim(p, c)
		}
	}
	if p.err != nil {
		return p.err
	}
	return tw.Flush()
}

// printClaim writes one claim with its conditions and destinations.
func printClaim(p *printer, c Claim) {
	p.f("\nCLAIM %s\towner %s\thandoff %s\tgeneration %d\tobserved %d\n", c.Key, c.Owner,
		c.Handoff, c.Generation, c.ObservedGeneration)
	for _, cd := range c.Conditions {
		p.f("  %s\t%s\t%s\t%s\n", cd.Type, cd.Status, dash(cd.Reason), cd.Message)
	}
	if c.Withdrawal != "" {
		p.f("  Withdrawing\t%s\n", c.Withdrawal)
	}
	if len(c.HandoffInterfaces) > 0 {
		p.f("  Handoff interfaces\t%s\n", strings.Join(c.HandoffInterfaces, ", "))
	}
	if len(c.Destinations) > 0 {
		p.f("  DESTINATION\tLOCALITY\tPROGRAMMED\tFORWARD\tRETURN\tREASON\tMESSAGE\n")
	}
	for _, d := range c.Destinations {
		p.f("  %s\t%s\t%t\t%t\t%t\t%s\t%s\n", d.ID, dash(d.Locality), d.Programmed,
			d.ForwardReady, d.ReturnReady, dash(d.Reason), d.Message)
	}
}

// scopeOwner returns how to show sc's owner, given this Worker's owner ID,
// and a note on the scope's state.
func scopeOwner(sc Scope, self string) (owner, note string) {
	owner = sc.Fence.Owner
	switch owner {
	case "":
		owner = "(unowned)"
	case self:
		owner += " (this Worker)"
	}
	switch {
	case sc.Repair:
		note = "repairing after a failed commit"
	case sc.Resyncing:
		note = "resyncing after start"
	case ownership.HandedBack(sc.Fence.Owner):
		note = "handed back; the next writer takes it"
	case ownership.WorkerOwned(sc.Fence.Owner) && sc.Fence.Owner != self:
		note = "owned by another Worker incarnation"
	}
	return owner, note
}

// printer writes formatted lines and keeps the first error.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) f(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, args...)
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
