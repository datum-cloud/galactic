// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package stream checks a RunDiagnostic stream against the contract's
// grammar and coverage rules (docs/designs/looking-glass-service.md, "Stream
// grammar and coverage") as a consumer sees them: from the events alone.
package stream

import (
	"fmt"

	servicev1 "go.datum.net/galactic/api/fabric/service/v1"
)

// The terminal reasons the contract defines. Stop reasons take precedence
// over the reason the counts imply.
const (
	Succeeded           = "Succeeded"
	PartialResults      = "PartialResults"
	ExecutionFailed     = "ExecutionFailed"
	NoNodesAvailable    = "NoNodesAvailable"
	DeadlineExceeded    = "DeadlineExceeded"
	Cancelled           = "Cancelled"
	OwnershipLost       = "OwnershipLost"
	OutputLimitExceeded = "OutputLimitExceeded"

	NotRequested = "NotRequested"
)

var stopReasons = map[string]bool{
	DeadlineExceeded: true, Cancelled: true, OwnershipLost: true, OutputLimitExceeded: true,
}

// Outcome is one router's outcome as delivered, without its payload.
type Outcome struct {
	Node string `json:"node"`
	// Result is "observation" or "failure".
	Result string `json:"result"`
	// Reason is the failure reason; empty for an observation.
	Reason    string `json:"reason,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	// Sequence is the event's sequence number, which is its completion
	// handoff order.
	Sequence uint64 `json:"sequence"`
}

// Counts are a stream's coverage.
type Counts struct {
	Expected   uint32 `json:"expected"`
	Successful uint32 `json:"successful"`
	Failed     uint32 `json:"failed"`
	Omitted    uint32 `json:"omitted"`
	Truncated  uint32 `json:"truncatedRouters"`
}

// Result is what a consumer can claim about a stream.
type Result struct {
	// Delivered is true only when a complete arrived, every rule held and
	// the stream ended with OK: the server's coverage is then known.
	Delivered bool `json:"delivered"`
	// Violations lists every broken rule, in the order seen.
	Violations []string `json:"violations,omitempty"`
	// Snapshot holds the snapshot's counts, Selected the routers it
	// selected, and OmittedReasons its omitted routers by reason.
	SnapshotID     string            `json:"snapshotId,omitempty"`
	Snapshot       *Counts           `json:"snapshot,omitempty"`
	Selected       []string          `json:"selected,omitempty"`
	OmittedReasons map[string]string `json:"omittedReasons,omitempty"`
	Unscheduled    uint32            `json:"unscheduledPodCount,omitempty"`
	Outcomes       []Outcome         `json:"outcomes,omitempty"`
	// Pending lists the selected routers with no delivered outcome: their
	// result is unknown to the consumer.
	Pending []string `json:"pending,omitempty"`
	// Complete is the server's terminal coverage and Reason its reason; both
	// are empty when no complete arrived.
	Complete *Counts `json:"complete,omitempty"`
	Reason   string  `json:"reason,omitempty"`
}

// Checker accumulates one stream's events.
type Checker struct {
	requestID string
	next      uint64
	snapshot  *servicev1.Snapshot
	routers   map[string]*servicev1.SnapshotRouter
	seen      map[string]bool
	complete  *servicev1.Complete
	unknown   bool
	res       Result
}

// New returns a Checker for the stream of request requestID.
func New(requestID string) *Checker {
	return &Checker{requestID: requestID, next: 1, seen: map[string]bool{}}
}

func (c *Checker) violate(format string, args ...any) {
	c.res.Violations = append(c.res.Violations, fmt.Sprintf(format, args...))
}

// Observe checks one event in arrival order.
func (c *Checker) Observe(ev *servicev1.DiagnosticEvent) {
	if ev.GetRequestId() != c.requestID {
		c.violate("event %d: request_id %q, want %q", ev.GetSequence(), ev.GetRequestId(), c.requestID)
	}
	if ev.GetSequence() != c.next {
		c.violate("event sequence %d, want %d", ev.GetSequence(), c.next)
	}
	c.next = ev.GetSequence() + 1
	if c.complete != nil {
		c.violate("event %d after complete", ev.GetSequence())
	}
	switch e := ev.GetEvent().(type) {
	case *servicev1.DiagnosticEvent_Snapshot:
		c.observeSnapshot(ev.GetSequence(), e.Snapshot)
	case *servicev1.DiagnosticEvent_Outcome:
		c.observeOutcome(ev.GetSequence(), e.Outcome)
	case *servicev1.DiagnosticEvent_Complete:
		c.observeComplete(ev.GetSequence(), e.Complete)
	default:
		// An unknown variant prevents claiming complete coverage.
		c.unknown = true
		c.violate("event %d: unknown event variant", ev.GetSequence())
	}
}

func (c *Checker) observeSnapshot(seq uint64, s *servicev1.Snapshot) {
	if c.snapshot != nil {
		c.violate("event %d: second snapshot", seq)
		return
	}
	if seq != 1 {
		c.violate("event %d: snapshot is not the first event", seq)
	}
	c.snapshot = s
	c.routers = map[string]*servicev1.SnapshotRouter{}
	counts := &Counts{}
	c.res.OmittedReasons = map[string]string{}
	for _, r := range s.GetRouters() {
		if _, dup := c.routers[r.GetNode()]; dup {
			c.violate("snapshot lists router %s twice", r.GetNode())
			continue
		}
		c.routers[r.GetNode()] = r
		counts.Expected++
		switch {
		case r.GetSelected() && r.GetPodUid() == "":
			c.violate("snapshot: selected router %s has no pod UID", r.GetNode())
		case r.GetSelected() && r.GetOmittedReason() != "":
			c.violate("snapshot: selected router %s has omitted reason %s", r.GetNode(), r.GetOmittedReason())
		case !r.GetSelected() && r.GetOmittedReason() == "":
			c.violate("snapshot: omitted router %s has no reason", r.GetNode())
		}
		if r.GetSelected() {
			c.res.Selected = append(c.res.Selected, r.GetNode())
		} else {
			counts.Omitted++
			c.res.OmittedReasons[r.GetNode()] = r.GetOmittedReason()
		}
	}
	c.res.SnapshotID = s.GetSnapshotId()
	c.res.Snapshot = counts
	c.res.Unscheduled = s.GetUnscheduledPodCount()
}

func (c *Checker) observeOutcome(seq uint64, o *servicev1.RouterOutcome) {
	if c.snapshot == nil {
		c.violate("event %d: outcome before snapshot", seq)
		return
	}
	r, ok := c.routers[o.GetNode()]
	switch {
	case !ok:
		c.violate("event %d: outcome for router %s outside the snapshot", seq, o.GetNode())
		return
	case !r.GetSelected():
		c.violate("event %d: outcome for omitted router %s", seq, o.GetNode())
		return
	case c.seen[o.GetNode()]:
		c.violate("event %d: second outcome for router %s", seq, o.GetNode())
		return
	case o.GetPodUid() != r.GetPodUid():
		c.violate("event %d: router %s outcome pod %s, snapshot froze %s", seq, o.GetNode(), o.GetPodUid(), r.GetPodUid())
	}
	if !o.GetCompletedAt().IsValid() {
		c.violate("event %d: router %s outcome has no completion time", seq, o.GetNode())
	}
	c.seen[o.GetNode()] = true
	out := Outcome{Node: o.GetNode(), Sequence: seq}
	switch {
	case o.GetObservation() != nil:
		obs := o.GetObservation()
		out.Result, out.Truncated = "observation", obs.GetTruncated()
		if obs.GetNode() != "" && obs.GetNode() != o.GetNode() {
			c.violate("event %d: router %s carries router %s's observation", seq, o.GetNode(), obs.GetNode())
		}
		if !obs.GetSampleTime().IsValid() {
			c.violate("event %d: router %s observation has no sample time", seq, o.GetNode())
		}
	case o.GetFailure() != nil:
		f := o.GetFailure()
		out.Result, out.Reason, out.Scope = "failure", f.GetReason(), f.GetScope()
		if f.GetReason() == "" {
			c.violate("event %d: router %s failure has no reason", seq, o.GetNode())
		}
		if len(f.GetMessage()) > 256 {
			c.violate("event %d: router %s failure message is %d bytes", seq, o.GetNode(), len(f.GetMessage()))
		}
	default:
		c.violate("event %d: router %s outcome has neither observation nor failure", seq, o.GetNode())
		out.Result = "unknown"
	}
	c.res.Outcomes = append(c.res.Outcomes, out)
}

func (c *Checker) observeComplete(seq uint64, k *servicev1.Complete) {
	if c.snapshot == nil {
		c.violate("event %d: complete before snapshot", seq)
	}
	c.complete = k
	c.res.Reason = k.GetReason()
	c.res.Complete = &Counts{
		Expected: k.GetExpected(), Successful: k.GetSuccessful(), Failed: k.GetFailed(),
		Omitted: k.GetOmitted(), Truncated: k.GetTruncatedRouters(),
	}
	if c.snapshot == nil {
		return
	}
	if k.GetSnapshotId() != c.snapshot.GetSnapshotId() {
		c.violate("complete snapshot %q, stream snapshot %q", k.GetSnapshotId(), c.snapshot.GetSnapshotId())
	}
	var got Counts
	got.Expected, got.Omitted = c.res.Snapshot.Expected, c.res.Snapshot.Omitted
	for _, o := range c.res.Outcomes {
		switch o.Result {
		case "observation":
			got.Successful++
			if o.Truncated {
				got.Truncated++
			}
		default:
			got.Failed++
		}
	}
	if got != *c.res.Complete {
		c.violate("complete counts %+v, delivered events imply %+v", *c.res.Complete, got)
	}
	if k.GetExpected() != k.GetSuccessful()+k.GetFailed()+k.GetOmitted() {
		c.violate("complete: expected %d != successful %d + failed %d + omitted %d",
			k.GetExpected(), k.GetSuccessful(), k.GetFailed(), k.GetOmitted())
	}
	if !k.GetFinishedAt().IsValid() {
		c.violate("complete has no finish time")
	}
	if want := c.impliedReason(got); !stopReasons[k.GetReason()] && k.GetReason() != want {
		c.violate("complete reason %s, counts imply %s", k.GetReason(), want)
	}
}

// impliedReason is the terminal reason the counts imply when no stop
// reason applies.
func (c *Checker) impliedReason(n Counts) string {
	selected := n.Successful + n.Failed
	partial := n.Failed > 0 || n.Truncated > 0
	for _, reason := range c.res.OmittedReasons {
		partial = partial || reason != NotRequested
	}
	switch {
	case selected == 0:
		return NoNodesAvailable
	case n.Successful == 0:
		return ExecutionFailed
	case partial:
		return PartialResults
	}
	return Succeeded
}

// Finish closes the stream with ok, whether the RPC ended with gRPC OK, and
// returns the result.
func (c *Checker) Finish(ok bool) Result {
	for _, n := range c.res.Selected {
		if !c.seen[n] {
			c.res.Pending = append(c.res.Pending, n)
		}
	}
	if c.complete != nil && len(c.res.Pending) > 0 {
		c.violate("complete arrived with %d selected routers missing an outcome", len(c.res.Pending))
	}
	if c.complete != nil && !ok {
		c.violate("stream ended with an error after complete")
	}
	c.res.Delivered = ok && c.complete != nil && !c.unknown && len(c.res.Violations) == 0
	return c.res
}
