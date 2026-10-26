// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	servicev1 "go.datum.net/galactic/api/fabric/service/v1"
	fabricv1 "go.datum.net/galactic/api/fabric/v1"
	"go.datum.net/galactic/internal/fabric/errcode"
	"go.datum.net/galactic/internal/fabric/gateway/limit"
	"go.datum.net/galactic/internal/fabric/node"
	"go.datum.net/galactic/internal/fabric/query"
)

// concurrency records running node jobs per principal, and the order in
// which principals' jobs started.
type concurrency struct {
	mu         sync.Mutex
	principal  map[string]string // request ID -> principal
	running    map[string]int
	maxRunning map[string]int
	total, max int
	starts     []string
}

func newConcurrency() *concurrency {
	return &concurrency{principal: map[string]string{}, running: map[string]int{}, maxRunning: map[string]int{}}
}

func (c *concurrency) assign(requestID, principal string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.principal[requestID] = principal
}

func (c *concurrency) answer(name string) routerAnswer {
	return func(_ context.Context, req *fabricv1.ExecuteRequest) (*fabricv1.Observation, error) {
		c.mu.Lock()
		p := c.principal[req.GetRequestId()]
		c.running[p]++
		c.total++
		c.maxRunning[p] = max(c.maxRunning[p], c.running[p])
		c.max = max(c.max, c.total)
		c.starts = append(c.starts, p)
		c.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		c.mu.Lock()
		c.running[p]--
		c.total--
		c.mu.Unlock()
		return pingObservation(name, 3), nil
	}
}

var loadRouters = []string{"router-1", "router-2", "router-3", "router-4", "router-5", "router-6"}

// TestFairnessUnderLoad queues 10 service streams from five projects and two
// FabricQuery runs behind a full executor, then lets them go. Every job
// completes, no principal ever holds more than its two slots nor the cell
// more than eight, every principal starts within the first round of grants,
// and a third concurrent stream from one project is refused.
func TestFairnessUnderLoad(t *testing.T) {
	c := newConcurrency()
	answers := map[string]routerAnswer{}
	for _, n := range loadRouters {
		answers[n] = c.answer(n)
	}
	nodes := &routerNodes{answers: answers}
	svc := newService(t, routerPods(loadRouters...), nodes, 8)
	l := roomyLimits()
	l.ProjectStreams = limit.Defaults().ProjectStreams
	withAdmission(t, svc, l)
	svc.Runner.QueueWait = limit.MaxQueueWait
	e := svc.Runner.Executor

	// Fill all eight slots with four plug principals.
	plugs := make([]func(), 0, 8)
	for i := range 8 {
		rel, err := e.Acquire(t.Context(), fmt.Sprintf("plug-%d", i/2), false)
		if err != nil {
			t.Fatal(err)
		}
		plugs = append(plugs, rel)
	}

	projects := []string{"project-0", "project-1", "project-2", "project-3", "project-4"}
	type stream struct {
		events <-chan *servicev1.DiagnosticEvent
		done   <-chan error
	}
	streams := make([]stream, 0, 2*len(projects))
	n := 0
	for _, p := range projects {
		for range 2 {
			n++
			req := requestFor(p, n, nil)
			c.assign(req.GetRequestId(), p)
			ev, done := run(t, svc, req, 0)
			streams = append(streams, stream{ev, done})
		}
	}
	// FabricQuery runs share the executor under their own principal.
	ping := node.QueryFromProto(&fabricv1.Query{Type: fabricv1.QueryType_QUERY_TYPE_PING, Target: probeTarget6,
		AddressFamily: fabricv1.AddressFamily_ADDRESS_FAMILY_IPV6})
	routers := make([]Node, 0, len(loadRouters))
	for _, r := range loadRouters {
		routers = append(routers, Node{Name: r, PodUID: "pod-" + r, Selected: true})
	}
	var fq sync.WaitGroup
	var fqOutcomes [][]Outcome
	var fqMu sync.Mutex
	for i := range 2 {
		id := fmt.Sprintf("fq-%d", i)
		c.assign(id, "ns/cluster")
		fq.Go(func() {
			out := svc.Runner.Run(t.Context(), "ns/cluster", id, ping, routers, nil, time.Now().Add(30*time.Second))
			fqMu.Lock()
			fqOutcomes = append(fqOutcomes, out)
			fqMu.Unlock()
		})
	}
	waitDepth(t, e, 10*len(loadRouters)+2*len(loadRouters))

	// A third live stream from one project is refused at once.
	_, err := collect(t, svc, requestFor("project-0", 999, nil))
	wantRetry(t, err, errcode.QueueFull, "queue")

	for _, rel := range plugs {
		rel()
	}
	for i, s := range streams {
		var events []*servicev1.DiagnosticEvent
		for ev := range s.events {
			events = append(events, ev)
		}
		if err := <-s.done; err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
		if _, _, cmp := checkGrammar(t, events); cmp.GetReason() != CompleteSucceeded {
			t.Errorf("stream %d: %v", i, cmp)
		}
	}
	fq.Wait()
	for _, out := range fqOutcomes {
		for _, o := range out {
			if o.Err != nil {
				t.Errorf("FabricQuery %s: %v", o.Node.Name, o.Err)
			}
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.max > 8 {
		t.Errorf("%d jobs ran at once, above the cell's 8", c.max)
	}
	for p, m := range c.maxRunning {
		if m > 2 {
			t.Errorf("%s ran %d jobs at once, above its 2", p, m)
		}
	}
	principals := append(append([]string{}, projects...), "ns/cluster")
	for _, p := range principals {
		first := -1
		for i, s := range c.starts {
			if s == p {
				first = i
				break
			}
		}
		if first < 0 || first >= 2*len(principals) {
			t.Errorf("%s first started at grant %d of %d", p, first, len(c.starts))
		}
	}
	if len(c.starts) != 12*len(loadRouters) {
		t.Errorf("%d jobs ran, want %d", len(c.starts), 12*len(loadRouters))
	}
}

func traceroute(target string) *fabricv1.Query {
	return &fabricv1.Query{Type: fabricv1.QueryType_QUERY_TYPE_TRACEROUTE, Target: target}
}

// TestDestinationPrefixAcrossProjects sends traceroutes from three projects
// to three hosts of one /64: the prefix budget binds whichever project asks.
func TestDestinationPrefixAcrossProjects(t *testing.T) {
	svc := newService(t, routerPods(routerA), &routerNodes{}, 8)
	l := roomyLimits()
	l.PacketPrefix = limit.Rate{PerSecond: 1, Burst: 2 * limit.TraceroutePackets}
	withAdmission(t, svc, l)
	for i, target := range []string{probeTarget6, "2001:db8::2", "2001:db8::3"} {
		events, err := collect(t, svc, requestFor(fmt.Sprintf("project-%d", i), i, func(r *runReq) {
			r.Query = traceroute(target)
		}))
		if err != nil {
			t.Fatal(err)
		}
		_, outcomes, _ := checkGrammar(t, events)
		throttled := outcomes[routerA].GetFailure().GetReason() == string(errcode.Throttled)
		if throttled != (i == 2) {
			t.Errorf("request %d to %s: %v", i, target, outcomes[routerA])
		}
	}
}

// TestAggregateBudgetsCoverEveryCaller charges a cell packet budget of three
// traceroutes from four callers, each with its own principal and
// destination prefix: the service, a FabricQuery, a direct operator through
// its node's permit, and an operator through the gateway. The fourth is
// refused at the cell scope whichever caller it is.
func TestAggregateBudgetsCoverEveryCaller(t *testing.T) {
	nodes := &routerNodes{}
	svc := newService(t, routerPods(routerA), nodes, 8)
	l := roomyLimits()
	small := limit.Rate{PerSecond: 0.5, Burst: 3 * limit.TraceroutePackets}
	l.PacketCell, l.PacketPrincipal, l.PacketHost, l.PacketPrefix = small, small, small, small
	adm := withAdmission(t, svc, l)
	permits := &Permits{Admission: adm, Executor: svc.Runner.Executor, Discoverer: svc.Discoverer, Elected: elected}
	routers := []Node{{Name: routerA, PodUID: podA, Selected: true}}
	expires := time.Now().Add(30 * time.Second)

	events, err := collect(t, svc, requestFor("project-a", 1, func(r *runReq) { r.Query = traceroute("2001:db8:1::1") }))
	if err != nil {
		t.Fatal(err)
	}
	if _, out, _ := checkGrammar(t, events); out[routerA].GetFailure() != nil {
		t.Fatalf("service: %v", out[routerA])
	}
	trace := func(target string) query.Query {
		return node.QueryFromProto(&fabricv1.Query{Type: fabricv1.QueryType_QUERY_TYPE_TRACEROUTE, Target: target,
			AddressFamily: fabricv1.AddressFamily_ADDRESS_FAMILY_IPV6})
	}
	out := svc.Runner.Run(t.Context(), "ns/cluster", "fq-1", trace("2001:db8:2::1"), routers, nil, expires)
	if out[0].Err != nil {
		t.Fatalf("FabricQuery: %v", out[0].Err)
	}
	req := pingPermitRequest(routerA, "alice", expires)
	req.Query = &fabricv1.Query{Type: fabricv1.QueryType_QUERY_TYPE_TRACEROUTE, Target: probeTarget4,
		AddressFamily: fabricv1.AddressFamily_ADDRESS_FAMILY_IPV4}
	if _, err := permits.RequestPermit(nodeCaller(t.Context(), routerA), req); err != nil {
		t.Fatalf("direct operator: %v", err)
	}

	out = svc.Runner.Run(t.Context(), "operator/bob", "op-1", trace("2001:db8:4::1"), routers, nil, expires)
	if errcode.Of(out[0].Err) != errcode.Throttled || errcode.Metadata(out[0].Err)[errcode.MetadataScope] != "cell" {
		t.Errorf("operator through the gateway past the cell budget: %v", out[0].Err)
	}
	req.Operator, req.Query.Target = "carol", "198.51.100.1"
	_, err = permits.RequestPermit(nodeCaller(t.Context(), routerA), req)
	if errcode.Of(err) != errcode.Throttled {
		t.Errorf("direct operator past the cell budget: %v", err)
	}
	if n := nodes.total(); n != 2 {
		t.Errorf("%d probes reached routers through the gateway, want 2", n)
	}
}
