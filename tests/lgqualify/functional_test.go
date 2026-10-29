// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package lgqualify_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// authorization: only an allowed same-cell service identity reaches the
// service, only its two methods, and forwarding metadata it sends is
// ignored (A1, A2).
func authorization(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	q := []string{fType, bgpSummary, fFamily, ipv4}
	r := mustRun(ctx, t, l, idService, append([]string{fProject, l.project()}, q...)...)
	expectDelivered(t, "allowed service", r, "Succeeded")
	ev.Observed["allowed service"] = brief(r)

	for _, c := range []struct {
		name string
		id   identity
		code string
	}{
		{"no client certificate", idNone, ""},
		{"expired certificate", idExpired, ""},
		{"service of another cell", idOtherCell, ""},
		{"service not allowlisted", idUnlisted, ""},
		{"operator identity", idOperator, "PermissionDenied"},
	} {
		r := mustRun(ctx, t, l, c.id, append([]string{fProject, l.project()}, q...)...)
		expectRefused(t, c.name, r, c.code, "")
		ev.Observed[c.name] = brief(r)
		lines, err := l.lgc(ctx, c.id, "capabilities")
		if err != nil {
			t.Fatal(err)
		}
		var caps struct {
			Status       struct{ Code string } `json:"status"`
			Capabilities json.RawMessage       `json:"capabilities"`
		}
		_ = json.Unmarshal(lines[0], &caps)
		if caps.Status.Code == "OK" || caps.Capabilities != nil {
			t.Errorf("%s: capabilities answered: %s", c.name, lines[0])
		}
		ev.Observed[c.name+" capabilities"] = lines[0]
	}

	r = mustRun(ctx, t, l, idService, append([]string{fProject, l.project(), "-request-cell", "iad"}, q...)...)
	expectRefused(t, "request for another cell", r, "PermissionDenied", "Unauthorized")
	ev.Observed["request for another cell"] = brief(r)

	// Every other method on the gateway's listener is closed to the
	// service, the leader-only forwarding method included.
	closed := map[string]any{}
	for _, m := range []string{
		"/fabric.v1.FabricGatewayService/Query", "/fabric.v1.FabricGatewayService/ListNodes",
		"/fabric.v1.FabricService/Execute", "/fabric.v1.FabricService/Info",
		"/fabric.forward.v1.ForwardService/ForwardDiagnostic",
		"/fabric.permit.v1.PermitService/RequestPermit", "/fabric.permit.v1.PermitService/ReleasePermit",
	} {
		lines, err := l.lgc(ctx, idService, "invoke", "--method", m)
		if err != nil {
			t.Fatal(err)
		}
		var res struct {
			Status struct{ Code, Reason string } `json:"status"`
		}
		_ = json.Unmarshal(lines[0], &res)
		closed[m] = res.Status
		if res.Status.Code != "PermissionDenied" && res.Status.Code != "Unimplemented" {
			t.Errorf("%s: %s/%s, want PermissionDenied", m, res.Status.Code, res.Status.Reason)
		}
	}
	ev.Observed["other methods"] = closed

	// Forged forwarding metadata: the request runs under its own
	// attribution, which the leader's log line records.
	project, since := l.project(), time.Now()
	r = mustRun(ctx, t, l, idService, append([]string{fProject, project, "-metadata",
		"x-fabric-api-project=lgq-forged,x-fabric-api-service=spiffe://fabric-api.datumapis.com/cell/dfw/service/forged," +
			"x-fabric-api-request-id=00000000-0000-4000-8000-000000000000,x-fabric-api-deadline=2099-01-01T00:00:00Z"}, q...)...)
	expectDelivered(t, "forged forwarding metadata", r, "Succeeded")
	ev.Observed["forged forwarding metadata"] = brief(r)
	line, err := waitFinished(ctx, l, r.RequestID, since)
	if err != nil {
		t.Error(err)
	} else {
		ev.Observed["forged forwarding metadata log"] = line
		text, _ := json.Marshal(line)
		if !bytes.Contains(text, []byte(project)) || bytes.Contains(text, []byte("forged")) {
			t.Errorf("forged metadata changed attribution: %s", text)
		}
	}

	// One connection carries several streams in turn.
	recs, _, err := l.load(ctx, spec{Groups: []group{{
		Name: "reused-connection", Count: 3, Concurrency: 1, Interval: "600ms",
		Projects: []string{l.project(), l.project(), l.project()},
		Options:  options{Query: query{Type: bgpSummary, Family: ipv6}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		expectDelivered(t, "reused connection", r, "Succeeded")
	}
	ev.Observed["reused connection"] = len(recs)

	rotation(ctx, t, l, ev, q)
	ev.Notes = append(ev.Notes, "CA rotation (overlapping bundle) is not exercised on the lab: rotating the "+
		"lab CA re-keys every node and gateway identity in the cell; the reload/overlap mechanism is covered "+
		"by internal/fabric/identity tests.")
}

// rotation reissues the service certificate and checks the new one and
// the still-valid old one are both accepted.
func rotation(ctx context.Context, t *testing.T, l *lab, ev *evidence, q []string) {
	const secret = "lg-qualify-looking-glass"
	old, err := l.cs.CoreV1().Secrets(ns).Get(ctx, secret, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.kubectl("-n", ns, "delete", "secret", secret); err != nil {
		t.Fatal(err)
	}
	var renewed *corev1.Secret
	for range 60 {
		time.Sleep(time.Second)
		s, err := l.cs.CoreV1().Secrets(ns).Get(ctx, secret, metav1.GetOptions{})
		if err == nil && len(s.Data[certFile]) > 0 && !bytes.Equal(s.Data[certFile], old.Data[certFile]) {
			renewed = s
			break
		}
	}
	if renewed == nil {
		t.Fatal("cert-manager did not reissue the service certificate within 60 s")
	}
	for _, f := range []string{certFile, keyFile, caFile} {
		if err := clientWrite(fmt.Sprintf("%s/rotated/%s", clientDir, f), renewed.Data[f], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []identity{"rotated", idService} {
		r := mustRun(ctx, t, l, id, append([]string{fProject, l.project()}, q...)...)
		expectDelivered(t, "certificate "+string(id), r, "Succeeded")
		ev.Observed["rotation: "+string(id)] = brief(r)
	}
}

// waitFinished polls for the leader's log line of requestID.
func waitFinished(ctx context.Context, l *lab, requestID string, since time.Time) (map[string]any, error) {
	var err error
	for range 10 {
		var line map[string]any
		if line, err = l.finishedLine(ctx, requestID, since); err == nil {
			return line, nil
		}
		time.Sleep(time.Second)
	}
	return nil, err
}

// compatibility: an incompatible major, unknown feature or unsupported
// operation is refused before any work, never downgraded (A7).
func compatibility(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	lines, err := l.lgc(ctx, idService, "capabilities", "--api-major", "2")
	if err != nil {
		t.Fatal(err)
	}
	var caps struct {
		Status struct{ Code, Reason string } `json:"status"`
	}
	_ = json.Unmarshal(lines[0], &caps)
	if caps.Status.Code != codeFailedPrecondition || caps.Status.Reason != "VersionUnsupported" {
		t.Errorf("capabilities api_major 2: %s", lines[0])
	}
	ev.Observed["capabilities api_major 2"] = caps.Status

	for _, c := range []struct {
		name         string
		args         []string
		code, reason string
	}{
		{
			"api_major 2", []string{"-api-major", "2", fType, bgpSummary, fFamily, ipv4},
			codeFailedPrecondition, "VersionUnsupported",
		},
		{
			"unknown required feature", []string{"-require", "teleport", fType, bgpSummary, fFamily, ipv4},
			codeFailedPrecondition, "",
		},
		{"ASPath", []string{fType, "ASPath", fTarget, "_65000_"}, "", ""},
		{"Community", []string{fType, "Community", fTarget, "65000:1"}, "", ""},
		{"unknown operation enum", []string{fType, "enum:99"}, "", ""},
	} {
		r := mustRun(ctx, t, l, idService, append([]string{fProject, l.project()}, c.args...)...)
		expectRefused(t, c.name, r, c.code, c.reason)
		ev.Observed[c.name] = brief(r)
	}
	r := mustRun(ctx, t, l, idService, fProject, l.project(), fType, bgpSummary, fFamily, ipv4,
		"-require", "router-outcomes,terminal-coverage,aggregate-probe-budgets")
	expectDelivered(t, "every served feature required", r, "Succeeded")
	ev.Observed["every served feature required"] = brief(r)
	ev.Notes = append(ev.Notes, "The client decodes the contract's published fixtures "+
		"(api/fabric/service/v1/testdata) in its own module's tests: examples/looking-glass-client/internal/stream.")
}

// event is the part of a delivered event the payload checks read.
type event struct {
	Outcome *struct {
		Node        string `json:"node"`
		Observation *struct {
			Truncated bool `json:"truncated"`
			Ping      *struct {
				Sent     int `json:"sent"`
				Received int `json:"received"`
			} `json:"ping"`
			Traceroute *struct {
				Reached bool              `json:"reached"`
				Hops    []json.RawMessage `json:"hops"`
			} `json:"traceroute"`
			Summary *struct {
				Peers []json.RawMessage `json:"peers"`
			} `json:"summary"`
			Routes json.RawMessage `json:"routes"`
		} `json:"observation"`
	} `json:"outcome"`
}

func observations(events []json.RawMessage) []event {
	var out []event
	for _, raw := range events {
		var e event
		if json.Unmarshal(raw, &e) == nil && e.Outcome != nil && e.Outcome.Observation != nil {
			out = append(out, e)
		}
	}
	return out
}

// diagnostics: all four operations on both families return typed
// observations from every router; loss, silent hops and an empty lookup
// are observations, not failures (A3, A6).
func diagnostics(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	type check func(e event) string
	pingReplies := func(want int) check {
		return func(e event) string {
			if p := e.Outcome.Observation.Ping; p == nil || p.Sent != pingPackets || p.Received != want {
				return fmt.Sprintf("ping %+v, want %d of %d replies", p, want, pingPackets)
			}
			return ""
		}
	}
	reached := func(want bool) check {
		return func(e event) string {
			if tr := e.Outcome.Observation.Traceroute; tr == nil || tr.Reached != want || len(tr.Hops) == 0 {
				return fmt.Sprintf("traceroute %+v, want reached=%t", tr, want)
			}
			return ""
		}
	}
	summary := func(e event) string {
		if s := e.Outcome.Observation.Summary; s == nil || len(s.Peers) == 0 {
			return "summary has no peers"
		}
		return ""
	}
	routes := func(e event) string {
		if len(e.Outcome.Observation.Routes) == 0 {
			return "lookup has no route result"
		}
		return ""
	}
	// queued marks a three-router traceroute that outlasts the queue wait:
	// a project holds two node slots, so its third router waits and fails
	// QueueTimeout at 10 s, the default behaviour the contract requires
	// qualification to report.
	cases := []struct {
		name   string
		args   []string
		check  check
		queued bool
	}{
		{"BGPSummary IPv4", []string{fType, bgpSummary, fFamily, ipv4}, summary, false},
		{"BGPSummary IPv6", []string{fType, bgpSummary, fFamily, ipv6}, summary, false},
		{"RouteLookup IPv4 longest match", []string{fType, routeLookup, fTarget, answer4}, routes, false},
		{"RouteLookup IPv6 longest match", []string{fType, routeLookup, fTarget, answer6}, routes, false},
		{"RouteLookup IPv4 exact", []string{fType, routeLookup, fTarget, "11.1.40.0/24"}, routes, false},
		{"RouteLookup IPv6 exact", []string{fType, routeLookup, fTarget, "2c0f:40::/64"}, routes, false},
		{"RouteLookup with no route", []string{fType, routeLookup, fTarget, "198.51.100.7"}, routes, false},
		{"Ping IPv4", []string{fType, ping, fTarget, answer4}, pingReplies(pingPackets), false},
		{"Ping IPv6", []string{fType, ping, fTarget, answer6}, pingReplies(pingPackets), false},
		{"Traceroute IPv4", []string{fType, traceroute, fTarget, answer4}, reached(true), false},
		{"Traceroute IPv6", []string{fType, traceroute, fTarget, answer6}, reached(true), false},
		{"Ping IPv4 with loss", []string{fType, ping, fTarget, l.sinkHost(4)}, pingReplies(0), false},
		{"Ping IPv6 with loss", []string{fType, ping, fTarget, l.sinkHost(6)}, pingReplies(0), false},
		{
			"Traceroute IPv4 with silent hops", []string{fType, traceroute, fTarget, l.sinkHost(4), fExpires, "60s"},
			reached(false), true,
		},
		{
			"Traceroute IPv6 with silent hops", []string{fType, traceroute, fTarget, l.sinkHost(6), fExpires, "60s"},
			reached(false), true,
		},
	}
	sizes := map[string]int{}
	for _, c := range cases {
		time.Sleep(pace)
		r, events, err := l.runEvents(ctx, idService, append([]string{fProject, l.project()}, c.args...)...)
		if err != nil {
			t.Fatal(err)
		}
		ev.Observed[c.name] = brief(r)
		sizes[c.name] = r.MaxEventBytes
		obs := observations(events)
		want := len(routers)
		if c.queued {
			want--
			expectDelivered(t, c.name, r, "PartialResults")
			checkQueueTimeout(t, c.name, r, ev)
		} else {
			expectDelivered(t, c.name, r, "Succeeded")
		}
		if len(obs) != want {
			t.Errorf("%s: %d observations, want %d", c.name, len(obs), want)
		}
		for _, e := range obs {
			if msg := c.check(e); msg != "" {
				t.Errorf("%s on %s: %s", c.name, e.Outcome.Node, msg)
			}
		}
	}
	ev.Observed["largest event bytes"] = sizes
}

// checkQueueTimeout checks r holds exactly one QueueTimeout router outcome,
// delivered within the queue wait (measured from the snapshot) plus 1.5 s.
func checkQueueTimeout(t *testing.T, name string, r Record, ev *evidence) {
	t.Helper()
	n := 0
	for i, o := range r.Stream.Outcomes {
		if o.Result != failure {
			continue
		}
		n++
		after := time.Duration((r.Timing.OutcomeMS[i] - r.Timing.SnapshotMS) * float64(time.Millisecond))
		ev.Observed[name+" queue timeout after snapshot"] = after.String()
		if o.Reason != "QueueTimeout" || after < queueWait-500*time.Millisecond || after > queueWait+1500*time.Millisecond {
			t.Errorf("%s: %s failed %s %s after the snapshot, want QueueTimeout at %s", name, o.Node, o.Reason, after, queueWait)
		}
	}
	if n != 1 {
		t.Errorf("%s: %d failed routers, want 1", name, n)
	}
}

// coverage: fixed membership and exact counts for an explicit subset, an
// unreachable router and an omitted one; a fast router's outcome is not
// held behind a slow one (A4, A5).
func coverage(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	r := mustRun(ctx, t, l, idService, fProject, l.project(), fType, bgpSummary, fFamily, ipv4, fNodes, routers[0])
	expectDelivered(t, "explicit subset", r, "Succeeded")
	if c := r.Stream.Complete; c == nil || c.Expected != 3 || c.Successful != 1 || c.Omitted != 2 ||
		r.Stream.OmittedReasons[routers[1]] != reasonNotRequested ||
		r.Stream.OmittedReasons[routers[2]] != reasonNotRequested {
		t.Errorf("explicit subset: %+v %v", r.Stream.Complete, r.Stream.OmittedReasons)
	}
	ev.Observed["explicit subset"] = brief(r)

	many := make([]string, 33)
	for i := range many {
		many[i] = fmt.Sprintf("router-%d", i)
	}
	for _, c := range []struct {
		name  string
		nodes string
	}{
		{"unknown router", "no-such-router"},
		{"duplicate router", routers[0] + "," + routers[0]},
		{"33 routers", strings.Join(many, ",")},
	} {
		r := mustRun(ctx, t, l, idService, fProject, l.project(), fType, bgpSummary, fFamily, ipv4, fNodes, c.nodes)
		expectRefused(t, c.name, r, "InvalidArgument", reasonInvalidQuery)
		ev.Observed[c.name] = brief(r)
	}

	unreachableRouter(ctx, t, l, ev)
	omittedRouter(ctx, t, l, ev)
}

// unreachableRouter drops the gateway's connections to dfw-worker3's
// sidecar and checks the other routers' outcomes arrive first, with the
// unreachable one a failure, not an omission.
func unreachableRouter(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	slow := routers[2]
	rule := "-p tcp --dport 9344 -j DROP"
	for _, ipt := range []string{iptables, ip6tables} {
		if _, err := nodeExec(slow, "sh", "-c", fmt.Sprintf("%s -w -I INPUT %s", ipt, rule)); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, ipt := range []string{iptables, ip6tables} {
			_, _ = nodeExec(slow, "sh", "-c", fmt.Sprintf("%s -w -D INPUT %s", ipt, rule))
		}
	})
	r := mustRun(ctx, t, l, idService, fProject, l.project(), fType, bgpSummary, fFamily, ipv4, fExpires, "60s")
	for _, ipt := range []string{iptables, ip6tables} {
		_, _ = nodeExec(slow, "sh", "-c", fmt.Sprintf("%s -w -D INPUT %s", ipt, rule))
	}
	expectDelivered(t, "unreachable router", r, "PartialResults")
	ev.Observed["unreachable router"] = brief(r)
	var fastLast, slowAt float64 = -1, -1
	for i, o := range r.Stream.Outcomes {
		at := r.Timing.OutcomeMS[i]
		switch {
		case o.Node == slow && o.Result == failure:
			slowAt = at
		case o.Node != slow && o.Result == observation:
			fastLast = max(fastLast, at)
		default:
			t.Errorf("unreachable router: unexpected outcome %s:%s:%s", o.Node, o.Result, o.Reason)
		}
	}
	ev.Observed["unreachable router timing"] = map[string]float64{
		"lastReachableOutcomeMs": fastLast, "unreachableOutcomeMs": slowAt,
	}
	if fastLast < 0 || slowAt < 0 || slowAt-fastLast < 1000 {
		t.Errorf("reachable outcomes at %.0f ms were not delivered ahead of the unreachable router's at %.0f ms",
			fastLast, slowAt)
	}
}

// omittedRouter keeps the fabric-api-certs pod off dfw-worker3 and checks
// that router is omitted, not failed, and the result partial.
func omittedRouter(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	target := routers[2]
	dsc := l.cs.AppsV1().DaemonSets(ns)
	ds, err := dsc.Get(ctx, "fabric-api-certs", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	original := ds.Spec.Template.Spec.Affinity.DeepCopy()
	restore := func() {
		cur, err := dsc.Get(context.Background(), "fabric-api-certs", metav1.GetOptions{})
		if err != nil {
			t.Errorf("restore fabric-api-certs: %v", err)
			return
		}
		cur.Spec.Template.Spec.Affinity = original
		if _, err := dsc.Update(context.Background(), cur, metav1.UpdateOptions{}); err != nil {
			t.Errorf("restore fabric-api-certs: %v", err)
		}
	}
	t.Cleanup(restore)
	excludeNode(ds, target)
	if _, err := dsc.Update(ctx, ds, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := l.certsRolledOut(); err != nil {
		t.Fatal(err)
	}
	others := func(nodes []string) bool { return !slices.Contains(nodes, target) && len(nodes) == len(routers)-1 }
	if err := waitCertsPods(ctx, l, others); err != nil {
		t.Fatal(err)
	}
	if err := l.waitRouters(ctx, routers[:2]); err != nil {
		t.Fatal(err)
	}
	r := mustRun(ctx, t, l, idService, fProject, l.project(), fType, bgpSummary, fFamily, ipv4)
	expectDelivered(t, "omitted router", r, "PartialResults")
	if reason := r.Stream.OmittedReasons[target]; reason == "" || reason == reasonNotRequested {
		t.Errorf("omitted router: %s omitted for %q", target, reason)
	}
	if c := r.Stream.Complete; c == nil || c.Expected != 3 || c.Successful != 2 || c.Omitted != 1 {
		t.Errorf("omitted router: counts %+v", r.Stream.Complete)
	}
	ev.Observed["omitted router"] = brief(r)
	ev.Observed["omitted reason"] = r.Stream.OmittedReasons[target]
	restore()
	if err := l.certsRolledOut(); err != nil {
		t.Fatal(err)
	}
	if err := l.waitRouters(ctx, routers); err != nil {
		t.Fatal(err)
	}
}

// certsRolledOut waits for the fabric-api-certs DaemonSet's rollout.
func (l *lab) certsRolledOut() error {
	_, err := l.kubectl("-n", ns, "rollout", "status", "daemonset/fabric-api-certs", "--timeout=180s")
	return err
}

// waitRouters waits until a summary answers from exactly the routers in
// want, which happens once each sidecar has loaded its certs pod's new
// certificate. It runs no probe, so it charges no packet budget.
func (l *lab) waitRouters(ctx context.Context, want []string) error {
	var last Record
	for range 60 {
		time.Sleep(3 * time.Second)
		r, err := l.run(ctx, idService, fProject, l.project(), fType, bgpSummary, fFamily, ipv4)
		if err != nil {
			return err
		}
		last = r
		var got []string
		for _, o := range r.Stream.Outcomes {
			if o.Result == observation {
				got = append(got, o.Node)
			}
		}
		slices.Sort(got)
		if slices.Equal(got, want) {
			return nil
		}
	}
	return fmt.Errorf("routers did not converge on %v: last %v", want, outcomeSummary(last))
}

// excludeNode adds a required node affinity term keeping ds off node.
func excludeNode(ds *appsv1.DaemonSet, node string) {
	spec := &ds.Spec.Template.Spec
	if spec.Affinity == nil {
		spec.Affinity = &corev1.Affinity{}
	}
	if spec.Affinity.NodeAffinity == nil {
		spec.Affinity.NodeAffinity = &corev1.NodeAffinity{}
	}
	na := spec.Affinity.NodeAffinity
	if na.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		na.RequiredDuringSchedulingIgnoredDuringExecution = &corev1.NodeSelector{
			NodeSelectorTerms: []corev1.NodeSelectorTerm{{}},
		}
	}
	not := corev1.NodeSelectorRequirement{
		Key: "kubernetes.io/hostname", Operator: corev1.NodeSelectorOpNotIn, Values: []string{node},
	}
	terms := na.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
	for i := range terms {
		terms[i].MatchExpressions = append(terms[i].MatchExpressions, not)
	}
}

// waitCertsPods waits until the running, ready fabric-api-certs pods'
// nodes satisfy ok.
func waitCertsPods(ctx context.Context, l *lab, ok func([]string) bool) error {
	for range 120 {
		pods, err := l.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: certsSelector})
		if err == nil {
			var nodes []string
			for _, p := range pods.Items {
				if p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning && podReady(p) {
					nodes = append(nodes, p.Spec.NodeName)
				}
			}
			if ok(nodes) {
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return errors.New("fabric-api-certs pods did not converge")
}

func podReady(p corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// destinations: the public probe policy and target syntax apply to every
// service probe, with no operator exception (A3).
func destinations(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	for _, c := range []struct {
		name, typ, target, family, reason string
	}{
		{"private IPv4", ping, "10.0.0.1", "", reasonDestinationNotAllowed},
		{"documentation IPv6", ping, "2001:db8:1:40::2", "", reasonDestinationNotAllowed},
		{"operator-allowed fabric loopback", ping, "fc00:0:2::1", "", reasonDestinationNotAllowed},
		{"operator-allowed IPv4 loopback", traceroute, "10.255.255.2", "", reasonDestinationNotAllowed},
		{"multicast", traceroute, "224.0.0.1", "", reasonDestinationNotAllowed},
		{"IPv4-mapped IPv6", ping, "::ffff:" + answer4, "", ""},
		{"hostname", ping, "remote.example", "", reasonInvalidQuery},
		{"family mismatch", ping, answer4, ipv6, reasonInvalidQuery},
		{"prefix as probe target", ping, "11.1.40.0/24", "", reasonInvalidQuery},
		{"lookup prefix with host bits", routeLookup, "11.1.40.1/24", "", reasonInvalidQuery},
		{"summary with target", bgpSummary, answer4, ipv4, reasonInvalidQuery},
	} {
		args := []string{fProject, l.project(), fType, c.typ, fTarget, c.target}
		if c.family != "" {
			args = append(args, fFamily, c.family)
		}
		r := mustRun(ctx, t, l, idService, args...)
		expectRefused(t, c.name, r, "InvalidArgument", c.reason)
		ev.Observed[c.name] = brief(r)
	}
}

// fabricQuery creates a FabricQuery for this cell and returns its status
// once Complete.
func (l *lab) fabricQuery(ctx context.Context, name, query string) (map[string]any, error) {
	manifest := fmt.Sprintf(`apiVersion: galactic.datumapis.com/v1alpha1
kind: FabricQuery
metadata:
  name: %[1]s
  namespace: fabric-api-verify
spec:
  requestID: %[1]s
  source: {uid: lg-qualify, cluster: lab, namespace: default, name: %[1]s}
  query: %[2]s
  site: %[3]s
  clusterName: %[3]s
  expiresAt: %[4]q
`, name, query, cell, time.Now().UTC().Add(90*time.Second).Format(time.RFC3339))
	_, err := l.kubectl("create", "namespace", "fabric-api-verify")
	if err != nil && !strings.Contains(err.Error(), "AlreadyExists") {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", l.kubeconfig, "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("apply FabricQuery: %w: %s", err, out)
	}
	defer func() { _, _ = l.kubectl("-n", "fabric-api-verify", "delete", "fabricquery", name, "--wait=false") }()
	_, err = l.kubectl("-n", "fabric-api-verify", "wait", "--for=condition=Complete", "--timeout=90s", "fabricquery/"+name)
	if err != nil {
		return nil, err
	}
	out, err := l.kubectl("-n", "fabric-api-verify", "get", "fabricquery", name, "-o", "jsonpath={.status}")
	if err != nil {
		return nil, err
	}
	var st map[string]any
	return st, json.Unmarshal([]byte(out), &st)
}

// fqSummary is a FabricQuery status's Complete reason and its observation
// and error counts.
func fqSummary(st map[string]any) (string, int, []string) {
	reason := ""
	if conds, ok := st["conditions"].([]any); ok {
		for _, c := range conds {
			if m, ok := c.(map[string]any); ok && m["type"] == "Complete" {
				reason, _ = m["reason"].(string)
			}
		}
	}
	obs := 0
	var errs []string
	if list, ok := st["observations"].([]any); ok {
		for _, o := range list {
			m, _ := o.(map[string]any)
			if code, ok := m["errorCode"].(string); ok && code != "" {
				errs = append(errs, code)
			} else {
				obs++
			}
		}
	}
	return reason, obs, errs
}

// nodeResult is one node's answer in the query CLI's JSON.
type nodeResult struct {
	Observation json.RawMessage `json:"observation"`
	ErrorCode   string          `json:"errorCode"`
}

// operatorResults parses the query CLI's JSON: per node, an observation or
// an error code. A gateway query prints {"results": [...]}, a direct node
// query that node's single result.
func operatorResults(out string) (int, []string, error) {
	i := strings.Index(out, "{")
	if i < 0 {
		return 0, nil, fmt.Errorf("no JSON in %q", out)
	}
	var res struct {
		Results []nodeResult `json:"results"`
		nodeResult
	}
	if err := json.Unmarshal([]byte(out[i:]), &res); err != nil {
		return 0, nil, err
	}
	if res.Results == nil {
		res.Results = []nodeResult{res.nodeResult}
	}
	obs := 0
	var codes []string
	for _, r := range res.Results {
		if r.ErrorCode != "" {
			codes = append(codes, r.ErrorCode)
		} else if r.Observation != nil {
			obs++
		}
	}
	return obs, codes, nil
}

// legacy: the operator debug service, direct operator node probes and
// FabricQuery keep working while the service is on; their probes are now
// charged and permitted (A16).
func legacy(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	for _, c := range []struct {
		name     string
		args     []string
		wantObs  int
		wantCode string
	}{
		{"operator gateway BGPSummary", l.viaGateway(bgpSummary, "--family", ipv6), 3, ""},
		{"operator gateway Ping", l.viaGateway(ping, answer4), 3, ""},
		{"operator gateway Ping of a fabric loopback", l.viaGateway(ping, "fc00:0:a::1"), 0, reasonDestinationNotAllowed},
	} {
		time.Sleep(pace)
		out, err := l.operator(ctx, c.args...)
		obs, codes, perr := operatorResults(out)
		ev.Observed[c.name] = answers{Observations: obs, Errors: codes}
		if err != nil || perr != nil {
			t.Errorf("%s: %v %v: %s", c.name, err, perr, out)
			continue
		}
		if obs != c.wantObs || (c.wantCode != "" && (len(codes) != len(routers) || codes[0] != c.wantCode)) {
			t.Errorf("%s: %d observations, errors %v", c.name, obs, codes)
		}
	}

	// A direct operator probe of a fabric loopback, on each node: the
	// sidecar must obtain a permit from the gateway first.
	certs, err := l.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: certsSelector})
	if err != nil {
		t.Fatal(err)
	}
	frs, err := l.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: fabricRouterSelector})
	if err != nil {
		t.Fatal(err)
	}
	direct := map[string]any{}
	for _, fr := range frs.Items {
		certPod := certsPodOn(certs.Items, fr.Spec.NodeName)
		out, obs, codes, err := l.directProbe(ctx, fr, certPod)
		res := map[string]any{"answers": answers{Observations: obs, Errors: codes, Failed: err != nil}}
		if err != nil {
			res["output"] = strings.TrimSpace(out)
		}
		direct[fr.Spec.NodeName] = res
		// Only clientNode's host network reaches the cluster's DNS and the
		// gateway Service in the lab, so only its sidecar can ask for a
		// permit; the edge nodes' results are recorded, not judged.
		if fr.Spec.NodeName == clientNode && (err != nil || obs != 1) {
			t.Errorf("direct operator probe on %s: %v: %s", fr.Spec.NodeName, err, strings.TrimSpace(out))
		}
		if fr.Spec.NodeName == clientNode {
			direct[fr.Spec.NodeName+" after certs pod replacement"] = l.certsReplacement(ctx, t, fr, certPod)
		}
	}
	ev.Observed["direct operator probe"] = direct
	ev.Notes = append(ev.Notes, "Direct operator probes are judged on "+clientNode+" only: the lab's edge nodes' host "+
		"network reaches neither the cluster DNS server nor the gateway Service, so their sidecars cannot ask for a permit.")

	for _, c := range []struct{ name, query string }{
		{"FabricQuery BGPSummary", "{type: BGPSummary, addressFamily: IPv6}"},
		{"FabricQuery Ping", fmt.Sprintf("{type: Ping, target: %q, addressFamily: IPv4}", answer4)},
	} {
		name := fmt.Sprintf("%s%s-%d", projectPrefix, strings.ToLower(strings.Fields(c.name)[1]), time.Now().Unix())
		st, err := l.fabricQuery(ctx, name, c.query)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		reason, obs, errs := fqSummary(st)
		ev.Observed[c.name] = answers{Reason: reason, Observations: obs, Errors: errs}
		if reason != "Succeeded" || obs != len(routers) {
			t.Errorf("%s: %s with %d observations, errors %v", c.name, reason, obs, errs)
		}
	}
}

func certsPodOn(pods []corev1.Pod, node string) string {
	for _, c := range pods {
		if c.Spec.NodeName == node && c.DeletionTimestamp == nil {
			return c.Name
		}
	}
	return ""
}

// directProbe pings a fabric loopback directly on fr's node, as an
// operator; the sidecar must obtain a permit from the gateway first.
func (l *lab) directProbe(ctx context.Context, fr corev1.Pod, certPod string) (string, int, []string, error) {
	time.Sleep(pace)
	out, err := l.operator(ctx, "--node", fmt.Sprintf("[%s]:9344", fr.Status.HostIP), "--node-name", fr.Spec.NodeName,
		"--node-pod", certPod, "--timeout", "10s", ping, "fc00:0:7::1")
	obs, codes, perr := operatorResults(out)
	return out, obs, codes, errors.Join(err, perr)
}

// certsReplacement replaces the fabric-api-certs pod on fr's node, which
// changes the node's identity without restarting its sidecar, and requires
// a direct operator probe there to succeed within certsReplacementBound of
// the new pod turning Ready: the sidecar's permit requests must present
// the new certificate.
func (l *lab) certsReplacement(ctx context.Context, t *testing.T, fr corev1.Pod, old string) map[string]any {
	res := map[string]any{"bound": certsReplacementBound.String()}
	if err := l.cs.CoreV1().Pods(ns).Delete(ctx, old, metav1.DeleteOptions{}); err != nil {
		t.Errorf("delete certs pod %s: %v", old, err)
		return res
	}
	var replacement string
	var ready time.Time
	waitCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for replacement == "" {
		select {
		case <-waitCtx.Done():
			t.Errorf("certs pod on %s not replaced within 2m", fr.Spec.NodeName)
			return res
		case <-time.After(time.Second):
		}
		pods, err := l.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: certsSelector,
			FieldSelector: "spec.nodeName=" + fr.Spec.NodeName})
		if err != nil {
			continue
		}
		for _, p := range pods.Items {
			if p.Name != old && p.DeletionTimestamp == nil && podReady(p) {
				replacement, ready = p.Name, time.Now()
			}
		}
	}
	var out string
	var obs int
	var err error
	for {
		out, obs, _, err = l.directProbe(ctx, fr, replacement)
		if err == nil && obs == 1 {
			res["succeededAfter"] = time.Since(ready).Round(time.Millisecond).String()
			return res
		}
		if time.Since(ready) > certsReplacementBound {
			break
		}
	}
	res["output"] = strings.TrimSpace(out)
	t.Errorf("direct operator probe on %s still failing %s after its certs pod was replaced: %v: %s",
		fr.Spec.NodeName, certsReplacementBound, err, strings.TrimSpace(out))
	return res
}

// targetPattern matches the probe destinations the suite uses.
var targetPatterns = []string{answer4, answer6, "11.1.42.", "2c0f:42:"}

// confidentiality: no service target or result reaches a routine log line
// or a metric label, and no metric label carries a project (A15).
func confidentiality(ctx context.Context, t *testing.T, l *lab, ev *evidence, since time.Time) {
	gws, err := l.gatewayPods(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string][]string{}
	scan := func(where, text string, patterns []string, levelFilter bool) {
		for line := range strings.SplitSeq(text, "\n") {
			if levelFilter && (strings.Contains(line, `"level":"DEBUG"`) || strings.Contains(line, "level=DEBUG")) {
				continue
			}
			// Operator and FabricQuery traffic may name its own targets;
			// only service request lines are bound by the contract.
			if levelFilter && !strings.Contains(line, "Looking Glass") && !strings.Contains(line, "/service/") {
				continue
			}
			for _, p := range patterns {
				if strings.Contains(line, p) {
					found[where] = append(found[where], line)
					break
				}
			}
		}
	}
	for _, p := range gws {
		logs, err := l.podLogs(ctx, p.Name, "gateway", since)
		if err != nil {
			t.Errorf("logs of %s: %v", p.Name, err)
			continue
		}
		scan(p.Name+" log", logs, targetPatterns, true)
		text, err := l.gatewayMetrics(ctx, p)
		if err != nil {
			t.Errorf("metrics of %s: %v", p.Name, err)
			continue
		}
		scan(p.Name+" metrics", text, append([]string{projectPrefix}, targetPatterns...), false)
	}
	nm, err := l.nodeMetrics(ctx)
	if err != nil {
		t.Error(err)
	}
	for node, text := range nm {
		scan(node+" sidecar metrics", text, append([]string{projectPrefix}, targetPatterns...), false)
	}
	frs, err := l.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: fabricRouterSelector})
	if err != nil {
		t.Fatal(err)
	}
	for _, fr := range frs.Items {
		logs, err := l.podLogs(ctx, fr.Name, "fabric-api", since)
		if err != nil {
			t.Errorf("logs of %s: %v", fr.Name, err)
			continue
		}
		scan(fr.Spec.NodeName+" sidecar log", logs, append([]string{projectPrefix}, targetPatterns...), true)
	}
	ev.Observed["leaks"] = found
	for where, lines := range found {
		t.Errorf("%s: %d lines name a service target or project, e.g. %s", where, len(lines), lines[0])
	}
}
