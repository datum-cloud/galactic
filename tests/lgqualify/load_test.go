// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package lgqualify_test

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"
)

// spread is the time between the first and last start in recs, in
// seconds, plus allowance for the hop from the client to the leader.
func spread(recs []Record) float64 {
	if len(recs) == 0 {
		return 0
	}
	lo, hi := recs[0].StartedAt, recs[0].StartedAt
	for _, r := range recs {
		if r.StartedAt.Before(lo) {
			lo = r.StartedAt
		}
		if r.StartedAt.After(hi) {
			hi = r.StartedAt
		}
	}
	return hi.Sub(lo).Seconds() + 0.5
}

// countStatuses counts recs by "<code>/<reason>".
func countStatuses(recs []Record) map[string]int {
	out := map[string]int{}
	for _, r := range recs {
		out[r.status()]++
	}
	return out
}

// checkThrottled checks a refused record carries the throttling contract:
// scope, execution_started=false and a positive retry delay of at most
// maxDelay.
func checkThrottled(t *testing.T, name string, r Record, scope string, maxDelay time.Duration) {
	t.Helper()
	md := r.Status.Metadata
	d := time.Duration(r.Status.RetryDelayMS) * time.Millisecond
	if r.Status.Code != "ResourceExhausted" || r.Status.Reason != "Throttled" || md["scope"] != scope ||
		md["execution_started"] != "false" || d <= 0 || d > maxDelay || r.Events != 0 {
		t.Errorf("%s: refusal %s scope=%q execution_started=%q retry=%s events=%d, want Throttled scope=%s retry in (0, %s]",
			name, r.status(), md["scope"], md["execution_started"], d, r.Events, scope, maxDelay)
	}
}

// bursts: the cell and project request buckets admit at most their burst
// plus refill, and refuse the rest with retry guidance (A8).
func bursts(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	q := query{Type: bgpSummary, Family: ipv4}
	projects := make([]string, 12)
	for i := range projects {
		projects[i] = l.project()
	}
	settle()
	recs, _, err := l.load(ctx, spec{Groups: []group{{
		Name: "cell-burst", Count: 12, Concurrency: 12, Projects: projects,
		Options: options{Query: q, Nodes: []string{routers[0]}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	l.saveRecords("bursts-cell", recs)
	admitted := 0
	// A token shortage is advised as the deficit over the rate, at most one
	// token's worth: 500 ms at 2/s, rounded up to the millisecond.
	maxDelay := time.Duration(math.Ceil(1000/requestCellRate)+1) * time.Millisecond
	for _, r := range recs {
		if r.ok() {
			admitted++
			expectDelivered(t, "cell burst", r, "Succeeded")
			continue
		}
		checkThrottled(t, "cell burst", r, "cell", maxDelay)
	}
	limit := requestCellBurst + int(math.Ceil(requestCellRate*spread(recs)))
	ev.Thresholds = map[string]any{"cellBurstAdmittedMax": limit, "cellRetryMaxMs": maxDelay.Milliseconds()}
	ev.Observed["cell burst"] = countStatuses(recs)
	ev.Observed["cell burst admitted"] = admitted
	ev.Observed["cell burst spread s"] = spread(recs)
	if admitted > limit || admitted == len(recs) {
		t.Errorf("cell burst: %d of %d admitted, want at most %d and at least one refusal", admitted, len(recs), limit)
	}

	settle()
	project := l.project()
	recs, _, err = l.load(ctx, spec{Groups: []group{{
		Name: "project-burst", Count: 5, Concurrency: 5, Projects: []string{project},
		Options: options{Query: q, Nodes: []string{routers[0]}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	l.saveRecords("bursts-project", recs)
	admitted = 0
	for _, r := range recs {
		if r.ok() {
			admitted++
			continue
		}
		// One project token is 5 s at 0.2/s.
		checkThrottled(t, "project burst", r, "project", time.Duration(1000/requestProjectRate+1)*time.Millisecond)
	}
	limit = requestProjectBurst + int(math.Floor(requestProjectRate*spread(recs)))
	ev.Thresholds["projectBurstAdmittedMax"] = limit
	ev.Observed["project burst"] = countStatuses(recs)
	ev.Observed["project burst admitted"] = admitted
	if admitted > limit || admitted == 0 {
		t.Errorf("project burst: %d of %d admitted, want 1 to %d", admitted, len(recs), limit)
	}
}

// fairness: a project sending faster than its rate is limited to its own
// bucket and never delays or refuses a project within its rate; a project
// holding its two node slots does not delay another project's routers
// (A8).
func fairness(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	const duration = 60 * time.Second
	heavy, light := l.project(), l.project()
	opts := options{Query: query{Type: bgpSummary, Family: ipv4}, Nodes: []string{routers[0]}}
	settle()
	recs, sums, err := l.load(ctx, spec{Groups: []group{
		{
			Name: "over-rate", Count: int(duration / time.Second), Concurrency: 4, Interval: "1s",
			Projects: []string{heavy}, Options: opts,
		},
		{
			Name: "within-rate", Count: int(duration / (5 * time.Second)), Concurrency: 1, Interval: "5s",
			StartAfter: "500ms", Projects: []string{light}, Options: opts,
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	l.saveRecords("fairness-rate", recs)
	var over, within []Record
	for _, r := range recs {
		if r.Group == "over-rate" {
			over = append(over, r)
		} else {
			within = append(within, r)
		}
	}
	overAdmitted := 0
	for _, r := range over {
		if r.ok() {
			overAdmitted++
		} else if r.Status.Metadata["scope"] != "project" {
			t.Errorf("over-rate project refused by scope %q (%s), want project", r.Status.Metadata["scope"], r.status())
		}
	}
	maxOver := requestProjectBurst + int(requestProjectRate*spread(over)) + 1
	minOver := int(requestProjectRate*spread(over)) - 1
	ev.Thresholds = map[string]any{"overRateAdmittedMax": maxOver, "overRateAdmittedMin": minOver, "withinRateRefusals": 0}
	ev.Observed["rate"] = map[string]any{
		"overRate": countStatuses(over), "withinRate": countStatuses(within), "summaries": sums,
	}
	if overAdmitted > maxOver || overAdmitted < minOver {
		t.Errorf("over-rate project: %d admitted, want %d to %d", overAdmitted, minOver, maxOver)
	}
	for _, r := range within {
		if !r.ok() || !r.Stream.Delivered {
			t.Errorf("within-rate project refused or undelivered while another project exceeded its rate: %s", r.status())
		}
	}

	// Slots: one project's three-router traceroute holds its two slots for
	// about 20 s; other projects' probes meanwhile run at once.
	settle()
	holder := l.project()
	target := l.sinkHost(4)
	holdCh := make(chan Record, 1)
	go func() {
		r, _ := l.run(ctx, idService, fProject, holder, fType, traceroute, fTarget, target, fExpires, "60s")
		holdCh <- r
	}()
	time.Sleep(2 * time.Second)
	others := make([]Record, 0, 3)
	for range 3 {
		others = append(others, mustRun(ctx, t, l, idService, fProject, l.project(), fType, ping, fTarget, answer4))
	}
	held := <-holdCh
	l.saveRecords("fairness-slots", append([]Record{held}, others...))
	ev.Observed["slot holder"] = brief(held)
	for i, r := range others {
		ev.Observed[fmt.Sprintf("probe beside the slot holder %d", i)] = brief(r)
	}
	checkQueueTimeout(t, "slot holder", held, ev)
	for _, r := range others {
		expectDelivered(t, "probe beside a slot holder", r, "Succeeded")
		if r.Timing.CompleteMS > 5000 {
			t.Errorf("probe beside a slot holder took %.0f ms", r.Timing.CompleteMS)
		}
	}
}

// destinationBudget: traceroutes from many projects to one host drain its
// destination bucket; refusals name the destination scope, reservations
// stay within B + rT and emissions within B + r(T + 32); operator and
// FabricQuery probes to the same host are charged to the same bucket and
// refused with it (A9, A10).
func destinationBudget(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	gws, err := l.gatewayPods(ctx)
	if err != nil {
		t.Fatal(err)
	}
	refusals := func() map[string]float64 {
		out := map[string]float64{}
		for _, p := range gws {
			text, err := l.gatewayMetrics(ctx, p)
			if err != nil {
				continue
			}
			for _, class := range []string{"service", "operator", "fabricquery"} {
				v, _ := metricValue(text, "fabric_api_gateway_admission_refusals_total",
					`class="`+class+`"`, `scope="destination"`)
				out[class] += v
				c, _ := metricValue(text, "fabric_api_gateway_probe_packets_charged_total", `class="`+class+`"`)
				out["charged/"+class] += c
			}
		}
		return out
	}
	if err := watch(answer4); err != nil {
		t.Fatal(err)
	}
	cnt := startCounter()
	before := refusals()
	settle()

	// 60 two-router traceroutes at the cell's request rate reserve 80
	// packets/s against the host's 20/s and burst 640 for 30 s.
	projects := make([]string, 60)
	for i := range projects {
		projects[i] = l.project()
	}
	loadDone := make(chan []Record, 1)
	loadStart := time.Now()
	go func() {
		recs, _, err := l.load(ctx, spec{Groups: []group{{
			Name: "drain", Count: len(projects), Concurrency: 8, Interval: "500ms", Projects: projects,
			Options: options{Query: query{Type: traceroute, Target: answer4}, Nodes: []string{routers[0], routers[1]}},
		}}})
		if err != nil {
			t.Error(err)
		}
		loadDone <- recs
	}()

	// Once the drain has emptied the host bucket, other callers probe the
	// same host in turn while it continues.
	time.Sleep(10 * time.Second)
	cross := map[string]any{}
	for i := range 3 {
		out, err := l.operator(ctx, l.viaGateway(traceroute, answer4)...)
		obs, codes, _ := operatorResults(out)
		cross[fmt.Sprintf("operator gateway traceroute %d", i)] = answers{
			Observations: obs, Errors: codes, Failed: err != nil,
		}
		st, err := l.fabricQuery(ctx, fmt.Sprintf("lgq-budget-%d-%d", time.Now().Unix(), i),
			fmt.Sprintf("{type: Traceroute, target: %q, addressFamily: IPv4}", answer4))
		if err == nil {
			reason, obs, errs := fqSummary(st)
			cross[fmt.Sprintf("FabricQuery traceroute %d", i)] = answers{Reason: reason, Observations: obs, Errors: errs}
		} else {
			cross[fmt.Sprintf("FabricQuery traceroute %d", i)] = err.Error()
		}
	}
	recs := <-loadDone
	loadEnd := time.Now()
	// Emissions continue up to 32 s after the last dispatch.
	time.Sleep(5 * time.Second)
	samples := cnt.close()
	after := refusals()
	l.saveRecords("destination-budget", recs)

	destRefused, dispatched := 0, 0
	for _, r := range recs {
		for _, o := range r.Stream.Outcomes {
			switch {
			case o.Result == failure && o.Reason == "Throttled":
				if o.Scope != "destination" {
					t.Errorf("drain: router throttled with scope %q, want destination", o.Scope)
				}
				destRefused++
			case o.Result == observation || (o.Result == failure && o.Reason != "QueueTimeout"):
				dispatched++
			}
		}
		if r.Status.Code == "ResourceExhausted" && r.Status.Metadata["scope"] == "destination" {
			destRefused++
		}
	}
	T := loadEnd.Sub(loadStart).Seconds()
	reservedMax := packetHostBurst + packetHostRate*T
	excess, wFrom, wTo, wCount := worstWindow(samples, []string{answer4}, packetHostBurst, packetHostRate)
	delta := map[string]float64{}
	for k, v := range after {
		delta[k] = v - before[k]
	}
	ev.Thresholds = map[string]any{
		"reservedPacketsMax": reservedMax, "emissionBound": "640 + 20(T+32) per window",
		"crossCallerRefusals": "operator and fabricquery destination refusals > 0",
	}
	ev.Observed["drain"] = map[string]any{
		"statuses": countStatuses(recs), "routersDispatched": dispatched, "routersThrottledDestination": destRefused,
		"reservedPackets": dispatched * traceroutePackets, "durationS": T,
	}
	ev.Observed["cross caller"] = cross
	ev.Observed["metric deltas"] = delta
	ev.Observed["emission"] = map[string]any{
		"totalPackets":      between(samples, answer4, loadStart.Add(-time.Second), time.Now()),
		"worstWindowExcess": excess, "worstWindowCount": wCount, "worstWindowS": wTo.Sub(wFrom).Seconds(),
	}
	if destRefused == 0 {
		t.Error("drain: no router was throttled by the destination budget")
	}
	if float64(dispatched*traceroutePackets) > reservedMax {
		t.Errorf("drain: %d packets reserved in %.1f s, over the host bucket's %.0f",
			dispatched*traceroutePackets, T, reservedMax)
	}
	if excess > 0 {
		t.Errorf("emission: %d packets in %s, over B + r(T + 32) by %.0f", wCount, wTo.Sub(wFrom), excess)
	}
	for _, class := range []string{"operator", "fabricquery"} {
		if delta[class] <= 0 {
			t.Errorf("no %s probe was refused by the destination budget the service drained", class)
		}
	}
	ev.Notes = append(ev.Notes, fmt.Sprintf("Emissions are bounded far below the bucket by node slots (8 per cell, 2 per "+
		"project) and probe duration in a 3-router cell; the emission check holds with margin %.0f packets, "+
		"it is not driven to its limit.", -excess))
}
