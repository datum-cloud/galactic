// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package lgqualify_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"os/exec"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The convergence trial: dfw-worker's IPv6 iBGP session to its edge node
// dfw-worker2, hard reset, timed until it is Established with its accepted
// prefixes back. Each router sees it as its own session to the other's
// link address.
const (
	trialRouter     = "dfw-worker"
	trialPeer       = "2001:db8:1:10::1"
	trialPeerRouter = "dfw-worker2"
	trialRouterAddr = "2001:db8:1:10::2"
	trialFamily     = "ipv6Unicast"
	trialBlock      = 10
	trialsEach      = 40
)

// trialScript runs in the router's frr container. It prints the
// convergence time in milliseconds, measured on that container's clock.
const trialScript = `
import json, subprocess, sys, time
peer, family = sys.argv[1], sys.argv[2]
def state():
    out = subprocess.run(["vtysh", "-c", "show bgp neighbors %s json" % peer], capture_output=True, text=True).stdout
    try:
        n = json.loads(out)[peer]
    except Exception:
        return None, None, None
    return (n.get("bgpState"), n.get("addressFamilyInfo", {}).get(family, {}).get("acceptedPrefixCounter"),
            n.get("bgpTimerUpMsec"))
st, base, _ = state()
if st != "Established" or not base:
    print(json.dumps({"error": "not established before the reset", "state": st}))
    sys.exit(0)
t0 = time.monotonic()
subprocess.run(["vtysh", "-c", "clear bgp %s" % peer], capture_output=True)
# The session counts as reset once seen down, or Established for less time
# than has passed since the reset.
down = False
while time.monotonic() - t0 < 60:
    st, n, up = state()
    elapsed = (time.monotonic() - t0) * 1000
    if st != "Established" or (up is not None and up < elapsed):
        down = True
    if down and st == "Established" and n is not None and n >= base:
        print(json.dumps({"ms": (time.monotonic() - t0) * 1000, "prefixes": base}))
        sys.exit(0)
    time.sleep(0.02)
print(json.dumps({"error": "did not converge in 60 s", "down": down}))
`

// sessions is a router's BGP peers' uptime and accepted prefixes.
const sessionsScript = `
import json, subprocess
out = subprocess.run(["vtysh", "-c", "show bgp summary json"], capture_output=True, text=True).stdout
dec, i, res = json.JSONDecoder(), 0, {}
while i < len(out):
    while i < len(out) and out[i].isspace():
        i += 1
    if i >= len(out):
        break
    obj, i = dec.raw_decode(out, i)
    for af, v in obj.items():
        for peer, p in (v.get("peers") or {}).items():
            res[af + "/" + peer] = {
                "state": p.get("state"), "uptimeMs": p.get("peerUptimeMsec"), "pfx": p.get("pfxRcd"),
            }
print(json.dumps(res))
`

type session struct {
	State    string `json:"state"`
	UptimeMS int64  `json:"uptimeMs"`
	Pfx      int64  `json:"pfx"`
}

// frrPods returns each dfw router's fabric-router pod.
func (l *lab) frrPods(ctx context.Context) (map[string]corev1.Pod, error) {
	pods, err := l.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: fabricRouterSelector})
	if err != nil {
		return nil, err
	}
	out := map[string]corev1.Pod{}
	for _, p := range pods.Items {
		out[p.Spec.NodeName] = p
	}
	return out, nil
}

func (l *lab) frrPython(ctx context.Context, pod string, script string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "kubectl", append([]string{"--kubeconfig", l.kubeconfig, "-n", ns, "exec", pod,
		"-c", "frr", "--", "python3", "-c", script}, args...)...)
	return cmd.Output()
}

// sessions returns every dfw router's sessions.
func (l *lab) sessions(ctx context.Context, pods map[string]corev1.Pod) (map[string]session, error) {
	out := map[string]session{}
	for node, p := range pods {
		raw, err := l.frrPython(ctx, p.Name, sessionsScript)
		if err != nil {
			return nil, fmt.Errorf("%s sessions: %w", node, err)
		}
		var m map[string]session
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		for k, v := range m {
			out[node+"/"+k] = v
		}
	}
	return out, nil
}

// trial resets the session once and returns its convergence time.
func (l *lab) trial(ctx context.Context, pod string) (float64, error) {
	raw, err := l.frrPython(ctx, pod, trialScript, trialPeer, trialFamily)
	if err != nil {
		return 0, err
	}
	var res struct {
		MS    float64 `json:"ms"`
		Error string  `json:"error"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, err
	}
	if res.Error != "" {
		return 0, fmt.Errorf("trial: %s", res.Error)
	}
	return res.MS, nil
}

// backgroundLoad starts a service workload on clientNode at the cell's
// admissible request rate and returns a function that stops it.
func (l *lab) backgroundLoad(ctx context.Context, tag string) (func() []Record, error) {
	// Each group's 20 projects stay within their own 0.2/s; together the
	// groups ask 2 requests/s of the cell.
	mix := func(name, start string, q query) group {
		projects := make([]string, 20)
		for i := range projects {
			projects[i] = l.project()
		}
		return group{
			Name: name, Count: 1000, Concurrency: 8, Interval: "2s", StartAfter: start,
			Projects: projects, Options: options{Query: q},
		}
	}
	workload := spec{Groups: []group{
		mix("lookup", "0s", query{Type: routeLookup, Target: answer6}),
		mix("summary", "500ms", query{Type: bgpSummary, Family: ipv6}),
		mix("ping", "1s", query{Type: ping, Target: answer4}),
		mix("traceroute", "1500ms", query{Type: traceroute, Target: answer6}),
	}}
	done := make(chan []Record, 1)
	path := fmt.Sprintf("%s/spec-%s.json", clientDir, tag)
	data, _ := json.Marshal(workload)
	if err := clientWrite(path, data, 0o600); err != nil {
		return nil, err
	}
	go func() {
		lines, _ := l.lgc(context.WithoutCancel(ctx), idService, "load", "--spec", path)
		var recs []Record
		for _, line := range lines {
			var r Record
			if json.Unmarshal(line, &r) == nil && r.RequestID != "" {
				recs = append(recs, r)
			}
		}
		done <- recs
	}()
	return func() []Record {
		// SIGINT ends the client's workload and prints what finished.
		_, _ = nodeExec(clientNode, "pkill", "-INT", "-f", path)
		select {
		case recs := <-done:
			return recs
		case <-time.After(90 * time.Second):
			return nil
		}
	}, nil
}

// p95 is the nearest-rank 95th percentile.
func p95(v []float64) float64 {
	s := slices.Clone(v)
	slices.Sort(s)
	i := int(math.Ceil(0.95*float64(len(s)))) - 1
	return s[max(0, i)]
}

// bootstrapHalfWidth is half the width of a bootstrap 95 % interval of
// v's p95, from a fixed seed.
func bootstrapHalfWidth(v []float64) float64 {
	rng := rand.New(rand.NewPCG(1048, 1048))
	est := make([]float64, 2000)
	sample := make([]float64, len(v))
	for i := range est {
		for j := range sample {
			sample[j] = v[rng.IntN(len(v))]
		}
		est[i] = p95(sample)
	}
	slices.Sort(est)
	return (est[int(0.975*float64(len(est)))-1] - est[int(0.025*float64(len(est)))]) / 2
}

// routingImpact: diagnostics at the cell's admissible rate neither reset a
// session nor slow the control plane's convergence measurably (contract
// "Acceptance matrix and evidence", routing-impact gate).
func routingImpact(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	pods, err := l.frrPods(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pod := pods[trialRouter].Name
	var control, loaded []float64
	var loadRecs []Record
	resets := map[string]any{}
	for block := 0; len(control) < trialsEach || len(loaded) < trialsEach; block++ {
		isLoaded := block%2 == 1
		var stop func() []Record
		var before map[string]session
		blockStart := time.Now()
		if isLoaded {
			if stop, err = l.backgroundLoad(ctx, fmt.Sprintf("routing-%d", block)); err != nil {
				t.Fatal(err)
			}
			time.Sleep(5 * time.Second)
			if before, err = l.sessions(ctx, pods); err != nil {
				t.Fatal(err)
			}
			blockStart = time.Now()
		}
		for range trialBlock {
			ms, err := l.trial(ctx, pod)
			if err != nil {
				t.Fatalf("block %d: %v", block, err)
			}
			if isLoaded {
				loaded = append(loaded, ms)
			} else {
				control = append(control, ms)
			}
			time.Sleep(3 * time.Second)
		}
		if isLoaded {
			after, err := l.sessions(ctx, pods)
			if err != nil {
				t.Fatal(err)
			}
			elapsed := time.Since(blockStart).Milliseconds()
			for k, b := range before {
				if k == trialRouter+"/"+trialFamily+"/"+trialPeer || k == trialPeerRouter+"/"+trialFamily+"/"+trialRouterAddr {
					continue
				}
				a, ok := after[k]
				if !ok || a.State != "Established" || a.UptimeMS < b.UptimeMS+elapsed-5000 || a.Pfx < b.Pfx {
					resets[fmt.Sprintf("block %d %s", block, k)] = map[string]any{"before": b, "after": a}
				}
			}
			loadRecs = append(loadRecs, stop()...)
		}
	}
	l.saveRecords("routing-load", loadRecs)
	cp, lp, hw := p95(control), p95(loaded), bootstrapHalfWidth(control)
	ev.Thresholds = map[string]any{"loadedP95MaxRatio": convergenceRatio, "trialsEach": trialsEach,
		"inconclusiveIfControlP95HalfWidthOver": 0.10}
	ev.Observed["controlMs"] = control
	ev.Observed["loadedMs"] = loaded
	ev.Observed["controlP95Ms"] = cp
	ev.Observed["loadedP95Ms"] = lp
	ev.Observed["ratio"] = lp / cp
	ev.Observed["controlP95HalfWidthMs"] = hw
	ev.Observed["unexpected session changes"] = resets
	ev.Observed["load"] = countStatuses(loadRecs)
	if len(resets) > 0 {
		t.Errorf("%d sessions reset or lost prefixes under diagnostic load", len(resets))
	}
	if len(loadRecs) == 0 {
		t.Error("the background load recorded no request")
	}
	if hw > 0.10*cp {
		ev.Notes = append(ev.Notes, fmt.Sprintf("inconclusive: the control p95's 95 %% bootstrap half-width is %.0f ms, "+
			"%.0f %% of its p95 %.0f ms, so a 10 %% regression cannot be distinguished", hw, 100*hw/cp, cp))
		t.Errorf("routing impact inconclusive: control variability (±%.0f ms on a %.0f ms p95) exceeds 10 %%", hw, cp)
		return
	}
	if lp > convergenceRatio*cp {
		t.Errorf("loaded convergence p95 %.0f ms exceeds %.2f × control p95 %.0f ms", lp, convergenceRatio, cp)
	}
}
