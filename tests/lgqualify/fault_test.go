// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package lgqualify_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// twoRouters selects two routers, so one project's traceroute holds both
// of its node slots and none of its routers queues.
var twoRouters = routers[0] + "," + routers[1]

// runAsync runs one diagnostic in the background.
func (l *lab) runAsync(ctx context.Context, args ...string) <-chan Record {
	ch := make(chan Record, 1)
	go func() {
		r, err := l.run(ctx, idService, args...)
		if err != nil {
			r.Status.Code, r.Status.Reason = "ClientError", err.Error()
		}
		ch <- r
	}()
	return ch
}

// leaderPod returns the gateway pod holding the lease.
func (l *lab) leaderPod(ctx context.Context) (corev1.Pod, string, error) {
	name, holder, err := l.leader(ctx)
	if err != nil {
		return corev1.Pod{}, "", err
	}
	p, err := l.cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return corev1.Pod{}, "", err
	}
	return *p, holder, nil
}

// gatewayPID returns the host PID of pod's gateway process, through the
// node's CRI.
// sandboxPID returns the PID of pod's sandbox, whose network namespace is
// the pod's for its whole life.
func sandboxPID(pod corev1.Pod) (int, error) {
	sandbox, err := nodeExec(pod.Spec.NodeName, "crictl", "pods",
		"--name", pod.Name, "--namespace", ns, "-q", "--state", "ready")
	if err != nil {
		return 0, err
	}
	sandbox = strings.TrimSpace(strings.Split(strings.TrimSpace(sandbox), "\n")[0])
	out, err := nodeExec(pod.Spec.NodeName, "crictl", "inspectp",
		"-o", "go-template", "--template", "{{.info.pid}}", sandbox)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(out))
}

func gatewayPID(pod corev1.Pod) (int, error) {
	sandbox, err := nodeExec(pod.Spec.NodeName, "crictl", "pods",
		"--name", pod.Name, "--namespace", ns, "-q", "--state", "ready")
	if err != nil {
		return 0, err
	}
	sandbox = strings.TrimSpace(strings.Split(strings.TrimSpace(sandbox), "\n")[0])
	cid, err := nodeExec(pod.Spec.NodeName, "crictl", "ps",
		"--pod", sandbox, "--name", "gateway", "-q", "--state", "running")
	if err != nil {
		return 0, err
	}
	cid = strings.TrimSpace(strings.Split(strings.TrimSpace(cid), "\n")[0])
	out, err := nodeExec(pod.Spec.NodeName, "crictl", "inspect", "-o", "go-template", "--template", "{{.info.pid}}", cid)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(out))
}

// gauge polls a gateway pod's metric every sampleEvery until cond holds
// or timeout, returning when it held.
func (l *lab) gauge(
	ctx context.Context, pod corev1.Pod, timeout time.Duration, cond func(text string) bool,
) (time.Time, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if text, err := l.gatewayMetrics(ctx, pod); err == nil && cond(text) {
			return time.Now(), true
		}
		time.Sleep(sampleEvery)
	}
	return time.Time{}, false
}

// peakDuring returns the largest value of a gateway pod's gauge while fn
// runs.
func (l *lab) peakDuring(ctx context.Context, pod corev1.Pod, name string, fn func()) float64 {
	stop := make(chan struct{})
	peak := make(chan float64, 1)
	go func() {
		best := 0.0
		for {
			if text, err := l.gatewayMetrics(ctx, pod); err == nil {
				if v, ok := metricValue(text, name); ok {
					best = max(best, v)
				}
			}
			select {
			case <-stop:
				peak <- best
				return
			case <-time.After(sampleEvery):
			}
		}
	}()
	fn()
	close(stop)
	return <-peak
}

func gaugeAtMost(name string, limit float64) func(string) bool {
	return func(text string) bool {
		v, ok := metricValue(text, name)
		return ok && v <= limit
	}
}

// at is r's offset ms as a wall time.
func at(r Record, ms float64) time.Time {
	return r.StartedAt.Add(time.Duration(ms * float64(time.Millisecond)))
}

// judgeStop checks packets toward dst stopped by bound and records it.
func judgeStop(
	t *testing.T, ev *evidence, name string, samples []sample, dst string, origin time.Time, bound time.Duration,
) {
	t.Helper()
	stop, total := lastIncrease(samples, dst)
	after := stop.Sub(origin)
	// A negative stop is the last probe before the trigger: probes toward
	// the sink go about 1 s apart, under every bound judged here, so a job
	// still running would have sent another inside the bound.
	ev.Observed[name] = map[string]any{"packets": total, "stoppedAfter": after.String(), "bound": bound.String()}
	switch {
	case total == 0:
		t.Errorf("%s: no probe packet was sent toward %s, so nothing was stopped", name, dst)
	case after > bound+sampleEvery:
		t.Errorf("%s: packets stopped %s after the trigger, bound %s", name, after, bound)
	}
}

// cancellation: a cancelled request's running and queued router jobs stop
// within 2 s of the cancellation (A12).
func cancellation(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	var r Record
	leader, _, err := l.leaderPod(ctx)
	if err != nil {
		t.Fatal(err)
	}
	running, queued := l.sinkHost(6), l.sinkHost(4)
	if err := watch(running, queued); err != nil {
		t.Fatal(err)
	}
	cnt := startCounter()
	// No gauge counts service router jobs in their slots; the leader's live
	// streams, which hold a request's jobs and buffers, stand in for them.
	peak := l.peakDuring(ctx, leader, "fabric_api_gateway_service_streams", func() {
		r = mustRun(ctx, t, l, idService, fProject, l.project(), fType, traceroute, fTarget, running,
			fNodes, twoRouters, fExpires, "60s", "-cancel-after", "4s")
	})
	ev.Observed["running: live streams before cancellation"] = peak
	if peak < 1 {
		t.Errorf("running: %v live streams before the cancellation, want 1", peak)
	}
	cancelAt := at(r, r.Timing.CancelMS)
	idle, ok := l.gauge(ctx, leader, 5*time.Second, gaugeAtMost("fabric_api_gateway_service_streams", 0))
	ev.Observed["running: stream"] = brief(r)
	ev.Observed["running: stream released after"] = idle.Sub(cancelAt).String()
	if !ok || idle.Sub(cancelAt) > stopBound+sampleEvery {
		t.Errorf("running: leader's live stream not released within %s of the cancellation", stopBound)
	}

	// Three routers from one project: two run, one queues for a slot.
	peak = l.peakDuring(ctx, leader, "fabric_api_gateway_queue_depth", func() {
		r = mustRun(ctx, t, l, idService, fProject, l.project(), fType, traceroute, fTarget, queued,
			fExpires, "60s", "-cancel-after", "3s")
	})
	ev.Observed["queued: queue depth before cancellation"] = peak
	if peak < 1 {
		t.Errorf("queued: queue depth %v before the cancellation, want a queued router", peak)
	}
	queuedCancel := at(r, r.Timing.CancelMS)
	empty, ok := l.gauge(ctx, leader, 5*time.Second, gaugeAtMost("fabric_api_gateway_queue_depth", 0))
	ev.Observed["queued: queue emptied after"] = empty.Sub(queuedCancel).String()
	if !ok || empty.Sub(queuedCancel) > stopBound+sampleEvery {
		t.Errorf("queued: leader's queue not emptied within %s of the cancellation", stopBound)
	}
	time.Sleep(5 * time.Second)
	samples := cnt.close()
	judgeStop(t, ev, "running: probes", samples, running, cancelAt, stopBound)
	judgeStop(t, ev, "queued: probes", samples, queued, queuedCancel, stopBound)
	sent := 0
	for _, n := range routers {
		if nodeTotal(samples, n, queued) > 0 {
			sent++
		}
	}
	ev.Observed["queued: routers that probed"] = sent
	if sent != 2 {
		t.Errorf("queued: %d routers probed, want the 2 holding slots", sent)
	}
	ev.Notes = append(ev.Notes, "Cancellation during discovery is not timed: discovery takes milliseconds, below "+
		"what an external client can aim a cancellation at.")
}

// deadline: a request whose expiry passes mid-execution ends with
// DeadlineExceeded, and its probes stop within 2 s of expiry (A12).
func deadline(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	target := l.sinkHost(4)
	if err := watch(target); err != nil {
		t.Fatal(err)
	}
	cnt := startCounter()
	const expiresIn = 6 * time.Second
	r := mustRun(ctx, t, l, idService, fProject, l.project(), fType, traceroute, fTarget, target,
		fNodes, twoRouters, fExpires, expiresIn.String(), "-deadline", "12s")
	time.Sleep(4 * time.Second)
	samples := cnt.close()
	ev.Observed["stream"] = brief(r)
	ev.Observed["stream ended after"] = time.Duration(r.Timing.EndMS * float64(time.Millisecond)).String()
	// At expires_at the deadline no longer allows delivery, so the stream
	// may end with complete DeadlineExceeded or, as the contract allows,
	// with the transport's DEADLINE_EXCEEDED and the routers unknown.
	switch {
	case r.Stream.Reason == "DeadlineExceeded" && r.Stream.Delivered:
	case r.Status.Code == "DeadlineExceeded" && r.Timing.SnapshotMS >= 0 && r.Stream.Complete == nil:
	default:
		t.Errorf("expired request: %s complete %q, want DeadlineExceeded", r.status(), r.Stream.Reason)
	}
	end := time.Duration(r.Timing.EndMS * float64(time.Millisecond))
	if end < expiresIn-200*time.Millisecond || end > expiresIn+time.Second {
		t.Errorf("expired request ended %s after it started, want about %s", end, expiresIn)
	}
	judgeStop(t, ev, "probes", samples, target, r.StartedAt.Add(expiresIn), stopBound)
}

// serviceSwitch: turning the switch off cancels running requests within
// 2 s of the read, refuses new ones, leaves operator diagnostics working,
// and turning it on admits again at once (A12, A15).
func serviceSwitch(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	t.Cleanup(func() { _ = l.setSwitch(context.Background(), "enabled") })
	target := l.sinkHost(6)
	if err := watch(target); err != nil {
		t.Fatal(err)
	}
	cnt := startCounter()
	running := l.runAsync(ctx, fProject, l.project(), fType, traceroute, fTarget, target,
		fNodes, twoRouters, fExpires, "60s")
	time.Sleep(3 * time.Second)
	offAt := time.Now()
	if err := l.setSwitch(ctx, "disabled"); err != nil {
		t.Fatal(err)
	}
	r := <-running
	ev.Observed["running"] = brief(r)
	expectDelivered(t, "running request", r, "Cancelled")
	if end := r.endAt().Sub(offAt); end > switchRead+stopBound+500*time.Millisecond {
		t.Errorf("running request ended %s after the switch, bound %s", end, switchRead+stopBound)
	}
	time.Sleep(2 * time.Second)
	samples := cnt.close()
	judgeStop(t, ev, "probes", samples, target, offAt, switchRead+stopBound)

	r = mustRun(ctx, t, l, idService, fProject, l.project(), fType, bgpSummary, fFamily, ipv4)
	expectRefused(t, "new request while off", r, codeFailedPrecondition, "ServiceDisabled")
	ev.Observed["new request while off"] = brief(r)
	lines, err := l.lgc(ctx, idService, "capabilities")
	if err != nil {
		t.Fatal(err)
	}
	var caps struct {
		Capabilities struct {
			Enabled bool `json:"enabled"`
		} `json:"capabilities"`
	}
	_ = json.Unmarshal(lines[0], &caps)
	ev.Observed["capabilities enabled while off"] = caps.Capabilities.Enabled
	if caps.Capabilities.Enabled {
		t.Error("capabilities report enabled while the switch is off")
	}
	out, err := l.operator(ctx, l.viaGateway(bgpSummary, "--family", ipv4)...)
	obs, codes, _ := operatorResults(out)
	ev.Observed["operator while off"] = answers{Observations: obs, Errors: codes}
	if err != nil || obs != len(routers) {
		t.Errorf("operator BGPSummary while the service is off: %d observations, %v: %s", obs, err, out)
	}

	onAt := time.Now()
	if err := l.setSwitch(ctx, "enabled"); err != nil {
		t.Fatal(err)
	}
	var first Record
	for range 10 {
		first = mustRun(ctx, t, l, idService, fProject, l.project(), fType, bgpSummary, fFamily, ipv4)
		if first.ok() {
			break
		}
	}
	ev.Observed["admitting again after"] = first.StartedAt.Sub(onAt).String()
	if !first.ok() || first.StartedAt.Sub(onAt) > switchRead+3*pace {
		t.Errorf("after switching on: %s at %s, want admission within %s",
			first.status(), first.StartedAt.Sub(onAt), switchRead+3*pace)
	}
}

// blackhole: a client whose connection silently stops passing packets has
// its request's probes stopped within transport liveness detection plus
// cleanup (A12).
func blackhole(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	target := l.sinkHost(4)
	if err := watch(target); err != nil {
		t.Fatal(err)
	}
	gws, err := l.gatewayPods(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cnt := startCounter()
	reqID := "00000000-0000-4000-8000-" + fmt.Sprintf("%012x", time.Now().UnixNano()&0xffffffffffff)
	done := l.runAsync(ctx, fProject, l.project(), "-request-id", reqID, fType, traceroute, fTarget, target,
		fNodes, twoRouters, fExpires, "60s")
	time.Sleep(3 * time.Second)
	port, err := clientPort()
	if err != nil {
		t.Fatal(err)
	}
	rules := []string{
		fmt.Sprintf("INPUT -p tcp --dport %d -j DROP", port),
		fmt.Sprintf("OUTPUT -p tcp --sport %d -j DROP", port),
	}
	blackAt := time.Now()
	for _, rule := range rules {
		if _, err := nodeExec(clientNode, "sh", "-c", "ip6tables -w -I "+rule); err != nil {
			t.Fatal(err)
		}
	}
	unblock := func() {
		for _, rule := range rules {
			_, _ = nodeExec(clientNode, "sh", "-c", "ip6tables -w -D "+rule)
		}
	}
	t.Cleanup(unblock)
	// The client is unaware; streams on either replica drain once the
	// gateway detects the dead peer.
	var released time.Time
	for time.Since(blackAt) < 2*blackholeBound {
		total := 0.0
		for _, p := range gws {
			if text, err := l.gatewayMetrics(ctx, p); err == nil {
				v, _ := metricValue(text, "fabric_api_gateway_service_streams")
				total += v
			}
		}
		if total == 0 {
			released = time.Now()
			break
		}
		time.Sleep(sampleEvery)
	}
	time.Sleep(2 * time.Second)
	samples := cnt.close()
	unblock()
	_, _ = nodeExec(clientNode, "pkill", "-f", reqID)
	r := <-done
	ev.Observed["client"] = brief(r)
	ev.Observed["client port"] = port
	judgeStop(t, ev, "probes", samples, target, blackAt, blackholeBound)
	if released.IsZero() || released.Sub(blackAt) > blackholeBound+sampleEvery {
		t.Errorf("service streams not released within %s of the blackhole", blackholeBound)
	} else {
		ev.Observed["streams released after"] = released.Sub(blackAt).String()
	}
}

// clientPort returns the local port of the client's connection to the
// gateway on clientNode.
func clientPort() (int, error) {
	out, err := nodeExec(clientNode, "ss", "-tnpH", "state", "established", fmt.Sprintf("( dport = :%d )", gatewayPort))
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(out, "\n") {
		if !strings.Contains(line, `"lgc"`) {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		local := f[2]
		p, err := strconv.Atoi(local[strings.LastIndex(local, ":")+1:])
		if err == nil {
			return p, nil
		}
	}
	return 0, fmt.Errorf("no client connection in %q", out)
}

// failoverWatch measures one leadership change: the new leader's
// acquisition, its recovery hold (no admission, no probe packet from an
// operator or the service), and when admission resumes.
func failoverWatch(ctx context.Context, t *testing.T, l *lab, ev *evidence, oldHolder string) {
	newHolder, acquired, err := l.waitNewLeader(ctx, oldHolder, 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ev.Observed["new leader"] = newHolder
	ev.Observed["acquired"] = acquired
	probe := l.sinkHost(6)
	if err := watch(probe); err != nil {
		t.Fatal(err)
	}
	cnt := startCounter()
	var firstOK time.Time
	refusals := map[string]int{}
	lastOperator := time.Time{}
	for time.Since(acquired) < recoveryHold+resumeSlack+10*time.Second {
		r, err := l.run(ctx, idService, fProject, l.project(), fType, ping, fTarget, probe)
		if err == nil && r.ok() {
			firstOK = r.StartedAt
			break
		}
		refusals[r.status()]++
		if time.Since(lastOperator) > 15*time.Second {
			out, _ := l.operator(ctx, l.viaGateway(ping, probe)...)
			_, codes, _ := operatorResults(out)
			for _, c := range codes {
				refusals["operator/"+c]++
			}
			lastOperator = time.Now()
		}
		time.Sleep(3 * time.Second)
	}
	samples := cnt.close()
	held := between(samples, probe, acquired, acquired.Add(recoveryHold))
	ev.Observed["hold refusals"] = refusals
	ev.Observed["hold probe packets"] = held
	ev.Observed["first admission after acquire"] = firstOK.Sub(acquired).String()
	switch {
	case firstOK.IsZero():
		t.Errorf("no admission within %s of the new leader's acquisition", recoveryHold+resumeSlack+10*time.Second)
	case firstOK.Before(acquired.Add(recoveryHold - 500*time.Millisecond)):
		t.Errorf("admitted %s after acquisition, inside the %s recovery hold", firstOK.Sub(acquired), recoveryHold)
	case firstOK.After(acquired.Add(recoveryHold + resumeSlack)):
		t.Errorf("first admission %s after acquisition, later than %s", firstOK.Sub(acquired), recoveryHold+resumeSlack)
	}
	if held > 0 {
		t.Errorf("%d probe packets sent during the recovery hold", held)
	}
}

// leaderCrash: the leader process is killed while its request runs. The
// running probes end by their node deadline, the stream is not replayed,
// and the replacement serves its hold (A11, A14).
func leaderCrash(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	leader, holder, err := l.leaderPod(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The isolated gateway exits when it loses the Lease and its container
	// restarts in the same pod, so the rules go in the pod sandbox's
	// network namespace, which outlives every container.
	pid, err := sandboxPID(leader)
	if err != nil {
		t.Fatal(err)
	}
	target := l.sinkHost(4)
	if err := watch(target); err != nil {
		t.Fatal(err)
	}
	cnt := startCounter()
	running := l.runAsync(ctx, fProject, l.project(), fType, traceroute, fTarget, target,
		fNodes, twoRouters, fExpires, "60s")
	time.Sleep(3 * time.Second)
	crashAt := time.Now()
	if _, err := nodeExec(leader.Spec.NodeName, "kill", "-9", strconv.Itoa(pid)); err != nil {
		t.Fatal(err)
	}
	ev.Observed["crashed"] = fault{Pod: leader.Name, At: crashAt}
	r := <-running
	ev.Observed["running stream"] = brief(r)
	if r.Stream.Delivered && r.Stream.Reason == "Succeeded" {
		t.Error("the crashed leader's request claims full delivery")
	}
	failoverWatch(ctx, t, l, ev, holder)
	samples := cnt.close()
	dispatch := at(r, r.Timing.SnapshotMS)
	if r.Timing.SnapshotMS < 0 {
		dispatch = crashAt.Add(-3 * time.Second)
	}
	judgeStop(t, ev, "running probes", samples, target, dispatch, maxEmission)
}

// leaderPause: the leader is stopped, replaced, then resumed. Nothing it
// had queued or dispatched runs after it resumes (A14).
func leaderPause(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	leader, holder, err := l.leaderPod(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := gatewayPID(leader)
	if err != nil {
		t.Fatal(err)
	}
	target := l.sinkHost(6)
	if err := watch(target); err != nil {
		t.Fatal(err)
	}
	cnt := startCounter()
	// Three routers from one project: two dispatched, one queued when the
	// leader stops.
	running := l.runAsync(ctx, fProject, l.project(), fType, traceroute, fTarget, target, fExpires, "60s")
	time.Sleep(3 * time.Second)
	pausedAt := time.Now()
	if _, err := nodeExec(leader.Spec.NodeName, "kill", "-STOP", strconv.Itoa(pid)); err != nil {
		t.Fatal(err)
	}
	resume := func() { _, _ = nodeExec(leader.Spec.NodeName, "kill", "-CONT", strconv.Itoa(pid)) }
	t.Cleanup(resume)
	newHolder, acquired, err := l.waitNewLeader(ctx, holder, 90*time.Second)
	if err != nil {
		resume()
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)
	resumedAt := time.Now()
	resume()
	ev.Observed["paused"] = fault{Pod: leader.Name, At: pausedAt}
	ev.Observed["new leader"] = newHolder
	ev.Observed["acquired after pause"] = acquired.Sub(pausedAt).String()
	ev.Observed["resumed after pause"] = resumedAt.Sub(pausedAt).String()
	time.Sleep(maxEmission + 3*time.Second)
	samples := cnt.close()
	r := <-running
	ev.Observed["running stream"] = brief(r)
	late := between(samples, target, resumedAt, time.Now())
	probed := 0
	for _, n := range routers {
		if nodeTotal(samples, n, target) > 0 {
			probed++
		}
	}
	ev.Observed["packets after resume"] = late
	ev.Observed["routers that probed"] = probed
	if late > 0 {
		t.Errorf("%d probe packets sent after the replaced leader resumed", late)
	}
	if probed > 2 {
		t.Errorf("%d routers probed: the paused leader's queued router was dispatched", probed)
	}
	if nm, err := l.nodeMetrics(ctx); err == nil {
		permits := map[string]string{}
		for node, text := range nm {
			for line := range strings.SplitSeq(text, "\n") {
				if strings.HasPrefix(line, "fabric_api_node_permits_total{") {
					permits[node] += line + "\n"
				}
			}
		}
		ev.Observed["node permit outcomes"] = permits
	}
	// The new leader's hold is measured from its acquisition, which is
	// already past; wait it out so the next scenario starts admitting.
	if _, err := l.waitReady(ctx, recoveryHold+resumeSlack); err != nil {
		t.Fatal(err)
	}
}

// apiIsolation: the leader loses the API server while its request runs.
// It stops admitting and dispatching on detection, its running probes stop
// within 2 s of detection, its queued router never runs, and the new
// leader serves its hold (A14).
func apiIsolation(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	leader, holder, err := l.leaderPod(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The isolated gateway exits when it loses the Lease and its container
	// restarts in the same pod, so the rules go in the pod sandbox's
	// network namespace, which outlives every container.
	pid, err := sandboxPID(leader)
	if err != nil {
		t.Fatal(err)
	}
	target := l.sinkHost(4)
	if err := watch(target); err != nil {
		t.Fatal(err)
	}
	cnt := startCounter()
	running := l.runAsync(ctx, fProject, l.project(), fType, traceroute, fTarget, target, fExpires, "60s")
	time.Sleep(3 * time.Second)
	rules := make([]string, 0, 4)
	for _, ipt := range []string{iptables, ip6tables} {
		for _, port := range []string{"443", "6443"} {
			rules = append(rules, fmt.Sprintf("%s -w -%%s OUTPUT -p tcp --dport %s -j DROP", ipt, port))
		}
	}
	nsenter := func(action string) error {
		for _, rule := range rules {
			if _, err := nodeExec(leader.Spec.NodeName, "nsenter", "-t", strconv.Itoa(pid), "-n", "sh", "-c",
				fmt.Sprintf(rule, action)); err != nil {
				return err
			}
		}
		return nil
	}
	isolatedAt := time.Now()
	if err := nsenter("I"); err != nil {
		t.Fatal(err)
	}
	var restoreOnce sync.Once
	restore := func() {
		restoreOnce.Do(func() {
			if err := nsenter("D"); err != nil {
				t.Errorf("remove the isolation rules from %s: %v", leader.Name, err)
			}
		})
	}
	t.Cleanup(restore)
	detected, ok := l.gauge(ctx, leader, 60*time.Second, func(text string) bool {
		v, found := metricValue(text, "fabric_api_gateway_limiter_state", `state="ready"`)
		return found && v == 0
	})
	ev.Observed["isolated"] = fault{Pod: leader.Name, At: isolatedAt}
	if ok {
		ev.Observed["detected after"] = detected.Sub(isolatedAt).String()
	} else {
		t.Error("the isolated leader's limiter never left ready")
	}
	// New work is refused from detection on; a Lease read already under
	// way at detection ends within its bound.
	time.Sleep(leaseReadBound)
	r, err := l.run(ctx, idService, fProject, l.project(), fType, bgpSummary, fFamily, ipv4)
	if err == nil {
		ev.Observed["request after detection"] = brief(r)
		if r.ok() {
			t.Error("a request was admitted after the leader lost the API")
		}
	}
	newHolder, acquired, err := l.waitNewLeader(ctx, holder, 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ev.Observed["new leader"] = map[string]any{"holder": newHolder, "acquiredAfter": acquired.Sub(isolatedAt).String()}
	time.Sleep(10 * time.Second)
	restore()
	ev.Observed["restored after"] = time.Since(isolatedAt).String()
	run := <-running
	ev.Observed["running stream"] = brief(run)
	time.Sleep(maxEmission)
	samples := cnt.close()
	dispatch := at(run, run.Timing.SnapshotMS)
	if run.Timing.SnapshotMS < 0 {
		dispatch = isolatedAt.Add(-3 * time.Second)
	}
	if ok {
		judgeStop(t, ev, "running probes after detection", samples, target, detected, stopBound)
	}
	judgeStop(t, ev, "running probes after dispatch", samples, target, dispatch, maxEmission)
	probed := 0
	for _, n := range routers {
		if nodeTotal(samples, n, target) > 0 {
			probed++
		}
	}
	ev.Observed["routers that probed"] = probed
	if probed > 2 {
		t.Errorf("%d routers probed: the isolated leader's queued router was dispatched", probed)
	}
	if _, err := l.waitReady(ctx, recoveryHold+resumeSlack); err != nil {
		t.Fatal(err)
	}
}

// cleanup: no fault the suite injected outlives it. No dfw node, nor any
// gateway pod, keeps a DROP rule in its INPUT or OUTPUT chain, and every
// gateway and fabric-router pod is Ready again within cleanupReadyBound
// (a container that crashed while isolated may wait out its restart
// back-off).
func cleanup(ctx context.Context, t *testing.T, l *lab, ev *evidence) {
	const list = "for t in iptables ip6tables; do $t -w -S INPUT; $t -w -S OUTPUT; done"
	residue := map[string][]string{}
	scan := func(where, node string, args ...string) {
		out, err := nodeExec(node, append(args, "sh", "-c", list)...)
		if err != nil {
			t.Errorf("list %s's rules: %v", where, err)
			return
		}
		for line := range strings.SplitSeq(out, "\n") {
			if strings.Contains(line, "-j DROP") {
				residue[where] = append(residue[where], strings.TrimSpace(line))
			}
		}
	}
	for _, n := range routers {
		scan(n, n)
	}
	gws, err := l.gatewayPods(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range gws {
		pid, err := sandboxPID(p)
		if err != nil {
			t.Errorf("sandbox of %s: %v", p.Name, err)
			continue
		}
		scan(p.Name, p.Spec.NodeName, "nsenter", "-t", strconv.Itoa(pid), "-n")
	}
	ev.Observed["rules left"] = residue
	for where, rules := range residue {
		t.Errorf("%s keeps %d DROP rules, e.g. %s", where, len(rules), rules[0])
	}

	start := time.Now()
	var notReady []string
	for {
		notReady = notReady[:0]
		for _, sel := range []string{"app.kubernetes.io/name=fabric-api-gateway", fabricRouterSelector} {
			pods, err := l.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: sel})
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range pods.Items {
				if !podReady(p) {
					notReady = append(notReady, p.Name)
				}
			}
		}
		if len(notReady) == 0 || time.Since(start) > cleanupReadyBound {
			break
		}
		time.Sleep(5 * time.Second)
	}
	ev.Observed["pods ready after"] = time.Since(start).Round(time.Second).String()
	if len(notReady) > 0 {
		t.Errorf("pods not Ready %s after the run: %v", cleanupReadyBound, notReady)
	}
}
