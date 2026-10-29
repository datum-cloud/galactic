// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeconformance_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// The contract's bounds (contract.md, Timing and failure bounds), as pass
// thresholds in real time. A 15.5 s bound on the holder's clock is at most
// 15.52 s of real time with MaxDrift 0.001.
const (
	localExpiry     = 15520 * time.Millisecond
	takeoverWait    = 15530 * time.Millisecond
	maxSkew         = 2 * time.Second
	margin          = 500 * time.Millisecond
	routerHoldBound = 9 * time.Second
	// probeInterval is the gap between probe datagrams; it bounds how
	// precisely a stop is timed.
	probeInterval = 20 * time.Millisecond
	// agentRestartGap is the largest reply gap allowed while galactic-edge
	// restarts with an attachment forwarding (row 15). Forwarding must
	// continue to its deadline, so anything near a lease is a failure.
	agentRestartGap = time.Second
)

// side is one tenant's provider deployment under test.
type side struct {
	tn     tenant
	svc    *galacticv1alpha1.EdgeService
	vpcUID string
	deploy string
	node   string
	pod    *corev1.Pod
	att    *galacticv1alpha1.EdgeAttachment
}

func (s *side) config(prefixes ...string) string {
	return providerConfig(s.tn.provider, serviceConfig{tn: s.tn, svc: s.svc, vpcUID: s.vpcUID, prefixes: prefixes})
}

// refresh rereads the side's running pod and attachment.
func (s *side) refresh(t *testing.T, l *lab) {
	t.Helper()
	s.pod = l.waitProviderPod(t, s.tn.namespace, s.deploy, s.node)
	s.att = l.waitServing(t, s.pod, s.svc)
}

// lease returns the side's instance lease.
func (s *side) lease(t *testing.T, l *lab) *coordinationv1.Lease {
	t.Helper()
	var le coordinationv1.Lease
	key := client.ObjectKey{Namespace: s.tn.namespace, Name: "ei-" + string(s.pod.UID)}
	if err := l.c.Get(context.Background(), key, &le); err != nil {
		t.Fatal(err)
	}
	return &le
}

// lastRenewal returns the renew-start of the last renewal a provider that
// has just stopped renewing made: it waits out a write already in flight,
// then reads the lease.
func (s *side) lastRenewal(t *testing.T, l *lab) time.Duration {
	t.Helper()
	time.Sleep(time.Second)
	return s.renewStart(t, l)
}

// renewStart returns the side's lease's latest renew-start.
func (s *side) renewStart(t *testing.T, l *lab) time.Duration {
	t.Helper()
	v, err := strconv.ParseInt(s.lease(t, l).Annotations[galacticv1alpha1.EdgeLeaseRenewStartAnnotation], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return time.Duration(v)
}

func TestConformance(t *testing.T) {
	l := getLab(t)
	t.Cleanup(func() { l.writeSummary(t) })

	a := &side{tn: tenantA, deploy: "a1", node: edgeNode1}
	b := &side{tn: tenantB, deploy: "b1", node: edgeNode1}
	// EDGE_CONFORMANCE_KEEP leaves the fixtures in place for debugging.
	if os.Getenv("EDGE_CONFORMANCE_KEEP") == "" {
		t.Cleanup(func() { teardown(t, l, a, b) })
	}
	if !t.Run("setup", func(t *testing.T) { setup(t, l, a, b) }) {
		t.FailNow()
	}
	pa := netip.MustParsePrefix(prefix)

	// Rows 1 to 5 and 7b: refusals. None may disturb the live attachments.
	t.Run("01-unknown-or-unapproved-provider", func(t *testing.T) { rowUnapproved(t, l, a, b) })
	t.Run("02-unsupported-version", func(t *testing.T) { rowVersions(t, l, a) })
	t.Run("03-out-of-grant", func(t *testing.T) { rowOutOfGrant(t, l, a) })
	t.Run("04-forged-identity", func(t *testing.T) { rowForged(t, l, a, pa) })
	t.Run("05-capacity", func(t *testing.T) { rowCapacity(t, l, a) })
	t.Run("06-overlapping-tenants", func(t *testing.T) { rowOverlap(t, l, a, b) })
	t.Run("07-prefix-conflict-between-providers", func(t *testing.T) { rowServiceConflict(t, l, a) })
	t.Run("07a-overlapping-prefixes", func(t *testing.T) { rowOverlappingPrefixes(t, l, a, pa) })
	t.Run("07b-route-on-another-pods-attachment", func(t *testing.T) { rowForeignAttachment(t, l, a, pa) })
	t.Run("07c-subnet-over-a-route", func(t *testing.T) { rowSubnet(t, l, a, pa) })
	t.Run("10-15a-provider-crash-and-restart-in-place", func(t *testing.T) { rowCrash(t, l, a, pa) })
	t.Run("11-provider-stall", func(t *testing.T) { rowStall(t, l, a, pa) })
	t.Run("11b-provider-hung-forwarding", func(t *testing.T) { rowFrozen(t, l, a, pa) })
	t.Run("13-cross-node-replacement", func(t *testing.T) { rowReplacement(t, l, a, pa) })
	t.Run("13e-removal-with-the-node-agent-stuck", func(t *testing.T) { rowRemovalAgentStuck(t, l, a, pa) })
	t.Run("14-galactic-edge-stall", func(t *testing.T) { rowAgentStall(t, l, a, pa) })
	t.Run("15-galactic-edge-restart", func(t *testing.T) { rowAgentRestart(t, l, a) })
	t.Run("16-galactic-router-down", func(t *testing.T) { rowRouterDown(t, l, a) })
	t.Run("17-revocation", func(t *testing.T) { rowRevocation(t, l, a, pa) })
	t.Run("19-20-traffic-policy", func(t *testing.T) { rowPolicy(t, l, a) })
	t.Run("21-gc-with-only-edge-users", func(t *testing.T) { rowGC(t, l, a) })
	t.Run("18-grant-ceiling", func(t *testing.T) { rowCeiling(t, l, a, pa) })
	t.Run("24-drain", func(t *testing.T) { rowDrain(t, l, a, b) })
}

// setup registers and approves both providers, grants each its tenant's
// VPC, and starts one provider instance per tenant on the same edge node,
// claiming the same prefix in each VPC.
func setup(t *testing.T, l *lab, sides ...*side) {
	for _, s := range sides {
		l.ensureNamespace(t, s.tn.namespace)
		l.register(t, s.tn.provider, s.tn.namespace, true)
		s.vpcUID = l.vpcUID(t, s.tn)
		s.svc = l.grantService(t, s.tn, s.tn.service, nil)
		l.waitServiceAdmitted(t, s.svc, true)
		l.deployProvider(t, s.tn.namespace, s.deploy, s.node, s.config(prefix))
	}
	for _, s := range sides {
		s.refresh(t, l)
		// The first route of a VPC waits out the takeover interval after
		// its index is created, so allow for that.
		l.waitAccepted(t, s.tn.namespace, s.vpcUID, netip.MustParsePrefix(prefix), s.att.Name, 3*time.Minute)
		l.waitReachable(t, s)
	}
}

// waitServiceAdmitted waits for the service's Admitted condition.
func (l *lab) waitServiceAdmitted(t *testing.T, svc *galacticv1alpha1.EdgeService, want bool) string {
	t.Helper()
	var reason string
	eventually(t, time.Minute, time.Second, "service "+svc.Name+" Admitted="+strconv.FormatBool(want),
		func() (bool, error) {
			if err := l.c.Get(context.Background(), client.ObjectKeyFromObject(svc), svc); err != nil {
				return false, err
			}
			c := meta.FindStatusCondition(svc.Status.Conditions, "Admitted")
			if c == nil || c.ObservedGeneration != svc.Generation {
				return false, nil
			}
			reason = c.Reason
			return (c.Status == metav1.ConditionTrue) == want, nil
		})
	return reason
}

// waitReachable waits until a probe from s's tenant on the compute node
// reaches s's prefix and is answered by s's provider.
func (l *lab) waitReachable(t *testing.T, s *side) {
	node := computeNode
	t.Helper()
	pid := l.clientPID(t, s.tn, node)
	eventually(t, 2*time.Minute, 2*time.Second, s.tn.provider+" reachable from "+node, func() (bool, error) {
		p, err := startProbe(node, pid, "reach", "send", "-to", "["+target+"]:"+strconv.Itoa(echoPort),
			"-interval", "50ms", "-duration", "1s")
		if err != nil {
			return false, err
		}
		_ = p.cmd.Wait()
		return strings.Contains(p.out.String(), s.tn.provider+"/"), nil
	})
}

// probe sends to target from tenant tn's client on node for d.
func (l *lab) probe(t *testing.T, tn tenant, node, name, dst string, d time.Duration) *probeRun {
	t.Helper()
	p, err := startProbe(node, l.clientPID(t, tn, node), name, "send", "-to", dst, "-interval",
		probeInterval.String(), "-duration", d.String())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func targetAddr() string { return "[" + target + "]:" + strconv.Itoa(echoPort) }

// replies returns the reply events, in time order.
func replies(evs []event) []event {
	var out []event
	for _, e := range evs {
		if e.Reply != "" {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].T < out[j].T })
	return out
}

// sentCount returns how many datagrams a send probe sent.
func sentCount(evs []event) int {
	for _, e := range evs {
		if e.Sent > 0 {
			return e.Sent
		}
	}
	return 0
}

// stopGap is the reply gap that counts as forwarding having stopped: 50
// probe intervals.
const stopGap = time.Second

// windowed returns the replies or captured packets of evs in time order,
// followed by the event that ends the probe's window, so a stop that lasts
// to the window's end is seen.
func windowed(evs []event) []event {
	var out []event
	var end *event
	for _, e := range evs {
		switch {
		case e.last():
			end = &e
		case e.Reply != "" || e.Dst != "":
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].T < out[j].T })
	if end != nil {
		out = append(out, *end)
	}
	return out
}

// stopAfter returns the time of the last reply before the first gap longer
// than stopGap that starts after from, and whether there is such a gap. The
// window's end counts as the end of a gap.
func stopAfter(rs []event, from time.Duration) (time.Duration, bool) {
	var last time.Duration
	for _, r := range rs {
		if r.T < from && !r.last() {
			last = r.T
			continue
		}
		if last != 0 && r.T-last > stopGap {
			return last, true
		}
		if r.last() {
			break
		}
		last = r.T
	}
	return last, false
}

// resumeAfter returns the first reply after at.
func resumeAfter(rs []event, at time.Duration) (time.Duration, bool) {
	for _, r := range rs {
		if r.T > at && !r.last() {
			return r.T, true
		}
	}
	return 0, false
}

// largestGap returns the largest gap between consecutive replies.
func largestGap(rs []event) time.Duration {
	var g time.Duration
	for i := 1; i < len(rs); i++ {
		if rs[i].last() {
			break
		}
		g = max(g, rs[i].T-rs[i-1].T)
	}
	return g
}

// writeSummary saves the run's measurements with the commit and core
// images it ran against.
func (l *lab) writeSummary(t *testing.T) {
	commit, _ := exec.CommandContext(context.Background(), "git", "-C", l.root, "rev-parse", "HEAD").Output()
	dirty, _ := exec.CommandContext(context.Background(), "git", "-C", l.root, "status", "--porcelain").Output()
	images := map[string]string{}
	for _, img := range []string{"galactic-edge:latest", "galactic-controller:latest", "galactic-router:latest",
		"galactic-cni:latest", "edge-provider:latest", "masque-provider:latest", "masque-service:latest",
		"masque-authority:latest"} {
		id, _ := exec.CommandContext(context.Background(), "docker", "image", "inspect", "--format", "{{.Id}}", img).Output()
		images[img] = strings.TrimSpace(string(id))
	}
	results.Lock()
	defer results.Unlock()
	b, _ := json.MarshalIndent(map[string]any{
		"commit": strings.TrimSpace(string(commit)), "dirty": len(dirty) > 0, "images": images,
		"finished": time.Now().UTC().Format(time.RFC3339), "results": results.m, "failed": t.Failed(),
	}, "", "  ")
	_ = os.WriteFile(filepath.Join(l.artifacts, "summary.json"), b, 0o644)
	t.Logf("summary: %s", filepath.Join(l.artifacts, "summary.json"))
}

// teardown removes everything the suite created.
func teardown(t *testing.T, l *lab, sides ...*side) {
	ctx := context.Background()
	for _, s := range sides {
		if _, err := l.kubectl("delete", "namespace", s.tn.namespace, "--wait=true", "--timeout=180s"); err != nil {
			t.Error(err)
		}
		_ = l.c.Delete(ctx, &galacticv1alpha1.EdgeService{ObjectMeta: metav1.ObjectMeta{Namespace: s.tn.vpcNamespace,
			Name: s.tn.service}})
		_ = l.c.Delete(ctx, &galacticv1alpha1.EdgeProvider{ObjectMeta: metav1.ObjectMeta{Name: s.tn.provider}})
	}
	for _, n := range []string{"edge-conf-u", "edge-conf-v"} {
		_, _ = l.kubectl("delete", "namespace", n, "--ignore-not-found", "--wait=true", "--timeout=180s")
	}
	for _, p := range []string{"conf-u", "conf-v"} {
		_ = l.c.Delete(ctx, &galacticv1alpha1.EdgeProvider{ObjectMeta: metav1.ObjectMeta{Name: p}})
	}
}

// ensureSA creates the provider ServiceAccount in namespace.
func (l *lab) ensureSA(t *testing.T, namespace string) {
	t.Helper()
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "edge-provider"}}
	if err := l.c.Create(context.Background(), sa); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
}

// requireRefused fails unless err is an API refusal: Forbidden or Invalid.
func requireRefused(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: accepted, want refused", what)
		return
	}
	if !apierrors.IsForbidden(err) && !apierrors.IsInvalid(err) {
		t.Errorf("%s: %v, want Forbidden or Invalid", what, err)
		return
	}
	t.Logf("%s: refused: %v", what, err)
}

// instanceFor creates pod's EdgeInstance as pod, as a provider does.
func instanceFor(t *testing.T, c client.Client, pod *corev1.Pod, provider string) {
	t.Helper()
	inst := &galacticv1alpha1.EdgeInstance{
		ObjectMeta: metav1.ObjectMeta{Namespace: pod.Namespace, Name: "ei-" + string(pod.UID)},
		Spec: galacticv1alpha1.EdgeInstanceSpec{ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: provider},
			PodName: pod.Name, PodUID: string(pod.UID), NodeName: pod.Spec.NodeName, BootID: fixtureTag},
	}
	if err := c.Create(context.Background(), inst); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
}

// attachmentRequest is an EdgeAttachment pod writes for svc.
func attachmentRequest(pod *corev1.Pod, provider string, svc *galacticv1alpha1.EdgeService, contract,
	capVersion string) *galacticv1alpha1.EdgeAttachment {
	return &galacticv1alpha1.EdgeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: pod.Namespace, Name: "ea-" + string(pod.UID) + "-" + string(svc.UID)},
		Spec: galacticv1alpha1.EdgeAttachmentSpec{
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: provider},
			ServiceRef: galacticv1alpha1.EdgeServiceReference{Namespace: svc.Namespace, Name: svc.Name,
				UID: string(svc.UID)},
			InstanceRef:     galacticv1alpha1.EdgeInstanceReference{Name: "ei-" + string(pod.UID)},
			PodUID:          string(pod.UID),
			ContractVersion: contract,
			Capabilities:    []galacticv1alpha1.EdgeCapability{{Name: capSocket, Version: capVersion}},
		},
	}
}

// waitRefused waits until core refuses att, and returns the reason.
func (l *lab) waitRefused(t *testing.T, att *galacticv1alpha1.EdgeAttachment) string {
	t.Helper()
	var reason string
	eventually(t, time.Minute, time.Second, "refusal of "+att.Name, func() (bool, error) {
		var cur galacticv1alpha1.EdgeAttachment
		if err := l.c.Get(context.Background(), client.ObjectKeyFromObject(att), &cur); err != nil {
			return false, err
		}
		c := meta.FindStatusCondition(cur.Status.Conditions, galacticv1alpha1.EdgeAttachmentAdmitted)
		if c == nil {
			return false, nil
		}
		if c.Status == metav1.ConditionTrue {
			reason = "admitted"
			return true, nil
		}
		reason = c.Reason
		return true, nil
	})
	return reason
}

// allocated reports whether the service holds an address for attachment.
func (l *lab) allocated(t *testing.T, svc *galacticv1alpha1.EdgeService, attachment string) bool {
	t.Helper()
	var cur galacticv1alpha1.EdgeService
	if err := l.c.Get(context.Background(), client.ObjectKeyFromObject(svc), &cur); err != nil {
		t.Fatal(err)
	}
	for _, a := range cur.Status.Allocations {
		if a.Attachment == attachment {
			return true
		}
	}
	return false
}

func rowUnapproved(t *testing.T, l *lab, a, b *side) {
	ctx := context.Background()
	// An unapproved provider: registered, never approved, so it has no
	// RoleBinding and RBAC refuses every write.
	l.ensureNamespace(t, "edge-conf-u")
	l.ensureSA(t, "edge-conf-u")
	l.register(t, "conf-u", "edge-conf-u", false)
	u := l.tokenPod(t, "edge-conf-u", "token-u", edgeNode1)
	cu := l.asPod(t, u)
	err := cu.Create(ctx, &galacticv1alpha1.EdgeInstance{
		ObjectMeta: metav1.ObjectMeta{Namespace: u.Namespace, Name: "ei-" + string(u.UID)},
		Spec: galacticv1alpha1.EdgeInstanceSpec{ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: "conf-u"},
			PodName: u.Name, PodUID: string(u.UID), NodeName: u.Spec.NodeName, BootID: fixtureTag},
	})
	requireRefused(t, "unapproved provider's instance", err)

	// An approved provider's pod naming a provider that is not registered.
	tp := l.tokenPod(t, a.tn.namespace, "token-a", edgeNode1)
	ca := l.asPod(t, tp)
	instanceFor(t, ca, tp, a.tn.provider)
	unknown := attachmentRequest(tp, "conf-none", a.svc, "v1alpha1", "v1")
	requireRefused(t, "attachment naming an unregistered provider", ca.Create(ctx, unknown))

	// An approved provider's pod requesting another provider's grant: an
	// unauthorized reference core refuses before allocating.
	foreign := attachmentRequest(tp, a.tn.provider, b.svc, "v1alpha1", "v1")
	if err := ca.Create(ctx, foreign); err != nil {
		t.Fatalf("attachment to another provider's grant: %v", err)
	}
	reason := l.waitRefused(t, foreign)
	l.record(t, "attachment to another provider's grant", reason)
	if reason != "ProviderNotGranted" {
		t.Errorf("attachment to another provider's grant: %s, want ProviderNotGranted", reason)
	}
	if l.allocated(t, b.svc, foreign.Name) {
		t.Error("a refused attachment holds an address")
	}
	l.deleteAndWait(t, foreign)
}

func rowVersions(t *testing.T, l *lab, a *side) {
	ctx := context.Background()
	tp := l.tokenPod(t, a.tn.namespace, "token-a", edgeNode1)
	ca := l.asPod(t, tp)
	instanceFor(t, ca, tp, a.tn.provider)
	for _, tc := range []struct{ name, contract, version, want string }{
		{"contract version the provider does not declare", "v1alpha9", "v1", "UnsupportedContractVersion"},
		{"capability version the provider does not declare", "v1alpha1", "v2", "UnsupportedCapability"},
	} {
		att := attachmentRequest(tp, a.tn.provider, a.svc, tc.contract, tc.version)
		if err := ca.Create(ctx, att); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		reason := l.waitRefused(t, att)
		l.record(t, tc.name, reason)
		if reason != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, reason, tc.want)
		}
		if l.allocated(t, a.svc, att.Name) {
			t.Errorf("%s: refused attachment holds an address", tc.name)
		}
		l.deleteAndWait(t, att)
	}

	// A provider that declares a contract version core does not implement:
	// core supports v1alpha1 only, so a request written to anything else is
	// refused before allocation whatever the provider claims.
	l.ensureNamespace(t, "edge-conf-v")
	l.ensureSA(t, "edge-conf-v")
	l.register(t, "conf-v", "edge-conf-v", true, "v1alpha1", "v1alpha9")
	svc := l.grantService(t, tenant{vpcNamespace: a.tn.vpcNamespace, vpc: a.tn.vpc, provider: "conf-v"}, "svc-v",
		func(s *galacticv1alpha1.EdgeService) {
			s.Spec.Prefixes, s.Spec.ClientPool = nil, "fd00:ed9e:0:3::/64"
			s.Spec.Capabilities = []string{capSocket}
		})
	defer l.deleteAndWait(t, svc)
	vp := l.tokenPod(t, "edge-conf-v", "token-v", edgeNode1)
	cv := l.asPod(t, vp)
	instanceFor(t, cv, vp, "conf-v")
	att := attachmentRequest(vp, "conf-v", svc, "v1alpha9", "v1")
	eventually(t, time.Minute, 2*time.Second, "conf-v RoleBinding", func() (bool, error) {
		err := cv.Create(ctx, att)
		return err == nil || apierrors.IsAlreadyExists(err), err
	})
	reason := l.waitRefused(t, att)
	l.record(t, "contract version core does not implement", reason)
	if reason != "UnsupportedContractVersion" {
		t.Errorf("a request written to contract v1alpha9, which core does not implement, was %s; "+
			"want UnsupportedContractVersion", reason)
	}
	l.deleteAndWait(t, att)
}

func rowOutOfGrant(t *testing.T, l *lab, a *side) {
	// A second instance of provider A whose configuration claims a prefix
	// outside A's grant.
	l.deployProvider(t, a.tn.namespace, "a-out", edgeNode2, a.config(outside))
	defer l.stopProvider(t, a.tn.namespace, "a-out")
	out := netip.MustParsePrefix(outside)
	var reason string
	eventually(t, time.Minute, time.Second, "refusal of "+outside, func() (bool, error) {
		r := l.route(t, a.tn.namespace, a.vpcUID, out)
		if r == nil {
			return false, nil
		}
		c := meta.FindStatusCondition(r.Status.Conditions, galacticv1alpha1.EdgeRouteClaimed)
		if c == nil || c.Status != metav1.ConditionFalse {
			return false, nil
		}
		reason = c.Reason
		return true, nil
	})
	l.record(t, "route outside the grant", reason)
	if reason != "PrefixNotGranted" {
		t.Errorf("route outside the grant: %s, want PrefixNotGranted", reason)
	}
	if r := l.route(t, a.tn.namespace, a.vpcUID, out); r.Status.Accepted != nil {
		t.Errorf("route outside the grant has an accepted holder: %+v", r.Status.Accepted)
	}
	if n := l.edgeAdvertisements(t, out); n != 0 {
		t.Errorf("route outside the grant has %d advertisements", n)
	}
	r := l.route(t, a.tn.namespace, a.vpcUID, out)
	l.stopProvider(t, a.tn.namespace, "a-out")
	if r != nil {
		l.deleteAndWait(t, r)
	}
}

// edgeAdvertisements counts the BGPAdvertisements core publishes for p.
func (l *lab) edgeAdvertisements(t *testing.T, p netip.Prefix) int {
	t.Helper()
	out, err := l.kubectl("get", "bgpadvertisements", "-n", "galactic-system", "-l", "galactic.datumapis.com/edge-route",
		"-o", "jsonpath={range .items[*]}{.spec}{\"\\n\"}{end}")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(out, p.String())
}

func rowForged(t *testing.T, l *lab, a *side, pa netip.Prefix) {
	ctx := context.Background()
	a.refresh(t, l)
	victim := a.pod
	tp := l.tokenPod(t, a.tn.namespace, "token-a", edgeNode1)
	ca := l.asPod(t, tp)

	inst := &galacticv1alpha1.EdgeInstance{
		ObjectMeta: metav1.ObjectMeta{Namespace: a.tn.namespace, Name: "ei-" + string(victim.UID) + "x"},
		Spec: galacticv1alpha1.EdgeInstanceSpec{ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: a.tn.provider},
			PodName: victim.Name, PodUID: string(victim.UID), NodeName: victim.Spec.NodeName, BootID: "x"},
	}
	requireRefused(t, "instance naming another pod", ca.Create(ctx, inst))

	att := attachmentRequest(victim, a.tn.provider, a.svc, "v1alpha1", "v1")
	att.Name += "x"
	requireRefused(t, "attachment naming another pod", ca.Create(ctx, att))

	le := a.lease(t, l)
	le.Annotations[galacticv1alpha1.EdgeLeaseReleasedAnnotation] = "true"
	requireRefused(t, "write of another pod's lease", ca.Update(ctx, le))

	r := l.route(t, a.tn.namespace, a.vpcUID, pa)
	r.Spec.Claim.Released = true
	requireRefused(t, "release of another pod's claim", ca.Update(ctx, r))

	r = l.route(t, a.tn.namespace, a.vpcUID, pa)
	r.Spec.Claim.Epoch++
	requireRefused(t, "claim written for another pod", ca.Update(ctx, r))

	cur := l.route(t, a.tn.namespace, a.vpcUID, pa)
	if cur.Status.Accepted == nil || cur.Status.Accepted.Attachment != a.att.Name {
		t.Errorf("refused writes moved the route: %+v", cur.Status.Accepted)
	}
}

func rowCapacity(t *testing.T, l *lab, a *side) {
	ctx := context.Background()
	// A grant whose prefixes are its own /120 client pool. The allocator
	// skips the pool's first address, a provider instance takes the next,
	// ::1, then claims routes over every other address, ::2 to ::ff, as
	// delegated client prefixes; the allocator never hands out an address
	// under a route, so the pool is then full.
	const capPool = "fd00:ed9e:0:4::/120"
	svc := l.grantService(t, a.tn, "svc-cap", func(s *galacticv1alpha1.EdgeService) {
		s.Spec.Prefixes, s.Spec.ClientPool = []string{capPool}, capPool
	})
	defer l.deleteAndWait(t, svc)
	l.waitServiceAdmitted(t, svc, true)
	fill := []string{"fd00:ed9e:0:4::80/121", "fd00:ed9e:0:4::40/122", "fd00:ed9e:0:4::20/123",
		"fd00:ed9e:0:4::10/124", "fd00:ed9e:0:4::8/125", "fd00:ed9e:0:4::4/126", "fd00:ed9e:0:4::2/127"}
	l.deployProvider(t, a.tn.namespace, "a-cap", edgeNode2, providerConfig(a.tn.provider,
		serviceConfig{tn: a.tn, svc: svc, vpcUID: a.vpcUID, prefixes: fill}))
	defer l.stopProvider(t, a.tn.namespace, "a-cap")
	holder := l.waitServing(t, l.waitProviderPod(t, a.tn.namespace, "a-cap", edgeNode2), svc)
	l.record(t, "the filling instance's address", holder.Status.Address)
	for _, p := range fill {
		l.waitAccepted(t, a.tn.namespace, a.vpcUID, netip.MustParsePrefix(p), holder.Name, 2*time.Minute)
	}

	tp := l.tokenPod(t, a.tn.namespace, "token-cap", edgeNode2)
	c := l.asPod(t, tp)
	instanceFor(t, c, tp, a.tn.provider)
	att := attachmentRequest(tp, a.tn.provider, svc, "v1alpha1", "v1")
	if err := c.Create(ctx, att); err != nil {
		t.Fatal(err)
	}
	var reason string
	eventually(t, time.Minute, time.Second, "allocation decision for "+att.Name, func() (bool, error) {
		var cur galacticv1alpha1.EdgeAttachment
		if err := l.c.Get(ctx, client.ObjectKeyFromObject(att), &cur); err != nil {
			return false, err
		}
		if cur.Status.Address != "" {
			reason = "allocated " + cur.Status.Address
			return true, nil
		}
		for _, cond := range cur.Status.Conditions {
			if cond.Status == metav1.ConditionFalse && (cond.Type == galacticv1alpha1.EdgeAttachmentAdmitted ||
				cond.Type == galacticv1alpha1.EdgeAttachmentAllocated) && cond.Reason != "Pending" {
				reason = cond.Reason
				return true, nil
			}
		}
		return false, nil
	})
	l.record(t, "request beyond the pool", reason)
	if reason != "PoolExhausted" {
		t.Errorf("a request with no free address: %s, want PoolExhausted", reason)
	}
	if l.allocated(t, svc, att.Name) {
		t.Error("the refused attachment holds an address")
	}
	cur := l.attachmentOf(t, l.waitProviderPod(t, a.tn.namespace, "a-cap", edgeNode2), svc)
	if cur == nil || cur.Status.Address != holder.Status.Address ||
		!meta.IsStatusConditionTrue(cur.Status.Conditions, galacticv1alpha1.EdgeAttachmentProgrammed) {
		t.Errorf("the existing attachment changed: %+v", cur)
	}
	l.deleteAndWait(t, att)
	l.stopProvider(t, a.tn.namespace, "a-cap")
	for _, p := range fill {
		if r := l.route(t, a.tn.namespace, a.vpcUID, netip.MustParsePrefix(p)); r != nil {
			l.deleteAndWait(t, r)
		}
	}
}

// reachable fails unless a short probe from a's tenant on node gets most of
// its datagrams answered by a's provider.
func (l *lab) reachable(t *testing.T, a *side, node string) {
	t.Helper()
	evs := l.probe(t, a.tn, node, "reachable-"+node, targetAddr(), 2*time.Second).wait(l, t)
	rs := replies(evs)
	if len(rs) < sentCount(evs)*9/10 {
		t.Errorf("%s answered %d of %d probes from %s", a.tn.provider, len(rs), sentCount(evs), node)
	}
	for _, r := range rs {
		if !strings.HasPrefix(r.Reply, a.tn.provider+"/") {
			t.Errorf("probe from %s answered by %q", node, r.Reply)
			return
		}
	}
}

func rowOverlap(t *testing.T, l *lab, a, b *side) {
	a.refresh(t, l)
	b.refresh(t, l)
	l.record(t, "attachment addresses", a.att.Status.Address+" (VPC 10), "+b.att.Status.Address+" (VPC 20)")
	// Both tenants send to the same prefix address, and to the same
	// attachment address, at the same time, from the compute node and
	// from the providers' own node, while B's packet device is watched for
	// anything of A's.
	sniff, err := startProbe(b.node, podPID(t, b.node, b.pod.Namespace, b.pod.Name), "sniff-b", "sniff",
		"-iface", b.att.Status.PacketDevice, "-port", strconv.Itoa(echoPort), "-duration", "8s")
	if err != nil {
		t.Fatal(err)
	}
	type run struct {
		s    *side
		node string
		dst  string
		p    *probeRun
	}
	runs := make([]run, 0, 6)
	for _, s := range []*side{a, b} {
		for _, node := range []string{computeNode, edgeNode1} {
			runs = append(runs, run{s, node, targetAddr(), l.probe(t, s.tn, node, "prefix-"+s.tn.vpc+"-"+node, targetAddr(),
				5*time.Second)})
		}
		dst := "[" + s.att.Status.Address + "]:" + strconv.Itoa(echoPort)
		runs = append(runs, run{s, edgeNode1, dst, l.probe(t, s.tn, edgeNode1, "address-"+s.tn.vpc, dst, 5*time.Second)})
	}
	for _, r := range runs {
		evs := r.p.wait(l, t)
		rs := replies(evs)
		wrong := 0
		for _, e := range rs {
			if !strings.HasPrefix(e.Reply, r.s.tn.provider+"/") {
				wrong++
			}
		}
		l.record(t, fmt.Sprintf("VPC %s from %s to %s", r.s.tn.vpc, r.node, r.dst),
			fmt.Sprintf("%d/%d answered, %d by the other tenant's provider", len(rs), sentCount(evs), wrong))
		if wrong > 0 || len(rs) < sentCount(evs)*9/10 {
			t.Errorf("VPC %s from %s to %s: %d of %d answered, %d by the wrong provider", r.s.tn.vpc, r.node, r.dst,
				len(rs), sentCount(evs), wrong)
		}
	}
	seen := sniff.wait(l, t)
	foreign := 0
	for _, e := range seen {
		// B's own tenant uses edge-client addresses fd20:20:...; anything
		// from fd20:10: is A's tenant's.
		if strings.HasPrefix(e.Src, "fd20:10:") {
			foreign++
		}
	}
	l.record(t, "VPC 10 packets on VPC 20's provider device", foreign)
	if foreign > 0 {
		t.Errorf("%d of VPC 10's packets reached VPC 20's provider", foreign)
	}
}

// podPID returns the sandbox PID of a pod on node.
func podPID(t *testing.T, node, namespace, pod string) int {
	t.Helper()
	pid, err := sandboxPID(node, namespace, pod)
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

func rowServiceConflict(t *testing.T, l *lab, a *side) {
	// Provider B granted the same prefixes in VPC 10 as provider A: grants
	// are exclusive in a VPC, so the later one admits nothing, while A
	// keeps forwarding.
	p := l.probe(t, a.tn, computeNode, "a-during-conflict", targetAddr(), 15*time.Second)
	svc := l.grantService(t, tenant{vpcNamespace: a.tn.vpcNamespace, vpc: a.tn.vpc, provider: tenantB.provider},
		"svc-conflict", func(s *galacticv1alpha1.EdgeService) { s.Spec.ClientPool = "fd00:ed9e:0:5::/64" })
	reason := l.waitServiceAdmitted(t, svc, false)
	l.record(t, "later overlapping grant", reason)
	if reason != "PrefixConflict" {
		t.Errorf("a later grant of the same prefixes: %s, want PrefixConflict", reason)
	}
	evs := p.wait(l, t)
	l.deleteAndWait(t, svc)
	rs := replies(evs)
	l.record(t, "A's largest reply gap", largestGap(rs))
	if len(rs) < sentCount(evs)*9/10 || largestGap(rs) > time.Second {
		t.Errorf("A answered %d of %d with a %v gap while the conflict was refused", len(rs), sentCount(evs),
			largestGap(rs))
	}
}

func rowOverlappingPrefixes(t *testing.T, l *lab, a *side, pa netip.Prefix) {
	// A second instance of provider A claims the /56 that holds A's /64.
	wide := netip.MustParsePrefix("fd00:ed9e:100::/56")
	p := l.probe(t, a.tn, computeNode, "a-during-overlap", targetAddr(), 20*time.Second)
	l.deployProvider(t, a.tn.namespace, "a-wide", edgeNode2, a.config(wide.String()))
	var reason string
	eventually(t, time.Minute, time.Second, "refusal of "+wide.String(), func() (bool, error) {
		r := l.route(t, a.tn.namespace, a.vpcUID, wide)
		if r == nil {
			return false, nil
		}
		c := meta.FindStatusCondition(r.Status.Conditions, galacticv1alpha1.EdgeRouteClaimed)
		if c == nil || c.Status != metav1.ConditionFalse || c.Reason == "WaitingForFencing" ||
			c.Reason == "IndexRebuilt" {
			return false, nil
		}
		reason = c.Reason
		return true, nil
	})
	l.record(t, "overlapping /56", reason)
	if reason != "PrefixConflict" {
		t.Errorf("an overlapping /56: %s, want PrefixConflict", reason)
	}
	evs := p.wait(l, t)
	rs := replies(evs)
	if len(rs) < sentCount(evs)*9/10 || largestGap(rs) > time.Second {
		t.Errorf("A answered %d of %d with a %v gap while the /56 was refused", len(rs), sentCount(evs), largestGap(rs))
	}
	r := l.route(t, a.tn.namespace, a.vpcUID, wide)
	l.stopProvider(t, a.tn.namespace, "a-wide")
	if r != nil {
		l.deleteAndWait(t, r)
	}
	if cur := l.route(t, a.tn.namespace, a.vpcUID, pa); cur.Status.Accepted == nil ||
		cur.Status.Accepted.Attachment != a.att.Name {
		t.Errorf("A's route moved: %+v", cur.Status.Accepted)
	}
}

func rowForeignAttachment(t *testing.T, l *lab, a *side, pa netip.Prefix) {
	ctx := context.Background()
	a.refresh(t, l)
	tp := l.tokenPod(t, a.tn.namespace, "token-a", edgeNode1)
	ca := l.asPod(t, tp)
	instanceFor(t, ca, tp, a.tn.provider)
	foreign := func(epoch int64) *galacticv1alpha1.EdgeRouteClaim {
		return &galacticv1alpha1.EdgeRouteClaim{Attachment: a.att.Name, HolderPodUID: string(tp.UID),
			HolderInstance: "ei-" + string(tp.UID), InstanceEpoch: 1, Epoch: epoch}
	}
	// refusal waits for core's decision on the token pod's claim. Route
	// conditions carry no observedGeneration, so the decision is the
	// Claimed condition whose message names the token pod.
	refusal := func(p netip.Prefix) string {
		var reason string
		eventually(t, time.Minute, 500*time.Millisecond, "core's decision on "+p.String(), func() (bool, error) {
			r := l.route(t, a.tn.namespace, a.vpcUID, p)
			if r == nil {
				return false, nil
			}
			c := meta.FindStatusCondition(r.Status.Conditions, galacticv1alpha1.EdgeRouteClaimed)
			if c == nil || !strings.Contains(c.Message, string(tp.UID)) {
				return false, nil
			}
			reason = c.Reason
			return true, nil
		})
		return reason
	}

	// At create: a route for an unclaimed prefix naming A's attachment.
	fresh := netip.MustParsePrefix("fd00:ed9e:100:2::/64")
	created := &galacticv1alpha1.EdgeRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: a.tn.namespace, Name: "conformance-foreign"},
		Spec: galacticv1alpha1.EdgeRouteSpec{ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: a.tn.provider},
			VPCUID: a.vpcUID, Prefix: fresh.String(), Incarnation: fixtureTag, Claim: foreign(1)},
	}
	if err := ca.Create(ctx, created); err != nil {
		t.Fatalf("route created for itself: %v", err)
	}
	reason := refusal(fresh)
	l.record(t, "new route on another pod's attachment", reason)
	if reason != "IdentityMismatch" {
		t.Errorf("a new route on another pod's attachment: %s, want IdentityMismatch", reason)
	}
	if r := l.route(t, a.tn.namespace, a.vpcUID, fresh); r.Status.Accepted != nil {
		t.Errorf("the route was accepted: %+v", r.Status.Accepted)
	}
	l.deleteAndWait(t, created)

	// On takeover: A's own route, swapped to a new epoch for the token
	// pod, still naming A's attachment. A is the accepted holder, so it
	// leaves the claim for core to refuse.
	p := l.probe(t, a.tn, computeNode, "a-during-foreign-claim", targetAddr(), 10*time.Second)
	r := l.route(t, a.tn.namespace, a.vpcUID, pa)
	r.Spec.Claim = foreign(r.Spec.Claim.Epoch + 1)
	if err := ca.Update(ctx, r); err != nil {
		t.Fatalf("claim of a new epoch for itself: %v", err)
	}
	reason = refusal(pa)
	l.record(t, "takeover on another pod's attachment", reason)
	if reason != "IdentityMismatch" {
		t.Errorf("a takeover on another pod's attachment: %s, want IdentityMismatch", reason)
	}
	evs := p.wait(l, t)
	rs := replies(evs)
	for _, e := range rs {
		if !strings.HasPrefix(e.Reply, a.tn.provider+"/"+a.pod.Name+"/") {
			t.Fatalf("answered by %q", e.Reply)
		}
	}
	l.record(t, "A's largest reply gap", largestGap(rs))
	if len(rs) < sentCount(evs)*9/10 {
		t.Errorf("A answered %d of %d during the foreign claim", len(rs), sentCount(evs))
	}
	if cur := l.route(t, a.tn.namespace, a.vpcUID, pa); cur.Status.Accepted.Attachment != a.att.Name {
		t.Errorf("the accepted holder moved to %s", cur.Status.Accepted.Attachment)
	}
	// Put A's own claim back, as the operator would, so later rows start
	// from A holding both the claim and the acceptance.
	cur := l.route(t, a.tn.namespace, a.vpcUID, pa)
	acc := cur.Status.Accepted
	cur.Spec.Claim = &galacticv1alpha1.EdgeRouteClaim{Attachment: acc.Attachment, HolderPodUID: string(a.pod.UID),
		HolderInstance: acc.Instance, InstanceEpoch: acc.InstanceEpoch, Epoch: cur.Spec.Claim.Epoch + 1}
	if err := l.c.Update(ctx, cur); err != nil {
		t.Fatal(err)
	}
	l.waitAccepted(t, a.tn.namespace, a.vpcUID, pa, a.att.Name, time.Minute)
}

func rowSubnet(t *testing.T, l *lab, a *side, pa netip.Prefix) {
	ctx := context.Background()
	p := l.probe(t, a.tn, computeNode, "a-subnet", targetAddr(), 30*time.Second)
	time.Sleep(3 * time.Second)
	// A workload subnet created over the route: the platform's IPAM writes
	// it in a VPCAttachment's status.
	va := &cloudv1alpha1.VPCAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: a.tn.vpcNamespace, Name: "edge-conformance-subnet"},
		Spec: cloudv1alpha1.VPCAttachmentSpec{VPC: cloudv1alpha1.VPCRef{Name: a.tn.vpc},
			Interface: cloudv1alpha1.VPCAttachmentInterface{Name: "eth9"}},
	}
	if err := l.c.Create(ctx, va); err != nil {
		t.Fatal(err)
	}
	recorded := boottime()
	va.Status.PodSubnet = prefix
	if err := l.c.Status().Update(ctx, va); err != nil {
		t.Fatal(err)
	}
	evs := p.wait(l, t)
	l.deleteAndWait(t, va)
	rs := windowed(evs)
	stop, ok := stopAfter(rs, recorded)
	if !ok {
		t.Fatalf("forwarding never stopped after the subnet was created")
	}
	l.record(t, "forwarding stopped after the subnet", stop-recorded)
	if stop-recorded > localExpiry {
		t.Errorf("forwarding stopped %v after the subnet, bound %v", stop-recorded, localExpiry)
	}
	r := l.route(t, a.tn.namespace, a.vpcUID, pa)
	if c := meta.FindStatusCondition(r.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted); c != nil {
		l.record(t, "route condition after the subnet", c.Reason)
	}
	// With the subnet gone, A claims a new epoch and is accepted again.
	l.waitAccepted(t, a.tn.namespace, a.vpcUID, pa, a.att.Name, 2*time.Minute)
	l.waitReachable(t, a)
}

// gateWindow probes A's prefix from the compute node while act runs, and
// returns the replies.
func gateWindow(t *testing.T, l *lab, a *side, name string, d time.Duration, act func()) []event {
	t.Helper()
	p := l.probe(t, a.tn, computeNode, name, targetAddr(), d)
	time.Sleep(2 * time.Second)
	act()
	return windowed(p.wait(l, t))
}

func rowCrash(t *testing.T, l *lab, a *side, pa netip.Prefix) {
	a.refresh(t, l)
	var last, killed time.Duration
	rs := gateWindow(t, l, a, "crash", 55*time.Second, func() {
		killed = boottime()
		if err := signal(a.node, a.pod.Namespace, a.pod.Name, "edge-provider", "KILL"); err != nil {
			t.Fatal(err)
		}
		last = a.lastRenewal(t, l)
	})
	stop, ok := stopAfter(rs, killed)
	if !ok {
		t.Fatal("forwarding never stopped after SIGKILL")
	}
	// The process is gone, so the stop is the data plane going with it;
	// the gate's own bound is checked by 11b. Here: nothing reopens until
	// the restarted process holds a new epoch, and it resumes in time.
	l.record(t, "last forwarded after the last renewal", stop-last)
	resume, ok := resumeAfter(rs, stop+time.Second)
	if !ok {
		t.Fatal("forwarding never resumed after the restart")
	}
	started := l.containerStart(t, a)
	l.record(t, "outage", resume-stop)
	l.record(t, "resumed after the restarted process started", resume-started)
	if resume-started > takeoverWait+5*time.Second {
		t.Errorf("forwarding resumed %v after the restarted process started, want TakeoverWait %v plus the 1 s "+
			"accept-and-apply target (measured, with 4 s of slack for the process's first read)",
			resume-started, takeoverWait)
	}
	r := l.route(t, a.tn.namespace, a.vpcUID, pa)
	l.record(t, "route epoch after restart", r.Spec.Claim.Epoch)
}

// containerStart returns when a's provider container last started.
func (l *lab) containerStart(t *testing.T, a *side) time.Duration {
	t.Helper()
	var pod corev1.Pod
	if err := l.c.Get(context.Background(), client.ObjectKeyFromObject(a.pod), &pod); err != nil {
		t.Fatal(err)
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Running != nil {
			return wallToBoot(cs.State.Running.StartedAt.Time)
		}
	}
	t.Fatal("provider container is not running")
	return 0
}

func rowStall(t *testing.T, l *lab, a *side, pa netip.Prefix) {
	a.refresh(t, l)
	pid := podPID(t, a.node, a.pod.Namespace, a.pod.Name)
	// SIGSTOP stops the provider's data plane too, so the gate is watched
	// on the provider's packet device: a probe that reaches it passed the
	// gate.
	sniff, err := startProbe(a.node, pid, "sniff-stall", "sniff", "-iface", a.att.Status.PacketDevice,
		"-port", strconv.Itoa(echoPort), "-duration", "40s")
	if err != nil {
		t.Fatal(err)
	}
	p := l.probe(t, a.tn, computeNode, "stall", targetAddr(), 38*time.Second)
	time.Sleep(3 * time.Second)
	if err := signal(a.node, a.pod.Namespace, a.pod.Name, "edge-provider", "STOP"); err != nil {
		t.Fatal(err)
	}
	resumed := false
	defer func() {
		if !resumed {
			_ = signal(a.node, a.pod.Namespace, a.pod.Name, "edge-provider", "CONT")
		}
	}()
	last := a.lastRenewal(t, l)
	time.Sleep(25 * time.Second)
	cont := boottime()
	if err := signal(a.node, a.pod.Namespace, a.pod.Name, "edge-provider", "CONT"); err != nil {
		t.Fatal(err)
	}
	resumed = true
	p.wait(l, t)
	seen := sniff.wait(l, t)
	arrivals := windowed(seen)
	stop, ok := stopAfter(arrivals, last)
	if !ok {
		t.Fatal("the gate never closed while the provider was stopped")
	}
	l.record(t, "gate closed after the last renewal start", stop-last)
	if stop-last > localExpiry {
		t.Errorf("the gate closed %v after the last renewal start, bound %v", stop-last, localExpiry)
	}
	if again, ok := resumeAfter(arrivals, stop+time.Second); ok && again < cont {
		t.Errorf("the gate reopened %v before the provider resumed", cont-again)
	}
	// Resumed, the provider finds its lease expired and reacquires it.
	a.refresh(t, l)
	l.waitAccepted(t, a.tn.namespace, a.vpcUID, pa, a.att.Name, 2*time.Minute)
	l.waitReachable(t, a)
}

func rowFrozen(t *testing.T, l *lab, a *side, pa netip.Prefix) {
	a.refresh(t, l)
	// The frozen pod never recovers: it is replaced whatever the outcome,
	// so later rows start from a serving instance.
	hung, hungAtt := a.pod, a.att.Name
	defer func() {
		_ = l.c.Delete(context.Background(), hung)
		a.refresh(t, l)
		if a.att.Name == hungAtt {
			t.Errorf("the replacement reused the hung pod's attachment %s", hungAtt)
		}
		l.waitAccepted(t, a.tn.namespace, a.vpcUID, pa, a.att.Name, 2*time.Minute)
	}()
	// SIGUSR1: the provider stops renewing and writing to the API but keeps
	// answering, so every reply after its deadline would be the
	// foundation failing to stop it.
	var last time.Duration
	rs := gateWindow(t, l, a, "frozen", 30*time.Second, func() {
		if err := signal(a.node, a.pod.Namespace, a.pod.Name, "edge-provider", "USR1"); err != nil {
			t.Fatal(err)
		}
		last = a.lastRenewal(t, l)
	})
	stop, ok := stopAfter(rs, last)
	if !ok {
		t.Fatal("the gate never closed on a provider that stopped renewing")
	}
	l.record(t, "last reply after the last renewal start", stop-last)
	if stop-last > localExpiry {
		t.Errorf("forwarding continued %v after the last renewal start, bound %v", stop-last, localExpiry)
	}
	if again, ok := resumeAfter(rs, stop+time.Second); ok {
		t.Errorf("forwarding resumed at +%v with no renewal", again-last)
	}
}

func rowReplacement(t *testing.T, l *lab, a *side, pa netip.Prefix) {
	a.refresh(t, l)
	oldPod, oldAtt := a.pod, a.att
	sniffOld, err := startProbe(a.node, podPID(t, a.node, oldPod.Namespace, oldPod.Name), "sniff-old", "sniff",
		"-iface", oldAtt.Status.PacketDevice, "-port", strconv.Itoa(echoPort), "-duration", "120s")
	if err != nil {
		t.Fatal(err)
	}
	p := l.probe(t, a.tn, computeNode, "replacement", targetAddr(), 118*time.Second)
	// A second instance of the provider, on the other edge node, claims
	// the same prefix while the first one keeps renewing: its claim is a
	// takeover of a live holder.
	b := &side{tn: a.tn, svc: a.svc, vpcUID: a.vpcUID, deploy: "a2", node: edgeNode2}
	l.deployProvider(t, a.tn.namespace, b.deploy, b.node, b.config(prefix))
	b.refresh(t, l)
	sniffNew, err := startProbe(b.node, podPID(t, b.node, b.pod.Namespace, b.pod.Name), "sniff-new", "sniff",
		"-iface", b.att.Status.PacketDevice, "-port", strconv.Itoa(echoPort), "-duration", "100s")
	if err != nil {
		t.Fatal(err)
	}
	var claimed bool
	eventually(t, time.Minute, time.Second, "the second instance's claim", func() (bool, error) {
		r := l.route(t, a.tn.namespace, a.vpcUID, pa)
		claimed = r.Spec.Claim != nil && r.Spec.Claim.Attachment == b.att.Name
		return claimed, nil
	})
	// While the first instance renews, core must keep it as the accepted
	// holder for at least two takeover intervals.
	contested := time.Now()
	for time.Since(contested) < 2*takeoverWait {
		r := l.route(t, a.tn.namespace, a.vpcUID, pa)
		if r.Status.Accepted == nil || r.Status.Accepted.Attachment != oldAtt.Name {
			t.Errorf("core moved the route to %+v while its holder still renewed", r.Status.Accepted)
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	l.record(t, "contested for", time.Since(contested).Round(time.Second))
	// The first instance shuts down: it stops forwarding and deletes its
	// attachment, so its node closes the gate and core moves the route.
	l.stopProvider(t, a.tn.namespace, a.deploy)
	r := l.waitAccepted(t, a.tn.namespace, a.vpcUID, pa, b.att.Name, 2*time.Minute)
	l.record(t, "closedEpoch of the old holder", r.Status.ClosedEpoch)
	evs := p.wait(l, t)
	seenOld, seenNew := sniffOld.wait(l, t), sniffNew.wait(l, t)
	if len(seenOld) == 0 || len(seenNew) == 0 {
		t.Fatalf("captured %d packets at the old node and %d at the new", len(seenOld), len(seenNew))
	}
	lastOld, firstNew := seenOld[len(seenOld)-1].T, seenNew[0].T
	l.record(t, "last packet at the old node to first at the new", firstNew-lastOld)
	if firstNew <= lastOld {
		t.Errorf("both nodes forwarded the prefix: the new node's first packet came %v before the old node's last",
			lastOld-firstNew)
	}
	l.record(t, "outage seen by the client", largestGap(replies(evs)))
	// The rest of the suite runs on the second instance.
	a.deploy, a.node = b.deploy, b.node
	a.refresh(t, l)
}

func rowRemovalAgentStuck(t *testing.T, l *lab, a *side, pa netip.Prefix) {
	ctx := context.Background()
	a.refresh(t, l)
	agent := l.agentPod(t, a.node)
	var deleted time.Duration
	rs := gateWindow(t, l, a, "removal-agent-stuck", 50*time.Second, func() {
		if err := signal(a.node, "galactic-system", agent, "galactic-edge", "STOP"); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = signal(a.node, "galactic-system", agent, "galactic-edge", "CONT") }()
		r := l.route(t, a.tn.namespace, a.vpcUID, pa)
		deleted = boottime()
		if err := l.c.Delete(ctx, r); err != nil {
			t.Fatal(err)
		}
		time.Sleep(25 * time.Second)
		if err := signal(a.node, "galactic-system", agent, "galactic-edge", "CONT"); err != nil {
			t.Fatal(err)
		}
	})
	stop, ok := stopAfter(rs, deleted)
	if !ok {
		t.Fatal("forwarding never stopped after the route was deleted")
	}
	l.record(t, "forwarding stopped after the deletion", stop-deleted)
	if stop-deleted > localExpiry {
		t.Errorf("forwarding stopped %v after the deletion, bound %v", stop-deleted, localExpiry)
	}
	// The provider recreates the route; it is a first claim only once the
	// deleted route's entry left the index, TakeoverWait after deletion.
	r := l.waitAccepted(t, a.tn.namespace, a.vpcUID, pa, a.att.Name, 2*time.Minute)
	if c := meta.FindStatusCondition(r.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted); c != nil {
		accepted := wallToBoot(c.LastTransitionTime.Time)
		l.record(t, "recreated route accepted after the deletion (1 s resolution)", accepted-deleted)
		if accepted-deleted < takeoverWait-time.Second {
			t.Errorf("the recreated route was accepted %v after the deletion, before TakeoverWait %v",
				accepted-deleted, takeoverWait)
		}
	}
	l.waitReachable(t, a)
}

// agentPod returns the galactic-edge pod on node.
func (l *lab) agentPod(t *testing.T, node string) string {
	t.Helper()
	var pods corev1.PodList
	if err := l.c.List(context.Background(), &pods, client.InNamespace("galactic-system"),
		client.MatchingLabels{"app.kubernetes.io/name": "galactic-edge"}); err != nil {
		t.Fatal(err)
	}
	for _, p := range pods.Items {
		if p.Spec.NodeName == node && p.Status.Phase == corev1.PodRunning && p.DeletionTimestamp == nil {
			return p.Name
		}
	}
	t.Fatalf("no galactic-edge pod on %s", node)
	return ""
}

func rowAgentStall(t *testing.T, l *lab, a *side, pa netip.Prefix) {
	a.refresh(t, l)
	agent := l.agentPod(t, a.node)
	var last, cont time.Duration
	rs := gateWindow(t, l, a, "agent-stall", 50*time.Second, func() {
		if err := signal(a.node, "galactic-system", agent, "galactic-edge", "STOP"); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = signal(a.node, "galactic-system", agent, "galactic-edge", "CONT") }()
		// The agent applied no renewal after it stopped, so the latest one
		// it can have applied started no later than this one.
		last = a.renewStart(t, l)
		time.Sleep(25 * time.Second)
		cont = boottime()
		if err := signal(a.node, "galactic-system", agent, "galactic-edge", "CONT"); err != nil {
			t.Fatal(err)
		}
	})
	stop, ok := stopAfter(rs, last)
	if !ok {
		t.Fatal("forwarding never stopped with galactic-edge stopped")
	}
	l.record(t, "forwarding stopped after the last renewal start", stop-last)
	if stop-last > localExpiry {
		t.Errorf("forwarding stopped %v after the last renewal start, bound %v", stop-last, localExpiry)
	}
	resume, ok := resumeAfter(rs, stop+time.Second)
	if !ok {
		t.Fatal("forwarding never resumed after galactic-edge resumed")
	}
	if resume < cont {
		t.Errorf("forwarding reopened %v before galactic-edge resumed", cont-resume)
	}
	renewed := a.renewStart(t, l)
	l.record(t, "resumed after galactic-edge resumed", resume-cont)
	if renewed < cont && resume > cont {
		l.record(t, "note", "latest renewal read after resume started before CONT")
	}
	l.waitAccepted(t, a.tn.namespace, a.vpcUID, pa, a.att.Name, time.Minute)
}

func rowAgentRestart(t *testing.T, l *lab, a *side) {
	a.refresh(t, l)
	agent := l.agentPod(t, a.node)
	rs := gateWindow(t, l, a, "agent-restart", 30*time.Second, func() {
		if err := l.c.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "galactic-system", Name: agent}}); err != nil {
			t.Fatal(err)
		}
	})
	l.record(t, "largest reply gap across the restart", largestGap(rs))
	if g := largestGap(rs); g > agentRestartGap {
		t.Errorf("forwarding stopped for %v while galactic-edge restarted, threshold %v", g, agentRestartGap)
	}
}

func rowRouterDown(t *testing.T, l *lab, a *side) {
	a.refresh(t, l)
	router := l.podOn(t, "galactic-system", "galactic-router", a.node)
	var stopped time.Duration
	rs := gateWindow(t, l, a, "router-down", 40*time.Second, func() {
		stopped = boottime()
		if err := signal(a.node, "galactic-system", router, "galactic-router", "STOP"); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = signal(a.node, "galactic-system", router, "galactic-router", "CONT") }()
		time.Sleep(25 * time.Second)
		if err := signal(a.node, "galactic-system", router, "galactic-router", "CONT"); err != nil {
			t.Fatal(err)
		}
	})
	stop, ok := stopAfter(rs, stopped)
	if !ok {
		t.Fatal("the compute node kept reaching the prefix with the holder's router stopped")
	}
	// The compute node loses the path only after the route reflector
	// withdrew it, so a loss within the bound shows the reflector withdrew
	// in time; a later loss would include propagation and is not decisive.
	l.record(t, "compute node lost the path after the router stopped", stop-stopped)
	if stop-stopped > routerHoldBound {
		t.Errorf("the compute node lost the path %v after the router stopped; the reflector's bound is %v, "+
			"plus up to the 5 s remote convergence target", stop-stopped, routerHoldBound)
	}
	l.waitReachable(t, a)
}

// podOn returns the running pod of a DaemonSet-style label on node.
func (l *lab) podOn(t *testing.T, namespace, name, node string) string {
	t.Helper()
	var pods corev1.PodList
	if err := l.c.List(context.Background(), &pods, client.InNamespace(namespace)); err != nil {
		t.Fatal(err)
	}
	for _, p := range pods.Items {
		if p.Spec.NodeName == node && strings.HasPrefix(p.Name, name+"-") && p.Status.Phase == corev1.PodRunning &&
			len(p.Spec.Containers) > 0 && p.Spec.Containers[0].Name == name {
			return p.Name
		}
	}
	t.Fatalf("no %s pod on %s", name, node)
	return ""
}

func rowRevocation(t *testing.T, l *lab, a *side, pa netip.Prefix) {
	ctx := context.Background()
	var revoked time.Duration
	rs := gateWindow(t, l, a, "revocation", 25*time.Second, func() {
		if err := l.c.Get(ctx, client.ObjectKeyFromObject(a.svc), a.svc); err != nil {
			t.Fatal(err)
		}
		a.svc.Spec.Prefixes = []string{"fd00:ed9e:300::/48"}
		revoked = boottime()
		if err := l.c.Update(ctx, a.svc); err != nil {
			t.Fatal(err)
		}
	})
	stop, ok := stopAfter(rs, revoked)
	if !ok {
		t.Fatal("forwarding never stopped after the prefix left the grant")
	}
	l.record(t, "forwarding stopped after the revocation", stop-revoked)
	if stop-revoked > localExpiry {
		t.Errorf("forwarding stopped %v after the revocation, bound %v (target 2 s)", stop-revoked, localExpiry)
	}
	if err := l.c.Get(ctx, client.ObjectKeyFromObject(a.svc), a.svc); err != nil {
		t.Fatal(err)
	}
	a.svc.Spec.Prefixes = []string{grant}
	if err := l.c.Update(ctx, a.svc); err != nil {
		t.Fatal(err)
	}
	a.refresh(t, l)
	l.waitAccepted(t, a.tn.namespace, a.vpcUID, pa, a.att.Name, 2*time.Minute)
	l.waitReachable(t, a)
}

func rowPolicy(t *testing.T, l *lab, a *side) {
	ctx := context.Background()
	setPolicy := func(ingress string) {
		t.Helper()
		if err := l.c.Get(ctx, client.ObjectKeyFromObject(a.svc), a.svc); err != nil {
			t.Fatal(err)
		}
		a.svc.Spec.TrafficPolicy.IngressPolicyRef = &galacticv1alpha1.LocalPolicyReference{Name: ingress}
		if err := l.c.Update(ctx, a.svc); err != nil {
			t.Fatal(err)
		}
	}
	// Row 20: a policy denying the probe's port, then the original back.
	deny := &galacticv1alpha1.TrafficPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: a.tn.vpcNamespace, Name: "edge-conformance-deny-echo"},
		Spec: galacticv1alpha1.TrafficPolicySpec{Rules: []galacticv1alpha1.TrafficRule{
			{Name: "deny-echo", Action: galacticv1alpha1.ActionDeny, Match: &galacticv1alpha1.TrafficRuleMatch{
				Protocol:         ptr.To(galacticv1alpha1.ProtocolUDP),
				DestinationPorts: []galacticv1alpha1.PortRange{{Start: echoPort, End: echoPort}},
			}},
			{Name: "allow", Action: galacticv1alpha1.ActionAllow},
		}},
	}
	if err := l.c.Create(ctx, deny); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	defer func() { _ = l.c.Delete(ctx, deny) }()
	for _, step := range []struct {
		name, policy string
		reachable    bool
	}{
		{"policy denying the port", deny.Name, false},
		{"original policy", labIngress, true},
		{"missing policy (row 19)", "edge-conformance-missing", false},
		{"original policy again", labIngress, true},
	} {
		changed := boottime()
		setPolicy(step.policy)
		var at time.Duration
		eventually(t, 30*time.Second, 500*time.Millisecond, step.name+" applied", func() (bool, error) {
			p, err := startProbe(computeNode, l.clientPID(t, a.tn, computeNode), "policy", "send", "-to", targetAddr(),
				"-interval", "50ms", "-duration", "1s")
			if err != nil {
				return false, err
			}
			_ = p.cmd.Wait()
			got := strings.Contains(p.out.String(), a.tn.provider+"/")
			at = boottime()
			return got == step.reachable, nil
		})
		l.record(t, step.name+" took effect within", at-changed)
	}
}

func rowGC(t *testing.T, l *lab, a *side) {
	ctx := context.Background()
	// Leave the edge attachment the VPC's only user on its node: scale the
	// tenant's client there to zero, then let galactic-router's GC run.
	i := map[string]string{edgeNode1: "2", edgeNode2: "3"}[a.node]
	d := &appsv1.Deployment{}
	key := client.ObjectKey{Namespace: a.tn.vpcNamespace, Name: "edge-client-" + i}
	if err := l.c.Get(ctx, key, d); err != nil {
		t.Fatal(err)
	}
	d.Spec.Replicas = ptr.To[int32](0)
	if err := l.c.Update(ctx, d); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := l.c.Get(ctx, key, d); err == nil {
			d.Spec.Replicas = ptr.To[int32](1)
			_ = l.c.Update(ctx, d)
		}
	}()
	interval := l.gcInterval(t)
	l.record(t, "galactic-router GC interval", interval)
	time.Sleep(interval + 30*time.Second)
	vrf := fmt.Sprintf("G%09sV", a.att.Status.VPC)
	if _, err := nodeExec(a.node, "ip", "link", "show", vrf); err != nil {
		t.Errorf("the VPC's VRF %s is gone from %s with an edge attachment still on it: %v", vrf, a.node, err)
	}
	l.reachable(t, a, computeNode)
}

// gcInterval reads galactic-router's GC interval from its DaemonSet.
func (l *lab) gcInterval(t *testing.T) time.Duration {
	t.Helper()
	var ds appsv1.DaemonSet
	if err := l.c.Get(context.Background(), client.ObjectKey{Namespace: "galactic-system", Name: "galactic-router"},
		&ds); err != nil {
		t.Fatal(err)
	}
	for _, c := range ds.Spec.Template.Spec.Containers {
		for _, arg := range c.Args {
			if v, ok := strings.CutPrefix(arg, "--gc-interval="); ok {
				if d, err := time.ParseDuration(v); err == nil {
					return d
				}
			}
		}
		for _, e := range c.Env {
			if e.Name == "GALACTIC_ROUTER_GC_INTERVAL" {
				if d, err := time.ParseDuration(e.Value); err == nil {
					return d
				}
			}
		}
	}
	return 5 * time.Minute
}

func rowCeiling(t *testing.T, l *lab, a *side, pa netip.Prefix) {
	ctx := context.Background()
	until := time.Now().Add(40 * time.Second).Truncate(time.Second)
	if err := l.c.Get(ctx, client.ObjectKeyFromObject(a.svc), a.svc); err != nil {
		t.Fatal(err)
	}
	a.svc.Spec.ValidUntil = &metav1.Time{Time: until}
	if err := l.c.Update(ctx, a.svc); err != nil {
		t.Fatal(err)
	}
	rs := replies(l.probe(t, a.tn, computeNode, "ceiling", targetAddr(), 50*time.Second).wait(l, t))
	ceiling := wallToBoot(until) - maxSkew
	if len(rs) == 0 {
		t.Fatal("no replies before the ceiling")
	}
	last := rs[len(rs)-1].T
	l.record(t, "last reply relative to validUntil - MaxSkew", last-ceiling)
	// The provider renews until then, so forwarding must have lasted to
	// within a probe gap of the ceiling: a stop well before it is a drain
	// or revocation, not the ceiling.
	if last < ceiling-stopGap-margin {
		t.Errorf("forwarding stopped %v before validUntil - MaxSkew; the ceiling was never reached", ceiling-last)
	}
	// The gate's deadline is capped at validUntil - MaxSkew; forwarding
	// stops within Margin of a deadline.
	if last > ceiling+margin {
		t.Errorf("forwarding continued %v past validUntil - MaxSkew, allowed Margin %v", last-ceiling, margin)
	}
	// The expired grant drains its attachments; restore it as a new grant.
	a.svc = l.grantService(t, a.tn, a.tn.service, nil)
	l.waitServiceAdmitted(t, a.svc, true)
	l.redeploy(t, a)
	l.waitAccepted(t, a.tn.namespace, a.vpcUID, pa, a.att.Name, 3*time.Minute)
}

// redeploy reapplies a's provider for its current grant, which rolls its
// pods, and waits for a pod created since to serve.
func (l *lab) redeploy(t *testing.T, a *side) {
	t.Helper()
	before := time.Now().Add(-time.Second)
	l.deployProvider(t, a.tn.namespace, a.deploy, a.node, a.config(prefix))
	eventually(t, 3*time.Minute, time.Second, "a new pod of "+a.deploy, func() (bool, error) {
		p := l.providerPod(t, a.tn.namespace, a.deploy)
		return p != nil && p.CreationTimestamp.After(before), nil
	})
	a.refresh(t, l)
}

func rowDrain(t *testing.T, l *lab, a, b *side) {
	ctx := context.Background()
	a.refresh(t, l)
	host := a.att.Status.HostLink
	drain := time.Duration(ptr.Deref(a.svc.Spec.DrainSeconds, 30)) * time.Second
	var deleted time.Duration
	rs := gateWindow(t, l, a, "drain", 30*time.Second, func() {
		deleted = boottime()
		if err := l.c.Delete(ctx, a.svc); err != nil {
			t.Fatal(err)
		}
	})
	stop, ok := stopAfter(rs, deleted)
	if !ok {
		t.Fatal("forwarding never stopped after the grant was deleted")
	}
	l.record(t, "forwarding stopped after the drain began", stop-deleted)
	if stop-deleted > drain+margin {
		t.Errorf("forwarding stopped %v after the drain began, drainSeconds %v", stop-deleted, drain)
	}
	// Deleting the grant also revokes its routes, so prefix forwarding
	// may end at once, well inside the window.
	eventually(t, time.Minute, time.Second, "release of "+a.att.Name, func() (bool, error) {
		return l.attachmentOf(t, a.pod, a.svc) == nil, nil
	})
	if _, err := nodeExec(a.node, "ip", "link", "show", host); err == nil {
		t.Errorf("host link %s remains after its attachment was released", host)
	}
	// The other tenant was untouched.
	l.reachable(t, b, computeNode)
}
