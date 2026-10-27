// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeconformance_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/admission"
)

// packetRequest is a PacketAccess EdgeAttachment pod writes for svc.
func packetRequest(pod *corev1.Pod, svc *galacticv1alpha1.EdgeService, contract, capVersion string,
) *galacticv1alpha1.EdgeAttachment {
	att := attachmentRequest(pod, masqueProvider, svc, contract, capVersion)
	att.Spec.Capabilities = []galacticv1alpha1.EdgeCapability{{Name: capPacket, Version: capVersion}}
	att.Spec.PacketDevice = &galacticv1alpha1.EdgePacketDevice{Owner: 65532, Group: 65532}
	return att
}

// rowRefusedRequests checks what the fixture's ServiceAccount cannot do. A
// pod under it may not write for another pod, is refused a service that
// does not exist and versions core or the provider does not implement, may
// not ask for packet access without a device owner, and is denied
// EdgeService, BGPAdvertisement, route index and status writes. Its token
// carries the pod-bound extras the admission policies read, and its only
// binding is the one core keeps for the approved provider.
func (m *masque) rowRefusedRequests(t *testing.T) {
	m.inUse(t)
	l, ctx := m.l, context.Background()
	tp := l.tokenPod(t, masqueNS, "token-masque", edgeNode1)
	defer l.deleteAndWait(t, tp)
	c := l.asPod(t, tp)
	instanceFor(t, c, tp, masqueProvider)

	forged := packetRequest(m.pod, m.a.svc, "v1alpha1", "v1")
	forged.Name += "x"
	requireRefused(t, "attachment naming another pod", c.Create(ctx, forged))

	missing := packetRequest(tp, m.a.svc, "v1alpha1", "v1")
	missing.Spec.PacketDevice = nil
	requireRefused(t, "PacketAccess without a device owner", c.Create(ctx, missing))

	unknown := m.a.svc.DeepCopy()
	unknown.UID = types.UID(strings.ToLower(rand.Text()))
	for _, tc := range []struct {
		name string
		att  *galacticv1alpha1.EdgeAttachment
		want string
	}{
		{"service that does not exist", packetRequest(tp, unknown, "v1alpha1", "v1"), ""},
		{"contract version the provider does not declare", packetRequest(tp, m.a.svc, "v1alpha9", "v1"),
			string(admission.UnsupportedContractVersion)},
		{"capability version the provider does not declare", packetRequest(tp, m.a.svc, "v1alpha1", "v2"),
			string(admission.UnsupportedCapability)},
	} {
		if err := c.Create(ctx, tc.att); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		reason := l.waitRefused(t, tc.att)
		l.record(t, tc.name, reason)
		if reason == "admitted" || (tc.want != "" && reason != tc.want) {
			t.Errorf("%s: %s, want refused%s", tc.name, reason, map[bool]string{true: " as " + tc.want}[tc.want != ""])
		}
		if l.allocated(t, m.a.svc, tc.att.Name) {
			t.Errorf("%s: the refused attachment holds an address", tc.name)
		}
		l.deleteAndWait(t, tc.att)
	}

	// The fixture's own pod, under its own token.
	own := l.asPod(t, m.pod)
	svc := &galacticv1alpha1.EdgeService{ObjectMeta: metav1.ObjectMeta{Namespace: m.a.tn.vpcNamespace, Name: "forged"},
		Spec: *m.a.svc.Spec.DeepCopy()}
	requireRefused(t, "EdgeService write", own.Create(ctx, svc))
	adv := &networkv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{Namespace: systemNS, Name: "forged-masque"}}
	requireRefused(t, "BGPAdvertisement write", own.Create(ctx, adv))
	var idx galacticv1alpha1.EdgeRouteIndex
	if err := l.c.Get(ctx, client.ObjectKey{Namespace: m.a.tn.vpcNamespace, Name: m.a.vpcUID}, &idx); err != nil {
		t.Fatalf("VPC 10's route index: %v", err)
	}
	idx.Spec.Rebuilt = !idx.Spec.Rebuilt
	requireRefused(t, "route index write", own.Update(ctx, &idx))
	r := l.route(t, masqueNS, m.a.vpcUID, netip.MustParsePrefix(masquePrefix))
	r.Status.ClosedEpoch = r.Spec.Claim.Epoch + 1
	requireRefused(t, "route status write", own.Status().Update(ctx, r))
	att := l.attachmentOf(t, m.pod, m.a.svc)
	att.Status.HostLink = "forged"
	requireRefused(t, "attachment host link write", own.Status().Update(ctx, att))

	review := &authv1.SelfSubjectReview{}
	if err := own.Create(ctx, review); err != nil {
		t.Fatalf("self subject review: %v", err)
	}
	extra := review.Status.UserInfo.Extra
	l.record(t, "fixture token user", review.Status.UserInfo.Username)
	l.record(t, "fixture token pod extras", fmt.Sprintf("pod-uid=%v node-name=%v",
		extra["authentication.kubernetes.io/pod-uid"], extra["authentication.kubernetes.io/node-name"]))
	if !slices.Equal(extra["authentication.kubernetes.io/pod-uid"], []string{string(m.pod.UID)}) ||
		!slices.Equal(extra["authentication.kubernetes.io/node-name"], []string{m.pod.Spec.NodeName}) {
		t.Errorf("the fixture's token does not carry its pod UID and node: %v", extra)
	}

	var bindings []string
	var rbs rbacv1.RoleBindingList
	if err := l.c.List(ctx, &rbs); err != nil {
		t.Fatal(err)
	}
	for _, rb := range rbs.Items {
		if subjectIsFixture(rb.Subjects) {
			bindings = append(bindings, rb.Namespace+"/"+rb.Name+" -> "+rb.RoleRef.Kind+"/"+rb.RoleRef.Name)
		}
	}
	var crbs rbacv1.ClusterRoleBindingList
	if err := l.c.List(ctx, &crbs); err != nil {
		t.Fatal(err)
	}
	for _, crb := range crbs.Items {
		if subjectIsFixture(crb.Subjects) {
			t.Errorf("ClusterRoleBinding %s binds the fixture's ServiceAccount cluster-wide", crb.Name)
		}
	}
	l.record(t, "fixture RoleBindings", strings.Join(bindings, "; "))
	if len(bindings) != 1 || !strings.HasSuffix(bindings[0], " -> ClusterRole/galactic-edge-provider") {
		t.Errorf("fixture bindings %v, want only core's galactic-edge-provider binding", bindings)
	}
}

func subjectIsFixture(subjects []rbacv1.Subject) bool {
	return slices.ContainsFunc(subjects, func(s rbacv1.Subject) bool {
		return s.Kind == rbacv1.ServiceAccountKind && s.Namespace == masqueNS && s.Name == providerSA
	})
}

// rowMissingDevice runs a fixture pod without /dev/net/tun. A connector's
// request gets its attachment programmed, but the fixture cannot open the
// packet device, so it reports the attachment not ready, refuses the
// request and claims no route: nothing forwards.
func (m *masque) rowMissingDevice(t *testing.T) {
	l := m.l
	token := rand.Text()
	b := marshalConfig([]fixtureService{m.a.serviceConfig()}, []fixtureConnector{{ID: "connector-nodev",
		Credential: token, Service: m.a.serviceKey(), Prefix: masquePartial}})
	pod := m.deploy(t, "nodev", edgeNode1, b, `  - target:
      kind: Deployment
    patch: |-
      - op: remove
        path: /spec/template/spec/containers/0/resources
`)
	defer func() {
		if _, err := l.kubectl("-n", masqueNS, "delete", "deployment", "masque-provider-nodev", "--wait=true",
			"--timeout=120s"); err != nil {
			t.Error(err)
		}
	}()
	dst := m.workload(t, m.a.tn, 2).addr
	var reason string
	eventually(t, 2*time.Minute, 2*time.Second, "the device-less pod's attachment reported", func() (bool, error) {
		evs, err := connectOnceTo(pod, token, "10", 1, time.Second, dst)
		if err != nil {
			return false, err
		}
		if s := status(evs); s == 200 || len(echoes(evs, dst)) > 0 {
			return false, fmt.Errorf("a pod with no packet device accepted a request: status %d", s)
		}
		att := l.attachmentOf(t, pod, m.a.svc)
		if att == nil || !meta.IsStatusConditionTrue(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentProgrammed) {
			return false, nil
		}
		c := meta.FindStatusCondition(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentReady)
		if c == nil || c.Status != metav1.ConditionFalse {
			return false, nil
		}
		reason = c.Reason + ": " + c.Message
		return true, nil
	})
	l.record(t, "attachment of a pod without /dev/net/tun", reason)
	if !strings.HasPrefix(reason, "DataPlaneFailed") {
		t.Errorf("attachment of a pod without /dev/net/tun: %s, want DataPlaneFailed", reason)
	}
	if r := l.route(t, masqueNS, m.a.vpcUID, netip.MustParsePrefix(masquePartial)); r != nil {
		t.Errorf("a pod with no packet device claimed route %s", r.Name)
	}
}

// rowRegistration records how the uSID datapath delivers to each fixture
// attachment. galactic-edge registers the attachment's host link, which is
// the host end of a veth whose peer is in the provider pod; the packet
// device sits behind that peer in the pod's VRF. So the host link is
// registered as a veth and delivered to with bpf_redirect_peer, never as a
// tap: the TUN device is not on the host. M07 proves both directions
// through it.
func (m *masque) rowRegistration(t *testing.T) {
	m.inUse(t)
	for _, mt := range []*masqueTenant{m.a, m.b} {
		att := m.l.attachmentOf(t, m.pod, mt.svc)
		link, err := nodeExec(edgeNode1, "ip", "-d", "-o", "link", "show", "dev", att.Status.HostLink)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(link, " veth ") {
			t.Errorf("VPC %s host link %s is not a veth: %s", mt.tn.vpc, att.Status.HostLink, link)
		}
		out, err := nodeExec(edgeNode1, "/usr/local/bin/edgeprobe", "egresskind", "-iface", att.Status.HostLink)
		if err != nil {
			t.Fatal(err)
		}
		var row struct {
			Kind    uint32 `json:"kind"`
			Present bool   `json:"present"`
		}
		if err := json.Unmarshal([]byte(out), &row); err != nil {
			t.Fatalf("egresskind: %v: %s", err, out)
		}
		m.l.record(t, "VPC "+mt.tn.vpc+" host link delivery", out)
		if !row.Present || row.Kind != 0 {
			t.Errorf("VPC %s host link %s: delivery row %+v, want a registered veth (kind 0)", mt.tn.vpc,
				att.Status.HostLink, row)
		}
	}
}

// rowRouteDrift adds a route through the fixture's pod link to its pod VRF,
// as a process with NET_ADMIN in the pod could, while a client is
// connected. galactic-edge removes it at its next pass, without taking the
// attachment out of service.
func (m *masque) rowRouteDrift(t *testing.T) {
	m.inUse(t)
	l := m.l
	att := l.attachmentOf(t, m.pod, m.a.svc)
	sandbox := strconv.Itoa(podPID(t, edgeNode1, m.pod.Namespace, m.pod.Name))
	inPod := func(args ...string) (string, error) {
		return nodeExec(edgeNode1, append([]string{"nsenter", "-t", sandbox, "-n"}, args...)...)
	}
	links, err := inPod("ip", "-o", "link", "show", "master", att.Status.PodVRF)
	if err != nil {
		t.Fatal(err)
	}
	var podLink string
	for _, line := range strings.Split(links, "\n") {
		if f := strings.Fields(line); len(f) > 1 {
			if name := strings.Split(strings.TrimSuffix(f[1], ":"), "@")[0]; name != att.Status.PacketDevice {
				podLink = name
			}
		}
	}
	if podLink == "" {
		t.Fatalf("no pod link in %s: %s", att.Status.PodVRF, links)
	}
	const stray = "fd00:dead:974::/64"
	dst := m.workload(t, m.a.tn, 2).addr
	p := m.connect(t, "drift-continuity", m.a.token, "10", m.a.id, 90*time.Second, dst)
	time.Sleep(3 * time.Second)
	if _, err := inPod("ip", "-6", "route", "add", stray, "dev", podLink, "vrf", att.Status.PodVRF); err != nil {
		t.Fatal(err)
	}
	added := time.Now()
	var repaired time.Duration
	eventually(t, 150*time.Second, time.Second, "stray route removed", func() (bool, error) {
		out, err := inPod("ip", "-6", "route", "show", "vrf", att.Status.PodVRF, stray)
		if err != nil {
			return false, err
		}
		cur := l.attachmentOf(t, m.pod, m.a.svc)
		if !meta.IsStatusConditionTrue(cur.Status.Conditions, galacticv1alpha1.EdgeAttachmentProgrammed) {
			t.Errorf("the attachment left Programmed while the stray route was present")
		}
		repaired = time.Since(added)
		return strings.TrimSpace(out) == "", nil
	})
	l.record(t, "stray pod link route removed after", repaired.Round(time.Second))
	evs := p.wait(l, t)
	requireSession(t, "the connected client's request", evs, 90*time.Second, 1)
	rs := echoes(evs, dst)
	l.record(t, "connected client across the repair", fmt.Sprintf("%d/%d, largest gap %v", len(rs),
		sentCount(evs), largestGap(rs)))
	if len(rs) < sentCount(evs)*9/10 || largestGap(rs) > time.Second {
		t.Errorf("connected client answered %d of %d with a %v gap across the repair", len(rs), sentCount(evs),
			largestGap(rs))
	}
}
