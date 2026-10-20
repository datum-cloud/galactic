// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// testNamespace holds every object these tests create.
const testNamespace = "default"

var policies = schema.GroupVersionResource{
	Group: "galactic.datumapis.com", Version: "v1alpha1", Resource: "trafficpolicies",
}

// startAPIServer installs the generated CRDs into a real API server. It needs
// envtest's kube-apiserver and etcd: set KUBEBUILDER_ASSETS (e.g.
// `setup-envtest use -p path`) to run it.
func startAPIServer(t *testing.T) (client.Client, dynamic.Interface) {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		// CI installs the binaries, so a missing path there is a broken
		// setup, not an environment to skip.
		if os.Getenv("CI") != "" {
			t.Fatal("KUBEBUILDER_ASSETS not set in CI")
		}
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	s := runtime.NewScheme()
	if err := galacticv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		t.Fatal(err)
	}
	return c, dynamic.NewForConfigOrDie(cfg)
}

// policyWithRules builds a TrafficPolicy from a JSON rules array, so a case
// can send exactly the fields, nulls and empty lists it means to.
func policyWithRules(t *testing.T, name, rules string) *unstructured.Unstructured {
	t.Helper()
	var r []any
	if err := json.Unmarshal([]byte(rules), &r); err != nil {
		t.Fatalf("%s: bad rules JSON: %v", name, err)
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "galactic.datumapis.com/v1alpha1",
		"kind":       "TrafficPolicy",
		"metadata":   map[string]any{"name": name, "namespace": testNamespace},
		"spec":       map[string]any{"rules": r},
	}}
}

// TestTrafficPolicySchema covers what the CRD alone admits and rejects. Null
// handling is the webhook's (see TestTrafficPolicyNullReachesAdmission).
func TestTrafficPolicySchema(t *testing.T) {
	_, dyn := startAPIServer(t)
	ctx := context.Background()
	res := dyn.Resource(policies).Namespace(testNamespace)

	const (
		notIP       = "must be an IPv4 or IPv6 address"
		badEnum     = "Unsupported value"
		atLeastOne  = "should have at least 1 items"
		familyMatch = "address family"
		portsNeed   = "ports require protocol"
	)
	// one wraps a single rule named "a" around a match object.
	one := func(action, match string) string {
		return `[{"name":"a","action":"` + action + `","match":` + match + `}]`
	}
	tests := []struct {
		name    string
		rules   string
		wantErr string // a substring of the rejection; empty means admitted
	}{
		{name: "default-deny-all", rules: `[{"name":"deny-all","action":"Deny"}]`},
		{name: "public-web-egress", rules: `[
			{"name":"https-through-nat","action":"Allow","match":{"path":"PublicNAT","protocol":"TCP",
			 "destinationPorts":[{"start":443,"end":443}]}},
			{"name":"deny-all","action":"Deny"}]`},
		{name: "address-pair", rules: one("Allow", `{"path":"Private","ipFamily":"IPv6",
			"sourceIPs":["2001:db8:10::10"],"destinationIPs":["2001:db8:20::20"],"protocol":"TCP",
			"destinationPorts":[{"start":8080,"end":8080}]}`)},
		{name: "source-only", rules: one("Allow", `{"sourceIPs":["192.0.2.1","2001:db8::1"]}`)},
		{name: "destination-cidr-only", rules: one("Deny", `{"destinationCIDRs":["10.0.0.0/8","2001:db8::/32"]}`)},
		{name: "ip-and-cidr-on-opposite-sides",
			rules: one("Allow", `{"sourceIPs":["192.0.2.1"],"destinationCIDRs":["198.51.100.0/24"]}`)},
		{name: "port-zero-and-adjacent-ranges", rules: one("Allow", `{"protocol":"UDP",
			"sourcePorts":[{"start":0,"end":0},{"start":1,"end":1023},{"start":1024,"end":65535}]}`)},
		{name: "icmp-type-and-code", rules: one("Allow", `{"protocol":"ICMPv6","icmp":{"type":2,"code":0}}`)},

		{name: "no-rules", rules: `[]`, wantErr: atLeastOne},
		{name: "unknown-action", rules: `[{"name":"a","action":"Reject"}]`, wantErr: badEnum},
		{name: "unknown-path", rules: one("Allow", `{"path":"Any"}`), wantErr: badEnum},
		{name: "unknown-protocol", rules: one("Allow", `{"protocol":"SCTP"}`), wantErr: badEnum},
		{name: "duplicate-rule-name", rules: `[{"name":"a","action":"Allow"},{"name":"a","action":"Deny"}]`,
			wantErr: "rule names must be unique"},
		{name: "bad-rule-name", rules: `[{"name":"Allow_All","action":"Allow"}]`, wantErr: "should match"},
		{name: "empty-ip-list", rules: one("Allow", `{"sourceIPs":[]}`), wantErr: atLeastOne},
		{name: "hostname", rules: one("Allow", `{"sourceIPs":["example.com"]}`), wantErr: notIP},
		{name: "prefix-in-ip-list", rules: one("Allow", `{"sourceIPs":["192.0.2.0/24"]}`), wantErr: notIP},
		{name: "address-and-port", rules: one("Allow", `{"destinationIPs":["192.0.2.1:80"]}`), wantErr: notIP},
		{name: "zone", rules: one("Allow", `{"sourceIPs":["fe80::1%eth0"]}`), wantErr: notIP},
		{name: "ipv4-mapped", rules: one("Allow", `{"sourceIPs":["::ffff:192.0.2.1"]}`), wantErr: notIP},
		{name: "duplicate-ip", rules: one("Allow", `{"sourceIPs":["192.0.2.1","192.0.2.1"]}`), wantErr: "Duplicate value"},
		{name: "host-bits", rules: one("Allow", `{"sourceCIDRs":["192.0.2.1/24"]}`), wantErr: "no host bits"},
		{name: "ip-and-cidr-same-side",
			rules:   one("Allow", `{"sourceIPs":["192.0.2.1"],"sourceCIDRs":["198.51.100.0/24"]}`),
			wantErr: "mutually exclusive"},
		{name: "family-mismatch", rules: one("Allow", `{"ipFamily":"IPv4","destinationIPs":["2001:db8::1"]}`),
			wantErr: familyMatch},
		{name: "icmp-v6-address", rules: one("Allow", `{"protocol":"ICMP","sourceCIDRs":["2001:db8::/32"]}`),
			wantErr: familyMatch},
		{name: "icmp-wrong-family", rules: one("Allow", `{"protocol":"ICMPv6","ipFamily":"IPv4"}`),
			wantErr: "requires ipFamily IPv6"},
		{name: "ports-without-protocol", rules: one("Allow", `{"destinationPorts":[{"start":80,"end":80}]}`),
			wantErr: portsNeed},
		{name: "ports-with-icmp", rules: one("Allow", `{"protocol":"ICMP","destinationPorts":[{"start":80,"end":80}]}`),
			wantErr: portsNeed},
		{name: "scalar-port", rules: one("Allow", `{"protocol":"TCP","destinationPorts":[80]}`),
			wantErr: "must be of type object"},
		{name: "reversed-range", rules: one("Allow", `{"protocol":"TCP","destinationPorts":[{"start":90,"end":80}]}`),
			wantErr: "start must not exceed end"},
		{name: "port-out-of-range", rules: one("Allow", `{"protocol":"TCP","destinationPorts":[{"start":1,"end":65536}]}`),
			wantErr: "less than or equal to 65535"},
		{name: "overlapping-ranges", rules: one("Allow",
			`{"protocol":"TCP","destinationPorts":[{"start":80,"end":90},{"start":90,"end":100}]}`),
			wantErr: "must not overlap"},
		{name: "icmp-without-protocol", rules: one("Allow", `{"icmp":{"type":8}}`), wantErr: "icmp requires protocol"},
		{name: "duplicate-ranges", rules: one("Allow",
			`{"protocol":"TCP","destinationPorts":[{"start":80,"end":80},{"start":80,"end":80}]}`),
			wantErr: "must not overlap"},
		{name: "touching-ranges", rules: one("Allow",
			`{"protocol":"TCP","sourcePorts":[{"start":80,"end":89},{"start":90,"end":99}]}`)},
		{name: "icmp-type-out-of-range", rules: one("Allow", `{"protocol":"ICMP","icmp":{"type":256}}`),
			wantErr: "less than or equal to 255"},
		{name: "icmp-code-out-of-range", rules: one("Allow", `{"protocol":"ICMP","icmp":{"type":3,"code":256}}`),
			wantErr: "less than or equal to 255"},
		{name: "icmp-v6-destination", rules: one("Allow", `{"protocol":"ICMP","destinationIPs":["2001:db8::1"]}`),
			wantErr: familyMatch},
		{name: "icmpv6-v4-source", rules: one("Allow", `{"protocol":"ICMPv6","sourceIPs":["192.0.2.1"]}`),
			wantErr: familyMatch},
		{name: "default-route", rules: one("Allow", `{"destinationCIDRs":["0.0.0.0/0","::/0"]}`)},
		{name: "null-path", rules: one("Allow", `{"path":null}`), wantErr: badEnum},
		{name: "null-protocol", rules: one("Allow", `{"protocol":null}`), wantErr: badEnum},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := res.Create(ctx, policyWithRules(t, tt.name, tt.rules), metav1.CreateOptions{})
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("rejected: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("admitted, want a rejection containing %q", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("rejection %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestTrafficPolicyBounds checks the list bounds the compiler relies on.
func TestTrafficPolicyBounds(t *testing.T) {
	_, dyn := startAPIServer(t)
	ctx := context.Background()
	res := dyn.Resource(policies).Namespace(testNamespace)

	rules := make([]string, galacticv1alpha1.MaxRules+1)
	for i := range rules {
		rules[i] = fmt.Sprintf(`{"name":"r%d","action":"Deny"}`, i)
	}
	tooMany := "[" + strings.Join(rules, ",") + "]"
	if _, err := res.Create(ctx, policyWithRules(t, "too-many-rules", tooMany), metav1.CreateOptions{}); err == nil ||
		!strings.Contains(err.Error(), "Too many") {
		t.Errorf("%d rules: err = %v, want Too many", len(rules), err)
	}

	ips := make([]string, galacticv1alpha1.MaxAddresses+1)
	for i := range ips {
		ips[i] = fmt.Sprintf(`"192.0.2.%d"`, i)
	}
	tooManyIPs := `[{"name":"a","action":"Allow","match":{"sourceIPs":[` + strings.Join(ips, ",") + `]}}]`
	if _, err := res.Create(ctx, policyWithRules(t, "too-many-ips", tooManyIPs), metav1.CreateOptions{}); err == nil ||
		!strings.Contains(err.Error(), "Too many") {
		t.Errorf("%d addresses: err = %v, want Too many", len(ips), err)
	}

	// The largest policy the schema allows must stay within the API
	// server's CEL cost budget, or a later schema edit could make valid
	// policies unadmittable.
	srcs := make([]string, galacticv1alpha1.MaxAddresses)
	dsts := make([]string, galacticv1alpha1.MaxAddresses)
	ports := make([]string, galacticv1alpha1.MaxPortRanges)
	for i := range srcs {
		srcs[i] = fmt.Sprintf(`"2001:db8::%x"`, i+1)
		dsts[i] = fmt.Sprintf(`"2001:db8:%x::/48"`, i+1)
	}
	for i := range ports {
		ports[i] = fmt.Sprintf(`{"start":%d,"end":%d}`, i*100, i*100+10)
	}
	largest := make([]string, galacticv1alpha1.MaxRules)
	for i := range largest {
		largest[i] = fmt.Sprintf(`{"name":"r%d","action":"Allow","match":{"protocol":"TCP","sourceIPs":[%s],`+
			`"destinationCIDRs":[%s],"sourcePorts":[%s],"destinationPorts":[%s]}}`,
			i, strings.Join(srcs, ","), strings.Join(dsts, ","), strings.Join(ports, ","), strings.Join(ports, ","))
	}
	biggest := policyWithRules(t, "largest", "["+strings.Join(largest, ",")+"]")
	if _, err := res.Create(ctx, biggest, metav1.CreateOptions{}); err != nil {
		t.Errorf("largest schema-valid policy rejected: %v", err)
	}
}

// TestTrafficPolicyUpdate checks that validation also holds on update: an
// invalid change to an admitted policy is rejected and leaves it unchanged.
func TestTrafficPolicyUpdate(t *testing.T) {
	_, dyn := startAPIServer(t)
	ctx := context.Background()
	res := dyn.Resource(policies).Namespace(testNamespace)

	if _, err := res.Create(ctx, policyWithRules(t, "web", `[{"name":"a","action":"Allow","match":{"protocol":"TCP"}}]`),
		metav1.CreateOptions{}); err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err := res.Patch(ctx, "web", types.MergePatchType,
		[]byte(`{"spec":{"rules":[{"name":"a","action":"Allow","match":{"destinationPorts":[{"start":80,"end":80}]}}]}}`),
		metav1.PatchOptions{})
	if err == nil || !strings.Contains(err.Error(), "ports require protocol") {
		t.Fatalf("invalid update: err = %v, want ports require protocol", err)
	}
	got, err := res.Get(ctx, "web", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if m := firstMatch(t, got); m["protocol"] != "TCP" || m["destinationPorts"] != nil {
		t.Errorf("stored match = %v, want the original", m)
	}
}

// TestTrafficPolicyNullReachesAdmission pins the property the validating
// webhook depends on: an explicit null at an optional match constraint is
// preserved through the CRD pipeline, on create, update and server-side
// apply, rather than being pruned to an omission the webhook could not see.
// A JSON merge patch that sets a field to null removes it, which is an
// intentional change to omission.
func TestTrafficPolicyNullReachesAdmission(t *testing.T) {
	_, dyn := startAPIServer(t)
	ctx := context.Background()
	res := dyn.Resource(policies).Namespace(testNamespace)

	nullIPs := policyWithRules(t, "null-create", `[{"name":"a","action":"Allow","match":{"sourceIPs":null}}]`)
	created, err := res.Create(ctx, nullIPs, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	assertNullKept(t, "create", created, "sourceIPs")

	nullMatch := policyWithRules(t, "null-match", `[{"name":"a","action":"Allow","match":null}]`)
	if _, err := res.Create(ctx, nullMatch, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create with null match: %v", err)
	}

	applied, err := res.Patch(ctx, "null-apply", types.ApplyPatchType, []byte(`{
		"apiVersion":"galactic.datumapis.com/v1alpha1","kind":"TrafficPolicy",
		"metadata":{"name":"null-apply","namespace":"default"},
		"spec":{"rules":[{"name":"a","action":"Allow","match":{"destinationPorts":null}}]}}`),
		metav1.PatchOptions{FieldManager: "test", Force: new(true)})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	assertNullKept(t, "apply", applied, "destinationPorts")

	for _, f := range []string{"sourceCIDRs", "icmp"} {
		name := "null-" + strings.ToLower(f)
		obj := policyWithRules(t, name, `[{"name":"a","action":"Allow","match":{"`+f+`":null}}]`)
		got, err := res.Create(ctx, obj, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("create with null %s: %v", f, err)
		}
		assertNullKept(t, "create", got, f)
	}

	toMerge := policyWithRules(t, "merge", `[{"name":"a","action":"Allow","match":{"sourceIPs":["192.0.2.1"]}}]`)
	if _, err := res.Create(ctx, toMerge, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create: %v", err)
	}
	merged, err := res.Patch(ctx, "merge", types.MergePatchType,
		[]byte(`{"spec":{"rules":[{"name":"a","action":"Allow","match":{"sourceIPs":null}}]}}`), metav1.PatchOptions{})
	if err != nil {
		t.Fatalf("merge patch: %v", err)
	}
	match := firstMatch(t, merged)
	if _, ok := match["sourceIPs"]; ok {
		t.Errorf("merge patch null: match = %v, want sourceIPs removed", match)
	}
}

func firstMatch(t *testing.T, u *unstructured.Unstructured) map[string]any {
	t.Helper()
	rules, _, _ := unstructured.NestedSlice(u.Object, "spec", "rules")
	if len(rules) == 0 {
		t.Fatalf("no rules in %v", u.Object)
	}
	match, _ := rules[0].(map[string]any)["match"].(map[string]any)
	return match
}

func assertNullKept(t *testing.T, op string, u *unstructured.Unstructured, field string) {
	t.Helper()
	match := firstMatch(t, u)
	v, ok := match[field]
	if !ok || v != nil {
		t.Errorf("%s: match = %v, want %s present and null", op, match, field)
	}
}

// TestTrafficPolicyBindingSchema covers the binding's references and its
// per-node status entries.
func TestTrafficPolicyBindingSchema(t *testing.T) {
	c, _ := startAPIServer(t)
	ctx := context.Background()

	b := &galacticv1alpha1.TrafficPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0-eth0", Namespace: testNamespace},
		Spec: galacticv1alpha1.TrafficPolicyBindingSpec{
			EgressPolicyRef: &galacticv1alpha1.LocalPolicyReference{Name: "public-web-egress"},
		},
	}
	if err := c.Create(ctx, b); err != nil {
		t.Fatalf("create with one direction: %v", err)
	}
	if b.Spec.IngressPolicyRef != nil {
		t.Errorf("ingress reference = %v, want it left omitted", b.Spec.IngressPolicyRef)
	}

	empty := &galacticv1alpha1.TrafficPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1-eth0", Namespace: testNamespace},
		Spec: galacticv1alpha1.TrafficPolicyBindingSpec{
			IngressPolicyRef: &galacticv1alpha1.LocalPolicyReference{},
		},
	}
	if err := c.Create(ctx, empty); err == nil {
		t.Error("admitted an empty policy name")
	}

	// Two nodes write their own entries without overwriting each other.
	for _, node := range []string{"dfw-compute-1", "dfw-compute-2"} {
		patch := fmt.Sprintf(`{"apiVersion":"galactic.datumapis.com/v1alpha1","kind":"TrafficPolicyBinding",
			"metadata":{"name":"web-0-eth0","namespace":"default"},
			"status":{"nodes":[{"node":%q,"egress":{"state":"Pending"}}]}}`, node)
		obj := &unstructured.Unstructured{}
		if err := obj.UnmarshalJSON([]byte(patch)); err != nil {
			t.Fatal(err)
		}
		if err := c.Status().Patch(ctx, obj, client.RawPatch(types.ApplyPatchType, []byte(patch)),
			client.FieldOwner(node), client.ForceOwnership); err != nil {
			t.Fatalf("%s status apply: %v", node, err)
		}
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(b), b); err != nil {
		t.Fatal(err)
	}
	if len(b.Status.Nodes) != 2 {
		t.Fatalf("status.nodes = %+v, want one entry per node", b.Status.Nodes)
	}
	for _, n := range b.Status.Nodes {
		if n.Egress == nil || n.Egress.State != galacticv1alpha1.StatePending {
			t.Errorf("node %s entry = %+v, want its own Pending egress kept", n.Node, n.Egress)
		}
	}
}
