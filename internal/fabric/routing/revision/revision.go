// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package revision turns a compiled router into an immutable
// FabricRouterRevision and back. Build captures exactly the objects the
// configuration renders, with their identities and digests; ToInput gives
// the node agent the compiler input a revision describes, so it can compile
// the same frr.conf the controller did and check it against the revision's
// rendered digest.
package revision

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabric/routing/compile"
)

// MaxBytes caps a revision's serialized size, well under etcd's object
// limit; the largest router today is a small fraction of it.
const MaxBytes = 512 * 1024

// ErrTooLarge reports a revision over MaxBytes.
var ErrTooLarge = fmt.Errorf("revision exceeds %d bytes", MaxBytes)

// ErrIncompatible reports a revision compiled for other compiler semantics
// or another FRR build than this binary's.
var ErrIncompatible = errors.New("revision targets another compiler or FRR build")

// Build compiles in and returns the revision for it. nodeUID is the target
// Node's UID, or empty when the Node is not found. The compile's refusal,
// if any, is returned unchanged.
func Build(in compile.Input, nodeUID string) (*networkv1alpha1.FabricRouterRevision, compile.Result, error) {
	res, err := compile.Compile(in)
	if err != nil {
		return nil, res, err
	}
	r := in.Router
	cfg := configuration(in, res.Rendered)
	semantics, err := digest(cfg)
	if err != nil {
		return nil, res, err
	}
	spec := networkv1alpha1.FabricRouterRevisionSpec{
		Target: networkv1alpha1.FabricRouterTarget{
			RouterName: r.Name, RouterUID: string(r.UID), NodeName: r.Spec.TargetRef.Name, NodeUID: nodeUID,
		},
		Parameters: networkv1alpha1.FabricRevisionParameters{
			Name: in.Parameters.Name, UID: string(in.Parameters.UID),
		},
		Compiler: networkv1alpha1.FabricRevisionCompiler{
			SemanticsVersion: compile.SemanticsVersion, FRRVersion: compile.FRRVersion,
		},
		Configuration:   cfg,
		Inputs:          inputs(in, res.Rendered),
		SemanticsDigest: semantics,
		RenderedDigest:  res.Digest,
	}
	dependency, err := digest(struct {
		Target     networkv1alpha1.FabricRouterTarget       `json:"target"`
		Semantics  string                                   `json:"semantics"`
		Parameters networkv1alpha1.FabricRevisionParameters `json:"parameters"`
		Compiler   networkv1alpha1.FabricRevisionCompiler   `json:"compiler"`
	}{spec.Target, semantics, spec.Parameters, spec.Compiler})
	if err != nil {
		return nil, res, err
	}
	spec.ActivationDependencyDigest = dependency

	rev := &networkv1alpha1.FabricRouterRevision{
		ObjectMeta: metav1.ObjectMeta{Name: Name(r.Name, dependency), Namespace: r.Namespace},
		Spec:       spec,
	}
	rev.SetGroupVersionKind(networkv1alpha1.GroupVersion.WithKind("FabricRouterRevision"))
	data, err := json.Marshal(rev)
	if err != nil {
		return nil, res, err
	}
	if len(data) > MaxBytes {
		return nil, res, fmt.Errorf("%w: %d", ErrTooLarge, len(data))
	}
	return rev, res, nil
}

// Name is a revision's name: the router's name and the first ten hex
// digits of the activation dependency digest, trimmed so the result stays a
// valid object name.
func Name(router, dependencyDigest string) string {
	const suffix = 11 // "-" and ten digits
	if len(router) > 253-suffix {
		router = router[:253-suffix]
	}
	return router + "-" + dependencyDigest[:10]
}

func configuration(in compile.Input, used compile.Rendered) networkv1alpha1.FabricRouterConfiguration {
	cfg := networkv1alpha1.FabricRouterConfiguration{
		Router:     *in.Router.Spec.DeepCopy(),
		Parameters: *in.Parameters.Spec.DeepCopy(),
	}
	for _, p := range sortedByName(in.Peers) {
		cfg.Peers = append(cfg.Peers, networkv1alpha1.FabricNamedPeer{Name: p.Name, Spec: *p.Spec.DeepCopy()})
	}
	for _, a := range sortedByName(in.Advertisements) {
		cfg.Advertisements = append(cfg.Advertisements,
			networkv1alpha1.FabricNamedAdvertisement{Name: a.Name, Spec: *a.Spec.DeepCopy()})
	}
	for _, s := range sortedByName(in.StaticRoutes) {
		cfg.StaticRoutes = append(cfg.StaticRoutes,
			networkv1alpha1.FabricNamedStaticRoute{Name: s.Name, Spec: *s.Spec.DeepCopy()})
	}
	for _, n := range used.Profiles {
		cfg.Profiles = append(cfg.Profiles,
			networkv1alpha1.FabricNamedPeerProfile{Name: n, Spec: *in.Profiles[n].Spec.DeepCopy()})
	}
	for _, n := range used.Policies {
		cfg.Policies = append(cfg.Policies, networkv1alpha1.FabricNamedPolicy{Name: n, Spec: *in.Policies[n].Spec.DeepCopy()})
	}
	for _, n := range used.PrefixLists {
		cfg.PrefixLists = append(cfg.PrefixLists,
			networkv1alpha1.FabricNamedPrefixList{Name: n, Spec: *in.PrefixLists[n].Spec.DeepCopy()})
	}
	for _, n := range used.CommunitySets {
		cfg.CommunitySets = append(cfg.CommunitySets,
			networkv1alpha1.FabricNamedCommunitySet{Name: n, Spec: *in.CommunitySets[n].Spec.DeepCopy()})
	}
	return cfg
}

func sortedByName[T any, PT interface {
	*T
	client.Object
}](list []T) []T {
	out := append([]T(nil), list...)
	sort.Slice(out, func(i, j int) bool { return PT(&out[i]).GetName() < PT(&out[j]).GetName() })
	return out
}

// inputs lists every object the configuration came from, by kind and name.
func inputs(in compile.Input, used compile.Rendered) []networkv1alpha1.FabricRevisionInput {
	var out []networkv1alpha1.FabricRevisionInput
	add := func(kind string, o client.Object, spec any) {
		// A spec that encoded once for the configuration encodes again.
		d, err := digest(spec)
		if err != nil {
			panic(fmt.Sprintf("digest %s %s: %v", kind, o.GetName(), err))
		}
		out = append(out, networkv1alpha1.FabricRevisionInput{
			Kind: kind, Name: o.GetName(), UID: string(o.GetUID()), Generation: o.GetGeneration(), Digest: d,
		})
	}
	add("BGPRouter", in.Router, in.Router.Spec)
	add("BGPRouterClass", in.Class, in.Class.Spec)
	add(networkv1alpha1.FRRRouterParametersKind, in.Parameters, in.Parameters.Spec)
	for i := range in.Peers {
		add("BGPPeer", &in.Peers[i], in.Peers[i].Spec)
	}
	for i := range in.Advertisements {
		add("BGPAdvertisement", &in.Advertisements[i], in.Advertisements[i].Spec)
	}
	for i := range in.StaticRoutes {
		add("BGPStaticRoute", &in.StaticRoutes[i], in.StaticRoutes[i].Spec)
	}
	for _, n := range used.Profiles {
		add("BGPPeerProfile", in.Profiles[n], in.Profiles[n].Spec)
	}
	for _, n := range used.Policies {
		add("BGPPolicy", in.Policies[n], in.Policies[n].Spec)
	}
	for _, n := range used.PrefixLists {
		add("BGPPrefixList", in.PrefixLists[n], in.PrefixLists[n].Spec)
	}
	for _, n := range used.CommunitySets {
		add("BGPCommunitySet", in.CommunitySets[n], in.CommunitySets[n].Spec)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// digest is the hex SHA-256 of v's canonical JSON: v is encoded, decoded
// into generic values, stripped of nulls, empty lists and empty objects, and
// re-encoded with object keys sorted. Two binaries whose API types differ
// only in field order, in omitempty tags or in an added unset field
// therefore digest the same configuration identically; numbers and
// booleans are kept as given, since a pointer to zero and an unset pointer
// mean different things.
func digest(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	var generic any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(prune(generic))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// prune drops nulls, empty lists and empty objects, recursively. Go's
// encoder already writes object keys in sorted order.
func prune(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, val := range t {
			if p := prune(val); !empty(p) {
				out[k] = p
			}
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, val := range t {
			out = append(out, prune(val))
		}
		return out
	}
	return v
}

func empty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case map[string]any:
		return len(t) == 0
	case []any:
		return len(t) == 0
	}
	return false
}

// ToInput is the compiler input a revision describes. The class is the
// fabric class by definition, since only its controller writes revisions.
func ToInput(rev *networkv1alpha1.FabricRouterRevision) compile.Input {
	s := rev.Spec
	cfg := s.Configuration.DeepCopy()
	meta := func(name string) metav1.ObjectMeta { return metav1.ObjectMeta{Name: name, Namespace: rev.Namespace} }
	in := compile.Input{
		Router: &networkv1alpha1.BGPRouter{ObjectMeta: meta(s.Target.RouterName), Spec: cfg.Router},
		Class: &networkv1alpha1.BGPRouterClass{
			Spec: networkv1alpha1.BGPRouterClassSpec{ControllerName: networkv1alpha1.FabricRouterControllerName},
		},
		Parameters: &networkv1alpha1.FRRRouterParameters{
			ObjectMeta: metav1.ObjectMeta{Name: s.Parameters.Name}, Spec: cfg.Parameters,
		},
		Profiles:      map[string]*networkv1alpha1.BGPPeerProfile{},
		Policies:      map[string]*networkv1alpha1.BGPPolicy{},
		PrefixLists:   map[string]*networkv1alpha1.BGPPrefixList{},
		CommunitySets: map[string]*networkv1alpha1.BGPCommunitySet{},
	}
	if cfg.Router.RouterClassName != nil {
		in.Class.Name = *cfg.Router.RouterClassName
	}
	for _, p := range cfg.Peers {
		in.Peers = append(in.Peers, networkv1alpha1.BGPPeer{ObjectMeta: meta(p.Name), Spec: p.Spec})
	}
	for _, a := range cfg.Advertisements {
		in.Advertisements = append(in.Advertisements,
			networkv1alpha1.BGPAdvertisement{ObjectMeta: meta(a.Name), Spec: a.Spec})
	}
	for _, r := range cfg.StaticRoutes {
		in.StaticRoutes = append(in.StaticRoutes, networkv1alpha1.BGPStaticRoute{ObjectMeta: meta(r.Name), Spec: r.Spec})
	}
	for _, p := range cfg.Profiles {
		in.Profiles[p.Name] = &networkv1alpha1.BGPPeerProfile{ObjectMeta: meta(p.Name), Spec: p.Spec}
	}
	for _, p := range cfg.Policies {
		in.Policies[p.Name] = &networkv1alpha1.BGPPolicy{ObjectMeta: meta(p.Name), Spec: p.Spec}
	}
	for _, p := range cfg.PrefixLists {
		in.PrefixLists[p.Name] = &networkv1alpha1.BGPPrefixList{ObjectMeta: meta(p.Name), Spec: p.Spec}
	}
	for _, c := range cfg.CommunitySets {
		in.CommunitySets[c.Name] = &networkv1alpha1.BGPCommunitySet{ObjectMeta: meta(c.Name), Spec: c.Spec}
	}
	return in
}

// Verify recompiles a revision and checks it renders the configuration its
// digests describe: the semantics digest over the configuration and the
// rendered digest over the frr.conf. It returns the compiled result.
func Verify(rev *networkv1alpha1.FabricRouterRevision) (compile.Result, error) {
	if c := rev.Spec.Compiler; c.SemanticsVersion != compile.SemanticsVersion || c.FRRVersion != compile.FRRVersion {
		return compile.Result{}, fmt.Errorf("%w: revision %s targets semantics %s and FRR %s, this build %s and %s",
			ErrIncompatible, rev.Name, c.SemanticsVersion, c.FRRVersion, compile.SemanticsVersion, compile.FRRVersion)
	}
	semantics, err := digest(rev.Spec.Configuration)
	if err != nil {
		return compile.Result{}, err
	}
	if semantics != rev.Spec.SemanticsDigest {
		return compile.Result{}, fmt.Errorf("revision %s: configuration digest %s, recorded %s",
			rev.Name, semantics, rev.Spec.SemanticsDigest)
	}
	res, err := compile.Compile(ToInput(rev))
	if err != nil {
		return res, fmt.Errorf("revision %s: %w", rev.Name, err)
	}
	if res.Digest != rev.Spec.RenderedDigest {
		return res, fmt.Errorf("revision %s: renders %s, recorded %s", rev.Name, res.Digest, rev.Spec.RenderedDigest)
	}
	return res, nil
}
