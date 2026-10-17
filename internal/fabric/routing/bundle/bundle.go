// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bundle reads and writes a set of fabric routing objects as a
// multi-document YAML stream, and assembles one router's compiler input from
// it. It lets the compiler run offline against files: infra's rendered
// objects, a preview before applying, or the importer's output.
package bundle

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"

	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"
	kjson "sigs.k8s.io/json"
	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabric/routing/compile"
	"go.datum.net/galactic/internal/fabric/routing/frrimport"
)

// kindParameters is the FRRRouterParameters kind, which a class names.
const kindParameters = "FRRRouterParameters"

// Bundle is every object the fabric compiler reads, from one namespace.
type Bundle struct {
	Routers        []*networkv1alpha1.BGPRouter
	Classes        []*networkv1alpha1.BGPRouterClass
	Parameters     []*networkv1alpha1.FRRRouterParameters
	Peers          []*networkv1alpha1.BGPPeer
	Profiles       []*networkv1alpha1.BGPPeerProfile
	Policies       []*networkv1alpha1.BGPPolicy
	PrefixLists    []*networkv1alpha1.BGPPrefixList
	CommunitySets  []*networkv1alpha1.BGPCommunitySet
	Advertisements []*networkv1alpha1.BGPAdvertisement
	StaticRoutes   []*networkv1alpha1.BGPStaticRoute
}

// FromImport wraps one imported router with a class and parameters named
// className.
func FromImport(o *frrimport.Objects, className string) *Bundle {
	params := &networkv1alpha1.FRRRouterParameters{Spec: o.Parameters}
	params.Name = className
	class := &networkv1alpha1.BGPRouterClass{Spec: networkv1alpha1.BGPRouterClassSpec{
		ControllerName: networkv1alpha1.FabricRouterControllerName,
		ParametersRef: &networkv1alpha1.BGPRouterClassParametersRef{
			Group: networkv1alpha1.GroupVersion.Group, Kind: kindParameters, Name: className,
		},
	}}
	class.Name = className
	return &Bundle{
		Routers: []*networkv1alpha1.BGPRouter{o.Router}, Classes: []*networkv1alpha1.BGPRouterClass{class},
		Parameters: []*networkv1alpha1.FRRRouterParameters{params},
		Peers:      o.Peers, Profiles: o.Profiles, Policies: o.Policies, PrefixLists: o.PrefixLists,
		CommunitySets: o.CommunitySets, Advertisements: o.Advertisements, StaticRoutes: o.StaticRoutes,
	}
}

// Input assembles the compiler input for the router named router: its
// class, the class's parameters, the peers, advertisements and static routes
// that reference it, and every definition available for reference.
func (b *Bundle) Input(router string) (compile.Input, error) {
	var in compile.Input
	if err := b.unique(); err != nil {
		return in, err
	}
	for _, r := range b.Routers {
		if r.Name == router {
			in.Router = r
		}
	}
	if in.Router == nil {
		return in, fmt.Errorf("no BGPRouter %q", router)
	}
	if err := b.sameNamespace(in.Router.Namespace); err != nil {
		return in, err
	}
	if name := in.Router.Spec.RouterClassName; name != nil {
		for _, c := range b.Classes {
			if c.Name == *name {
				in.Class = c
			}
		}
	}
	if in.Class != nil && in.Class.Spec.ParametersRef != nil && in.Class.Spec.ParametersRef.Kind == kindParameters {
		for _, p := range b.Parameters {
			if p.Name == in.Class.Spec.ParametersRef.Name {
				in.Parameters = p
			}
		}
	}
	for _, p := range b.Peers {
		if p.Spec.RouterRef != nil && p.Spec.RouterRef.Name == router {
			in.Peers = append(in.Peers, *p)
		}
	}
	for _, a := range b.Advertisements {
		if a.Spec.RouterRef.Name == router {
			in.Advertisements = append(in.Advertisements, *a)
		}
	}
	for _, s := range b.StaticRoutes {
		if s.Spec.RouterRef.Name == router {
			in.StaticRoutes = append(in.StaticRoutes, *s)
		}
	}
	in.Profiles = byName(b.Profiles)
	in.Policies = byName(b.Policies)
	in.PrefixLists = byName(b.PrefixLists)
	in.CommunitySets = byName(b.CommunitySets)
	return in, nil
}

// unique refuses two objects of one kind with one name, which a cluster
// could never hold and which would otherwise resolve to whichever came last.
func (b *Bundle) unique() error {
	for _, group := range [][]client.Object{
		objs(b.Routers), objs(b.Classes), objs(b.Parameters), objs(b.Peers), objs(b.Profiles), objs(b.Policies),
		objs(b.PrefixLists), objs(b.CommunitySets), objs(b.Advertisements), objs(b.StaticRoutes),
	} {
		seen := map[string]bool{}
		for _, o := range group {
			key := o.GetNamespace() + "/" + o.GetName()
			if seen[key] {
				return fmt.Errorf("%T %s appears twice", o, key)
			}
			seen[key] = true
		}
	}
	return nil
}

// sameNamespace refuses namespaced objects outside the router's namespace,
// which the compiler would otherwise read as if they were in it.
func (b *Bundle) sameNamespace(ns string) error {
	for _, group := range [][]client.Object{
		objs(b.Peers), objs(b.Profiles), objs(b.Policies), objs(b.PrefixLists),
		objs(b.CommunitySets), objs(b.Advertisements), objs(b.StaticRoutes),
	} {
		for _, o := range group {
			if o.GetNamespace() != ns {
				return fmt.Errorf("%T %s is in namespace %q, not the router's %q", o, o.GetName(), o.GetNamespace(), ns)
			}
		}
	}
	return nil
}

func byName[T client.Object](list []T) map[string]T {
	m := make(map[string]T, len(list))
	for _, o := range list {
		m[o.GetName()] = o
	}
	return m
}

// objects lists the bundle in a stable order: by kind, then name.
func (b *Bundle) objects() []client.Object {
	var out []client.Object
	add := func(group []client.Object) {
		sort.SliceStable(group, func(i, j int) bool { return group[i].GetName() < group[j].GetName() })
		out = append(out, group...)
	}
	add(objs(b.Classes))
	add(objs(b.Parameters))
	add(objs(b.Routers))
	add(objs(b.Profiles))
	add(objs(b.Peers))
	add(objs(b.StaticRoutes))
	add(objs(b.Advertisements))
	add(objs(b.Policies))
	add(objs(b.PrefixLists))
	add(objs(b.CommunitySets))
	return out
}

func objs[T client.Object](list []T) []client.Object {
	out := make([]client.Object, len(list))
	for i, o := range list {
		out[i] = o
	}
	return out
}

// Write encodes the bundle as a YAML stream, one document per object, each
// with its apiVersion and kind.
func (b *Bundle) Write(w io.Writer) error {
	scheme := runtime.NewScheme()
	if err := networkv1alpha1.AddToScheme(scheme); err != nil {
		return err
	}
	for i, o := range b.objects() {
		gvks, _, err := scheme.ObjectKinds(o)
		if err != nil {
			return err
		}
		o.GetObjectKind().SetGroupVersionKind(gvks[0])
		data, err := yaml.Marshal(o)
		if err != nil {
			return err
		}
		if i > 0 {
			if _, err := io.WriteString(w, "---\n"); err != nil {
				return err
			}
		}
		if _, err := w.Write(stripEmptyStatus(data)); err != nil {
			return err
		}
	}
	return nil
}

// stripEmptyStatus drops the `status: {}` and `creationTimestamp: null`
// lines an unsaved object marshals with.
func stripEmptyStatus(data []byte) []byte {
	var out bytes.Buffer
	for _, line := range bytes.SplitAfter(data, []byte("\n")) {
		t := bytes.TrimSpace(line)
		if bytes.Equal(t, []byte("status: {}")) || bytes.Equal(t, []byte("creationTimestamp: null")) {
			continue
		}
		out.Write(line)
	}
	return out.Bytes()
}

// Read decodes a YAML stream into a bundle. Documents of other kinds are
// an error, so a misspelled kind is not silently left out.
func Read(r io.Reader) (*Bundle, error) {
	b := &Bundle{}
	dec := utilyaml.NewYAMLReader(bufio.NewReader(r))
	for {
		doc, err := dec.Read()
		if errors.Is(err, io.EOF) {
			return b, nil
		}
		if err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(doc)) == 0 {
			continue
		}
		var meta struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
		}
		if err := yaml.Unmarshal(doc, &meta); err != nil {
			return nil, err
		}
		if meta.Kind == "" {
			continue
		}
		if meta.APIVersion != networkv1alpha1.GroupVersion.String() {
			return nil, fmt.Errorf("%s with apiVersion %q: want %s", meta.Kind, meta.APIVersion, networkv1alpha1.GroupVersion)
		}
		if err := b.decode(meta.Kind, doc); err != nil {
			return nil, fmt.Errorf("%s: %w", meta.Kind, err)
		}
	}
}

func (b *Bundle) decode(kind string, doc []byte) error {
	data, err := yaml.YAMLToJSON(doc)
	if err != nil {
		return err
	}
	// The API server's own decoding: field names are case-sensitive and
	// unknown or duplicate fields are errors.
	strict := func(into any) error {
		strictErrs, err := kjson.UnmarshalStrict(data, into)
		if err != nil {
			return err
		}
		return errors.Join(strictErrs...)
	}
	switch kind {
	case "BGPRouter":
		return appendDecoded(&b.Routers, strict)
	case "BGPRouterClass":
		return appendDecoded(&b.Classes, strict)
	case kindParameters:
		return appendDecoded(&b.Parameters, strict)
	case "BGPPeer":
		return appendDecoded(&b.Peers, strict)
	case "BGPPeerProfile":
		return appendDecoded(&b.Profiles, strict)
	case "BGPPolicy":
		return appendDecoded(&b.Policies, strict)
	case "BGPPrefixList":
		return appendDecoded(&b.PrefixLists, strict)
	case "BGPCommunitySet":
		return appendDecoded(&b.CommunitySets, strict)
	case "BGPAdvertisement":
		return appendDecoded(&b.Advertisements, strict)
	case "BGPStaticRoute":
		return appendDecoded(&b.StaticRoutes, strict)
	}
	return errors.New("not a kind the fabric compiler reads")
}

func appendDecoded[T any](list *[]*T, decode func(any) error) error {
	v := new(T)
	if err := decode(v); err != nil {
		return err
	}
	*list = append(*list, v)
	return nil
}
