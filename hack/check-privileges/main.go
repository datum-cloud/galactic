// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command check-privileges fails when rendered manifests grant different
// privileges than an expectation file records. It summarizes what each
// workload may do on its host (host namespaces, privileged mode, added
// capabilities, hostPath mounts) and what each role may do in the API (one
// line per API group, resource and verb), which ServiceAccount each binding
// grants a role to, and which Worker capabilities the galactic-worker
// allowlist grants. Any difference fails, so a grant can be added only by
// recording it, and a stale record fails too.
//
//	kustomize build tests/manifests/worker-profiles/combined |
//	  check-privileges -expect tests/manifests/worker-profiles/combined/privileges.yaml
//
// With -write, it writes the summary to the expectation file instead.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

// fromImage is a user or group no manifest sets, so the image's applies.
const fromImage = "image"

// allowlistConfigMap is the prefix of galactic-worker's allowlist ConfigMap,
// whose generated name ends in a content hash.
const allowlistConfigMap = "galactic-worker-allowlist"

// Summary is the privilege record of a set of manifests.
type Summary struct {
	// Workloads are keyed Kind/namespace/name.
	Workloads map[string]Workload `json:"workloads"`
	// Roles are keyed Kind/namespace/name (no namespace for a ClusterRole),
	// each rule as group/resource:verb.
	Roles map[string][]string `json:"roles"`
	// Bindings are keyed Kind/namespace/name, each subject as
	// Kind/namespace/name -> role Kind/name.
	Bindings map[string][]string `json:"bindings"`
	// WorkerAllowlist is each ServiceAccount's Worker capabilities.
	WorkerAllowlist map[string][]string `json:"workerAllowlist,omitempty"`
}

// Workload is what a pod template may do on its host.
type Workload struct {
	HostNetwork bool                 `json:"hostNetwork,omitempty"`
	HostPID     bool                 `json:"hostPID,omitempty"`
	HostIPC     bool                 `json:"hostIPC,omitempty"`
	Containers  map[string]Container `json:"containers"`
}

// Container is one container's host privileges.
type Container struct {
	// RunAsUser and RunAsGroup are the container's, or else the pod's;
	// "image" when neither sets one.
	RunAsUser                string `json:"runAsUser"`
	RunAsGroup               string `json:"runAsGroup"`
	WritableRootFilesystem   bool   `json:"writableRootFilesystem,omitempty"`
	Privileged               bool   `json:"privileged,omitempty"`
	AllowPrivilegeEscalation bool   `json:"allowPrivilegeEscalation,omitempty"`
	// DropsAll is false when the container keeps the runtime's default
	// capabilities.
	DropsAll     bool     `json:"dropsAll"`
	Capabilities []string `json:"capabilities,omitempty"`
	// HostPaths are the host paths mounted, with ":rw" when writable.
	HostPaths []string `json:"hostPaths,omitempty"`
}

func main() {
	expect := flag.String("expect", "", "expectation file")
	write := flag.Bool("write", false, "write the summary to -expect instead of comparing")
	flag.Parse()
	if *expect == "" {
		fmt.Fprintln(os.Stderr, "usage: check-privileges -expect FILE [-write] < rendered.yaml")
		os.Exit(2)
	}
	got, err := Summarize(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	out, err := yaml.Marshal(got)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *write {
		header := "# Privileges the rendered manifests beside this file grant, checked by\n" +
			"# hack/check-privileges in task test:manifests. Review every change.\n" +
			"# Regenerate with check-privileges -write, then task lint-fix.\n"
		if err := os.WriteFile(*expect, append([]byte(header), out...), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		return
	}
	b, err := os.ReadFile(*expect)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var want Summary
	if err := yaml.UnmarshalStrict(b, &want); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", *expect, err)
		os.Exit(2)
	}
	if diffs := Compare(want, got); len(diffs) > 0 {
		for _, d := range diffs {
			fmt.Fprintf(os.Stderr, "%s: %s\n", *expect, d)
		}
		os.Exit(1)
	}
}

// Summarize reads a YAML stream of rendered manifests.
func Summarize(r io.Reader) (Summary, error) {
	s := Summary{Workloads: map[string]Workload{}, Roles: map[string][]string{}, Bindings: map[string][]string{}}
	dec := utilyaml.NewYAMLReader(bufio.NewReader(r))
	for {
		doc, err := dec.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return s, err
		}
		var meta struct {
			Kind string `json:"kind"`
		}
		if err := yaml.Unmarshal(doc, &meta); err != nil {
			return s, err
		}
		if err := s.add(meta.Kind, doc); err != nil {
			return s, fmt.Errorf("%s: %w", meta.Kind, err)
		}
	}
	return s, nil
}

func key(kind, ns, name string) string {
	if ns == "" {
		return kind + "/" + name
	}
	return kind + "/" + ns + "/" + name
}

func (s *Summary) add(kind string, doc []byte) error {
	switch kind {
	case "DaemonSet":
		var o appsv1.DaemonSet
		if err := yaml.Unmarshal(doc, &o); err != nil {
			return err
		}
		s.Workloads[key(kind, o.Namespace, o.Name)] = workload(o.Spec.Template.Spec)
	case "Deployment":
		var o appsv1.Deployment
		if err := yaml.Unmarshal(doc, &o); err != nil {
			return err
		}
		s.Workloads[key(kind, o.Namespace, o.Name)] = workload(o.Spec.Template.Spec)
	case "StatefulSet":
		var o appsv1.StatefulSet
		if err := yaml.Unmarshal(doc, &o); err != nil {
			return err
		}
		s.Workloads[key(kind, o.Namespace, o.Name)] = workload(o.Spec.Template.Spec)
	case "Job":
		var o batchv1.Job
		if err := yaml.Unmarshal(doc, &o); err != nil {
			return err
		}
		s.Workloads[key(kind, o.Namespace, o.Name)] = workload(o.Spec.Template.Spec)
	case "CronJob":
		var o batchv1.CronJob
		if err := yaml.Unmarshal(doc, &o); err != nil {
			return err
		}
		s.Workloads[key(kind, o.Namespace, o.Name)] = workload(o.Spec.JobTemplate.Spec.Template.Spec)
	case "Pod":
		var o corev1.Pod
		if err := yaml.Unmarshal(doc, &o); err != nil {
			return err
		}
		s.Workloads[key(kind, o.Namespace, o.Name)] = workload(o.Spec)
	case "ReplicaSet", "ReplicationController", "PodTemplate":
		return fmt.Errorf("unsupported workload kind %s: add it to check-privileges", kind)
	case "ClusterRole", "Role":
		var o rbacv1.Role
		if err := yaml.Unmarshal(doc, &o); err != nil {
			return err
		}
		s.Roles[key(kind, o.Namespace, o.Name)] = rules(o.Rules)
	case "ClusterRoleBinding", "RoleBinding":
		var o rbacv1.RoleBinding
		if err := yaml.Unmarshal(doc, &o); err != nil {
			return err
		}
		var subs []string
		for _, sub := range o.Subjects {
			subs = append(subs, key(sub.Kind, sub.Namespace, sub.Name)+" -> "+o.RoleRef.Kind+"/"+o.RoleRef.Name)
		}
		slices.Sort(subs)
		s.Bindings[key(kind, o.Namespace, o.Name)] = subs
	case "ConfigMap":
		var o corev1.ConfigMap
		if err := yaml.Unmarshal(doc, &o); err != nil {
			return err
		}
		if !strings.HasPrefix(o.Name, allowlistConfigMap) {
			return nil
		}
		var f struct {
			ServiceAccounts []struct {
				ServiceAccount string   `json:"serviceAccount"`
				Capabilities   []string `json:"capabilities"`
			} `json:"serviceAccounts"`
		}
		if err := yaml.UnmarshalStrict([]byte(o.Data["allowlist.yaml"]), &f); err != nil {
			return fmt.Errorf("%s: %w", o.Name, err)
		}
		s.WorkerAllowlist = map[string][]string{}
		for _, sa := range f.ServiceAccounts {
			caps := slices.Clone(sa.Capabilities)
			slices.Sort(caps)
			s.WorkerAllowlist[sa.ServiceAccount] = caps
		}
	}
	return nil
}

func rules(rs []rbacv1.PolicyRule) []string {
	var out []string
	for _, r := range rs {
		for _, url := range r.NonResourceURLs {
			for _, v := range r.Verbs {
				out = append(out, url+":"+v)
			}
		}
		for _, g := range r.APIGroups {
			for _, res := range r.Resources {
				names := ""
				if len(r.ResourceNames) > 0 {
					names = "[" + strings.Join(r.ResourceNames, ",") + "]"
				}
				for _, v := range r.Verbs {
					grp := g
					if grp == "" {
						grp = "core"
					}
					out = append(out, grp+"/"+res+names+":"+v)
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func workload(spec corev1.PodSpec) Workload {
	w := Workload{HostNetwork: spec.HostNetwork, HostPID: spec.HostPID, HostIPC: spec.HostIPC,
		Containers: map[string]Container{}}
	hostPaths := map[string]string{}
	for _, v := range spec.Volumes {
		if v.HostPath != nil {
			hostPaths[v.Name] = v.HostPath.Path
		}
	}
	all := append(slices.Clone(spec.InitContainers), spec.Containers...)
	for _, c := range all {
		ct := Container{RunAsUser: fromImage, RunAsGroup: fromImage, WritableRootFilesystem: true}
		if psc := spec.SecurityContext; psc != nil {
			if psc.RunAsUser != nil {
				ct.RunAsUser = strconv.FormatInt(*psc.RunAsUser, 10)
			}
			if psc.RunAsGroup != nil {
				ct.RunAsGroup = strconv.FormatInt(*psc.RunAsGroup, 10)
			}
		}
		// Escalation is allowed unless set false, and always with
		// privileged or CAP_SYS_ADMIN.
		ct.AllowPrivilegeEscalation = true
		if sc := c.SecurityContext; sc != nil {
			if sc.RunAsUser != nil {
				ct.RunAsUser = strconv.FormatInt(*sc.RunAsUser, 10)
			}
			if sc.RunAsGroup != nil {
				ct.RunAsGroup = strconv.FormatInt(*sc.RunAsGroup, 10)
			}
			ct.WritableRootFilesystem = sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem
			ct.Privileged = sc.Privileged != nil && *sc.Privileged
			if sc.AllowPrivilegeEscalation != nil {
				ct.AllowPrivilegeEscalation = *sc.AllowPrivilegeEscalation
			}
			if sc.Capabilities != nil {
				for _, d := range sc.Capabilities.Drop {
					if strings.EqualFold(string(d), "ALL") {
						ct.DropsAll = true
					}
				}
				for _, a := range sc.Capabilities.Add {
					ct.Capabilities = append(ct.Capabilities, strings.TrimPrefix(string(a), "CAP_"))
				}
				slices.Sort(ct.Capabilities)
			}
		}
		for _, m := range c.VolumeMounts {
			p, ok := hostPaths[m.Name]
			if !ok {
				continue
			}
			if m.SubPath != "" {
				p += "/" + m.SubPath
			}
			if !m.ReadOnly {
				p += ":rw"
			}
			ct.HostPaths = append(ct.HostPaths, p)
		}
		slices.Sort(ct.HostPaths)
		w.Containers[c.Name] = ct
	}
	return w
}

// Compare returns one line per difference between want and got.
func Compare(want, got Summary) []string {
	var out []string
	wb, _ := yaml.Marshal(want)
	gb, _ := yaml.Marshal(got)
	if string(wb) == string(gb) {
		return nil
	}
	wl := lines(want)
	gl := lines(got)
	for _, l := range gl {
		if _, ok := slices.BinarySearch(wl, l); !ok {
			out = append(out, "granted but not recorded: "+l)
		}
	}
	for _, l := range wl {
		if _, ok := slices.BinarySearch(gl, l); !ok {
			out = append(out, "recorded but not granted: "+l)
		}
	}
	return out
}

// lines flattens a summary into sorted lines, one per grant.
func lines(s Summary) []string {
	var out []string
	for k, w := range s.Workloads {
		for _, f := range []struct {
			name string
			on   bool
		}{{"hostNetwork", w.HostNetwork}, {"hostPID", w.HostPID}, {"hostIPC", w.HostIPC}} {
			if f.on {
				out = append(out, k+" "+f.name)
			}
		}
		for n, c := range w.Containers {
			p := k + " container " + n + " "
			out = append(out, p+"runAsUser "+c.RunAsUser, p+"runAsGroup "+c.RunAsGroup)
			if c.WritableRootFilesystem {
				out = append(out, p+"writable root filesystem")
			}
			if c.Privileged {
				out = append(out, p+"privileged")
			}
			if c.AllowPrivilegeEscalation {
				out = append(out, p+"allowPrivilegeEscalation")
			}
			if !c.DropsAll {
				out = append(out, p+"keeps default capabilities")
			}
			for _, cp := range c.Capabilities {
				out = append(out, p+"capability "+cp)
			}
			for _, h := range c.HostPaths {
				out = append(out, p+"hostPath "+h)
			}
		}
	}
	for k, rs := range s.Roles {
		for _, r := range rs {
			out = append(out, k+" "+r)
		}
	}
	for k, bs := range s.Bindings {
		for _, b := range bs {
			out = append(out, k+" "+b)
		}
	}
	for sa, caps := range s.WorkerAllowlist {
		for _, c := range caps {
			out = append(out, "worker allowlist "+sa+" "+c)
		}
	}
	slices.Sort(out)
	return out
}
