// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/fabric/errcode"
)

// Defaults for discovery.
const (
	// DefaultNamespace is where the fabric-router DaemonSet runs.
	DefaultNamespace = "galactic-system"
	// DefaultPodSelector selects fabric-router pods.
	DefaultPodSelector = "app.kubernetes.io/name=fabric-router"
	// ContainerName is the sidecar's container name in those pods.
	ContainerName = "fabric-api"
	// PortName names the sidecar's gRPC port.
	PortName = "fabric-api"
	// DefaultPort is used when the container declares no named port.
	DefaultPort = 9344
)

// Reasons a discovered node is not executed on.
const (
	OmitPodTerminating  = "PodTerminating"
	OmitPodNotRunning   = "PodNotRunning"
	OmitSidecarNotReady = "SidecarNotRunning"
	OmitNoHostIP        = "NoHostIP"
	OmitDuplicatePod    = "DuplicatePod"
	OmitNodeBudget      = "NodeBudget"
	OmitNoCertificate   = "NoCertificatePod"
	// OmitNotRequested and OmitNoSidecar are used only by Inventory: a
	// router outside an explicit selection, and a router whose pod has no
	// fabric-api container.
	OmitNotRequested = "NotRequested"
	OmitNoSidecar    = "NoSidecar"
)

// MaxInventoryRouters bounds the routers one Inventory may list.
const MaxInventoryRouters = 256

// Node is one node in an execution snapshot.
type Node struct {
	Name   string
	Pod    string
	PodUID string
	HostIP string
	Port   int
	// IdentityPod is the pod whose identity the node's sidecar presents:
	// the newest fabric-api-certs pod on the node, which holds its
	// certificate.
	IdentityPod string
	// IdentityPods lists every fabric-api-certs pod on the node, newest
	// first. While one replaces another the sidecar may still present the
	// older one's certificate, which is just as bound to the node, so the
	// gateway accepts any of them.
	IdentityPods  []string
	Selected      bool
	OmittedReason string
}

// Address returns the sidecar's dial address.
func (n Node) Address() string {
	return fmt.Sprintf("%s:%d", hostPort(n.HostIP), n.Port)
}

func hostPort(ip string) string {
	for _, c := range ip {
		if c == ':' {
			return "[" + ip + "]"
		}
	}
	return ip
}

// DefaultCertsSelector selects the fabric-api-certs pods.
const DefaultCertsSelector = "app.kubernetes.io/name=fabric-api-certs"

// Discoverer finds the cell's fabric-api sidecars.
type Discoverer struct {
	Reader    client.Reader
	Namespace string
	Selector  labels.Selector
	// CertsSelector selects the per-node pods that obtain the sidecars'
	// certificates. Each node's sidecar presents its certs pod's identity.
	// Nil means each sidecar presents its own pod's identity.
	CertsSelector labels.Selector
}

// Snapshot lists the fabric-router pods carrying the fabric-api sidecar on
// nodes matching nodeSelector, one per node, and selects at most maxNodes of
// them in node-name order. Every discovered node appears in the result: one
// that cannot be executed on is kept with Selected false and a reason, so
// coverage accounts for it rather than silently dropping it.
func (d *Discoverer) Snapshot(ctx context.Context, nodeSelector *metav1.LabelSelector, maxNodes int) ([]Node, error) {
	var pods corev1.PodList
	if err := d.Reader.List(ctx, &pods,
		client.InNamespace(d.Namespace),
		client.MatchingLabelsSelector{Selector: d.Selector},
	); err != nil {
		return nil, fmt.Errorf("list fabric-router pods: %w", err)
	}
	var nodeSel labels.Selector
	if nodeSelector != nil {
		s, err := metav1.LabelSelectorAsSelector(nodeSelector)
		if err != nil {
			return nil, fmt.Errorf("node selector: %w", err)
		}
		nodeSel = s
	}

	certs, err := d.certPods(ctx)
	if err != nil {
		return nil, err
	}

	byNode := map[string][]Node{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		port, ok := sidecarPort(pod)
		if !ok || pod.Spec.NodeName == "" {
			continue
		}
		if nodeSel != nil {
			var node corev1.Node
			if err := d.Reader.Get(ctx, client.ObjectKey{Name: pod.Spec.NodeName}, &node); err != nil {
				continue
			}
			if !nodeSel.Matches(labels.Set(node.Labels)) {
				continue
			}
		}
		n := Node{Name: pod.Spec.NodeName, Pod: pod.Name, PodUID: string(pod.UID), HostIP: pod.Status.HostIP, Port: port}
		n.IdentityPod, n.IdentityPods = pod.Name, []string{pod.Name}
		if certs != nil {
			n.IdentityPods = certs[n.Name]
			n.IdentityPod = ""
			if len(n.IdentityPods) > 0 {
				n.IdentityPod = n.IdentityPods[0]
			}
		}
		n.OmittedReason = omitReason(pod)
		if n.OmittedReason == "" && n.IdentityPod == "" {
			n.OmittedReason = OmitNoCertificate
		}
		n.Selected = n.OmittedReason == ""
		byNode[n.Name] = append(byNode[n.Name], n)
	}

	var out []Node
	for _, candidates := range byNode {
		// During a rolling update a node can briefly have two pods: keep
		// one usable pod, record the rest as duplicates.
		sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].Selected && !candidates[j].Selected })
		for i, c := range candidates {
			if i > 0 && c.Selected {
				c.Selected, c.OmittedReason = false, OmitDuplicatePod
			}
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Pod < out[j].Pod
	})
	selected := 0
	for i := range out {
		if !out[i].Selected {
			continue
		}
		if selected >= maxNodes {
			out[i].Selected, out[i].OmittedReason = false, OmitNodeBudget
			continue
		}
		selected++
	}
	return out, nil
}

// certPods maps each node to its fabric-api-certs pods, newest first, or
// returns nil when the discoverer has no CertsSelector. Only a running pod
// can be the newest, since only it can have its certificate yet; pods
// being replaced follow it.
func (d *Discoverer) certPods(ctx context.Context) (map[string][]string, error) {
	if d.CertsSelector == nil {
		return nil, nil
	}
	var pods corev1.PodList
	if err := d.Reader.List(ctx, &pods,
		client.InNamespace(d.Namespace),
		client.MatchingLabelsSelector{Selector: d.CertsSelector},
	); err != nil {
		return nil, fmt.Errorf("list fabric-api-certs pods: %w", err)
	}
	byNode := map[string][]*corev1.Pod{}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Spec.NodeName != "" {
			byNode[p.Spec.NodeName] = append(byNode[p.Spec.NodeName], p)
		}
	}
	out := map[string][]string{}
	for node, ps := range byNode {
		sort.Slice(ps, func(i, j int) bool {
			ri, rj := certsUsable(ps[i]), certsUsable(ps[j])
			if ri != rj {
				return ri
			}
			return ps[i].CreationTimestamp.After(ps[j].CreationTimestamp.Time)
		})
		if !certsUsable(ps[0]) {
			continue
		}
		for _, p := range ps {
			out[node] = append(out[node], p.Name)
		}
	}
	return out, nil
}

func certsUsable(p *corev1.Pod) bool {
	return p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning
}

// sidecarPort returns the fabric-api container's gRPC port, reporting false
// when the pod has no fabric-api container.
func sidecarPort(pod *corev1.Pod) (int, bool) {
	for _, c := range pod.Spec.Containers {
		if c.Name != ContainerName {
			continue
		}
		for _, p := range c.Ports {
			if p.Name == PortName {
				return int(p.ContainerPort), true
			}
		}
		return DefaultPort, true
	}
	return 0, false
}

// omitReason returns why a pod cannot be executed on, or "". Pod Ready is
// deliberately not consulted: FRR's own probes drive it, and the sidecar's
// diagnostics never gate it.
func omitReason(pod *corev1.Pod) string {
	switch {
	case pod.DeletionTimestamp != nil:
		return OmitPodTerminating
	case pod.Status.Phase != corev1.PodRunning:
		return OmitPodNotRunning
	case pod.Status.HostIP == "":
		return OmitNoHostIP
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name == ContainerName {
			if cs.State.Running == nil {
				return OmitSidecarNotReady
			}
			return ""
		}
	}
	return OmitSidecarNotReady
}

// Inventory is the fixed router membership of one Looking Glass service
// request: every scheduled fabric-router pod grouped by node, one entry per
// router, whether or not it can execute.
type Inventory struct {
	ID              string
	CapturedAt      time.Time
	ResourceVersion string
	// Unscheduled counts fabric-router pods with no node.
	Unscheduled int
	// Routers lists one Node per router, sorted by name. A selected router
	// carries the pod it runs on; an omitted one carries its reason.
	Routers []Node
}

// Inventory lists the cell's fabric-router pods once and returns one router
// per node. Each router runs on its newest usable pod, ties broken by pod
// name; other pods on the node add nothing. A router with no usable pod is
// omitted with the reason of its newest pod. When requested is non-empty it
// selects exactly those routers, every other router being NotRequested, and
// naming a router outside the inventory fails with InvalidQuery. At most
// maxSelected routers are selected, in name order, the rest NodeBudget. An
// inventory of more than MaxInventoryRouters fails with InventoryTooLarge.
// Unlike Snapshot, it applies no node selector.
func (d *Discoverer) Inventory(
	ctx context.Context, requested []string, maxSelected int, now time.Time,
) (Inventory, error) {
	var pods corev1.PodList
	if err := d.Reader.List(ctx, &pods,
		client.InNamespace(d.Namespace),
		client.MatchingLabelsSelector{Selector: d.Selector},
	); err != nil {
		return Inventory{}, fmt.Errorf("list fabric-router pods: %w", err)
	}
	certs, err := d.certPods(ctx)
	if err != nil {
		return Inventory{}, err
	}
	inv := Inventory{ID: uuid.NewString(), CapturedAt: now, ResourceVersion: pods.ResourceVersion}
	type candidate struct {
		node    Node
		created time.Time
	}
	byNode := map[string][]candidate{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Spec.NodeName == "" {
			inv.Unscheduled++
			continue
		}
		n := Node{Name: pod.Spec.NodeName, Pod: pod.Name, PodUID: string(pod.UID), HostIP: pod.Status.HostIP}
		n.IdentityPod, n.IdentityPods = pod.Name, []string{pod.Name}
		if certs != nil {
			n.IdentityPods, n.IdentityPod = certs[n.Name], ""
			if len(n.IdentityPods) > 0 {
				n.IdentityPod = n.IdentityPods[0]
			}
		}
		port, ok := sidecarPort(pod)
		switch {
		case !ok:
			n.OmittedReason = OmitNoSidecar
		default:
			n.Port, n.OmittedReason = port, omitReason(pod)
			if n.OmittedReason == "" && n.IdentityPod == "" {
				n.OmittedReason = OmitNoCertificate
			}
		}
		n.Selected = n.OmittedReason == ""
		byNode[n.Name] = append(byNode[n.Name], candidate{node: n, created: pod.CreationTimestamp.Time})
	}
	if len(byNode) > MaxInventoryRouters {
		return Inventory{}, errcode.Status(errcode.InventoryTooLarge,
			fmt.Sprintf("the cell has %d routers, more than the %d a snapshot may list", len(byNode), MaxInventoryRouters))
	}
	for _, cs := range byNode {
		sort.Slice(cs, func(i, j int) bool {
			if cs[i].node.Selected != cs[j].node.Selected {
				return cs[i].node.Selected
			}
			if !cs[i].created.Equal(cs[j].created) {
				return cs[i].created.After(cs[j].created)
			}
			return cs[i].node.Pod < cs[j].node.Pod
		})
		inv.Routers = append(inv.Routers, cs[0].node)
	}
	sort.Slice(inv.Routers, func(i, j int) bool { return inv.Routers[i].Name < inv.Routers[j].Name })

	if len(requested) > 0 {
		want := make(map[string]bool, len(requested))
		for _, name := range requested {
			want[name] = true
		}
		for i := range inv.Routers {
			r := &inv.Routers[i]
			if want[r.Name] {
				delete(want, r.Name)
				continue
			}
			r.Selected, r.OmittedReason = false, OmitNotRequested
		}
		if len(want) > 0 {
			return Inventory{}, errcode.Status(errcode.InvalidQuery, "a selected node is not in the cell's router inventory")
		}
	}
	selected := 0
	for i := range inv.Routers {
		r := &inv.Routers[i]
		if !r.Selected {
			continue
		}
		if selected >= maxSelected {
			r.Selected, r.OmittedReason = false, OmitNodeBudget
			continue
		}
		selected++
	}
	return inv, nil
}
