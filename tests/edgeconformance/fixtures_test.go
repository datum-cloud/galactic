// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeconformance_test

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// The suite's providers and grants. Tenants ns10 and ns20 are VPCs 10 and
// 20 of the lab; both grants hold the same client pool and prefixes, so the
// two providers' attachments and routes overlap address for address.
const (
	echoPort = 7777

	pool    = "fd00:ed9e:0:1::/64"
	grant   = "fd00:ed9e:100::/48"
	prefix  = "fd00:ed9e:100:1::/64"
	target  = "fd00:ed9e:100:1::1"
	outside = "fd00:ed9e:200:1::/64"

	capSocket = "SocketAccess"
	// fixtureTag fills fields of objects the suite writes as a pod that
	// runs no provider.
	fixtureTag = "conformance"
	labIngress = "lab-ingress"
)

// edgeTaint tolerates the taint the lab's edge nodes carry for the egress
// shards.
var edgeTaint = corev1.Toleration{Key: "galactic.datumapis.com/nat", Operator: corev1.TolerationOpExists,
	Effect: corev1.TaintEffectNoSchedule}

// tenant is one VPC of the lab and the provider the suite grants it to.
type tenant struct {
	vpcNamespace string
	vpc          string
	provider     string
	namespace    string
	service      string
}

var (
	tenantA = tenant{vpcNamespace: "ns10", vpc: "10", provider: "conf-a", namespace: "edge-conf-a", service: "svc-a"}
	tenantB = tenant{vpcNamespace: "ns20", vpc: "20", provider: "conf-b", namespace: "edge-conf-b", service: "svc-b"}
)

// register applies the provider's registration from
// examples/edge-provider/deploy/registration, renamed, and approves it when
// approve is set.
func (l *lab) register(t *testing.T, provider, namespace string, approve bool, contractVersions ...string) {
	t.Helper()
	if len(contractVersions) == 0 {
		contractVersions = []string{"v1alpha1"}
	}
	versions := `["` + strings.Join(contractVersions, `","`) + `"]`
	l.applyOverlay(t, "registration-"+provider, "registration", fmt.Sprintf(`
patches:
  - target:
      kind: EdgeProvider
      name: example-echo
    options:
      allowNameChange: true
    patch: |-
      - op: replace
        path: /metadata/name
        value: %s
      - op: replace
        path: /spec/serviceAccounts
        value: [{namespace: %s, name: edge-provider}]
      - op: replace
        path: /spec/contractVersions
        value: %s
`, provider, namespace, versions), nil)
	if approve {
		if _, err := l.kubectl("patch", "edgeprovider", provider, "--subresource=status", "--type=merge",
			"-p", `{"status":{"approved":true}}`); err != nil {
			t.Fatal(err)
		}
	}
}

// applyOverlay renders a kustomization over one of
// examples/edge-provider/deploy's directories and applies it.
func (l *lab) applyOverlay(t *testing.T, name, base, extra string, files map[string]string) {
	t.Helper()
	l.applyOverlayOf(t, filepath.Join(l.root, "examples", "edge-provider", "deploy", base), name, extra, files)
}

// applyOverlayOf renders a kustomization named name over the directory base
// and applies it.
func (l *lab) applyOverlayOf(t *testing.T, base, name, extra string, files map[string]string) {
	t.Helper()
	dir := filepath.Join(l.artifacts, "overlays", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(dir, base)
	if err != nil {
		t.Fatal(err)
	}
	k := "resources:\n  - " + rel + "\n" + extra
	if err := os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(k), 0o644); err != nil {
		t.Fatal(err)
	}
	for f, body := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.kubectl("apply", "-k", dir); err != nil {
		t.Fatal(err)
	}
}

// ensureNamespace creates a provider namespace.
func (l *lab) ensureNamespace(t *testing.T, name string) {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if err := l.c.Create(context.Background(), ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
}

// vpcUID returns the UID of a tenant's VPC object.
func (l *lab) vpcUID(t *testing.T, tn tenant) string {
	t.Helper()
	var v cloudv1alpha1.VPC
	if err := l.c.Get(context.Background(), client.ObjectKey{Namespace: tn.vpcNamespace, Name: tn.vpc}, &v); err != nil {
		t.Fatalf("VPC %s/%s (task deploy:galactic-edge creates it): %v", tn.vpcNamespace, tn.vpc, err)
	}
	return string(v.UID)
}

// grantService creates or replaces the platform authority's grant of tn's
// VPC to tn's provider, and returns it as stored.
func (l *lab) grantService(t *testing.T, tn tenant, name string, mutate func(*galacticv1alpha1.EdgeService),
) *galacticv1alpha1.EdgeService {
	t.Helper()
	svc := &galacticv1alpha1.EdgeService{
		ObjectMeta: metav1.ObjectMeta{Namespace: tn.vpcNamespace, Name: name},
		Spec: galacticv1alpha1.EdgeServiceSpec{
			ProviderRef:  galacticv1alpha1.EdgeProviderReference{Name: tn.provider},
			VPCRef:       galacticv1alpha1.EdgeVPCReference{Name: tn.vpc, UID: l.vpcUID(t, tn)},
			Capabilities: []string{capSocket, "PacketAccess", "PrefixReachability"},
			Prefixes:     []string{grant},
			ClientPool:   pool,
			DrainSeconds: ptr.To[int32](10),
			TrafficPolicy: &galacticv1alpha1.TrafficPolicyBindingSpec{
				IngressPolicyRef: &galacticv1alpha1.LocalPolicyReference{Name: labIngress},
				EgressPolicyRef:  &galacticv1alpha1.LocalPolicyReference{Name: "lab-egress"},
			},
		},
	}
	if mutate != nil {
		mutate(svc)
	}
	ctx := context.Background()
	l.deleteAndWait(t, &galacticv1alpha1.EdgeService{ObjectMeta: svc.ObjectMeta})
	if err := l.c.Create(ctx, svc); err != nil {
		t.Fatal(err)
	}
	return svc
}

// deleteAndWait deletes obj and waits until it is gone.
func (l *lab) deleteAndWait(t *testing.T, obj client.Object) {
	t.Helper()
	ctx := context.Background()
	if err := l.c.Delete(ctx, obj); client.IgnoreNotFound(err) != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Minute, time.Second, "deletion of "+obj.GetName(), func() (bool, error) {
		err := l.c.Get(ctx, client.ObjectKeyFromObject(obj), obj)
		return apierrors.IsNotFound(err), err
	})
}

// providerConfig is the provider's config.yaml for one service.
type serviceConfig struct {
	tn       tenant
	svc      *galacticv1alpha1.EdgeService
	vpcUID   string
	prefixes []string
	contract string
}

func providerConfig(provider string, services ...serviceConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "provider: %s\nport: %d\nservices:\n", provider, echoPort)
	for _, s := range services {
		fmt.Fprintf(&b, "  - namespace: %s\n    name: %s\n    uid: %s\n    vpcUID: %s\n", s.svc.Namespace,
			s.svc.Name, s.svc.UID, s.vpcUID)
		b.WriteString("    capabilities: [SocketAccess, PacketAccess]\n")
		if len(s.prefixes) > 0 {
			quoted := make([]string, len(s.prefixes))
			for i, p := range s.prefixes {
				quoted[i] = strconv.Quote(p)
			}
			fmt.Fprintf(&b, "    prefixes: [%s]\n", strings.Join(quoted, ", "))
		}
		if s.contract != "" {
			fmt.Fprintf(&b, "    contractVersion: %s\n", s.contract)
		}
	}
	return b.String()
}

// deployProvider applies examples/edge-provider/deploy/provider as
// deployment name in namespace, running config on node, and waits for its
// pod to run.
func (l *lab) deployProvider(t *testing.T, namespace, name, node, config string) {
	t.Helper()
	l.applyOverlay(t, namespace+"-"+name, "provider", fmt.Sprintf(`
namespace: %s
configMapGenerator:
  - name: edge-provider-config-%s
    files:
      - config.yaml
patches:
  - target:
      kind: Deployment
    options:
      allowNameChange: true
    patch: |-
      - op: replace
        path: /metadata/name
        value: edge-provider-%s
      - op: replace
        path: /spec/template/spec/volumes/0/configMap/name
        value: edge-provider-config-%s
      - op: add
        path: /spec/template/spec/nodeSelector
        value: {kubernetes.io/hostname: %s}
      - op: add
        path: /spec/template/spec/tolerations
        value: [{key: galactic.datumapis.com/nat, operator: Exists, effect: NoSchedule}]
      - op: add
        path: /spec/template/spec/containers/0/imagePullPolicy
        value: Never
      - op: add
        path: /spec/template/metadata/labels/edge-conformance~1instance
        value: %s
      - op: add
        path: /spec/selector/matchLabels/edge-conformance~1instance
        value: %s
`, namespace, name, name, name, node, name, name)+tunPatch, map[string]string{"config.yaml": config})
	l.waitProviderPod(t, namespace, name, node)
}

// tunPatch is how the lab gives a provider pod /dev/net/tun; see
// deploy/containerlab/resources/galactic-edge/tun-device-plugin.
var tunPatch = `  - target:
      kind: Deployment
    patch: |-
      - op: add
        path: /spec/template/spec/containers/0/resources
        value: {limits: {devic.es/tun: "1"}}
`

// providerPod returns the running pod of deployment name, on node.
func (l *lab) providerPod(t *testing.T, namespace, name string) *corev1.Pod {
	t.Helper()
	var pods corev1.PodList
	if err := l.c.List(context.Background(), &pods, client.InNamespace(namespace),
		client.MatchingLabels{"edge-conformance/instance": name}); err != nil {
		t.Fatal(err)
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning {
			return p
		}
	}
	return nil
}

func (l *lab) waitProviderPod(t *testing.T, namespace, name, node string) *corev1.Pod {
	t.Helper()
	var pod *corev1.Pod
	eventually(t, 3*time.Minute, time.Second, "provider "+name+" running on "+node, func() (bool, error) {
		pod = l.providerPod(t, namespace, name)
		return pod != nil && pod.Spec.NodeName == node, nil
	})
	return pod
}

// stopProvider scales the deployment to zero, which shuts its pods down
// gracefully.
func (l *lab) stopProvider(t *testing.T, namespace, name string) {
	t.Helper()
	key := client.ObjectKey{Namespace: namespace, Name: "edge-provider-" + name}
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		d := &appsv1.Deployment{}
		if err := l.c.Get(context.Background(), key, d); err != nil {
			return err
		}
		d.Spec.Replicas = ptr.To[int32](0)
		return l.c.Update(context.Background(), d)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// attachmentOf returns pod's attachment to svc.
func (l *lab) attachmentOf(t *testing.T, pod *corev1.Pod, svc *galacticv1alpha1.EdgeService,
) *galacticv1alpha1.EdgeAttachment {
	t.Helper()
	var a galacticv1alpha1.EdgeAttachment
	key := client.ObjectKey{Namespace: pod.Namespace, Name: "ea-" + string(pod.UID) + "-" + string(svc.UID)}
	if err := l.c.Get(context.Background(), key, &a); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		t.Fatal(err)
	}
	return &a
}

// waitServing waits until pod's attachment to svc is programmed and ready.
func (l *lab) waitServing(t *testing.T, pod *corev1.Pod, svc *galacticv1alpha1.EdgeService,
) *galacticv1alpha1.EdgeAttachment {
	t.Helper()
	var a *galacticv1alpha1.EdgeAttachment
	eventually(t, 3*time.Minute, 2*time.Second, "attachment of "+pod.Name+" ready", func() (bool, error) {
		a = l.attachmentOf(t, pod, svc)
		if a == nil {
			return false, nil
		}
		c := a.Status.Conditions
		if cond := meta.FindStatusCondition(c, galacticv1alpha1.EdgeAttachmentAdmitted); cond != nil &&
			cond.Status == metav1.ConditionFalse {
			return false, fmt.Errorf("refused: %s: %s", cond.Reason, cond.Message)
		}
		return meta.IsStatusConditionTrue(c, galacticv1alpha1.EdgeAttachmentProgrammed) &&
			meta.IsStatusConditionTrue(c, galacticv1alpha1.EdgeAttachmentReady), nil
	})
	return a
}

// route returns the route of p in vpcUID from namespace, found by its
// spec rather than by a provider's naming.
func (l *lab) route(t *testing.T, namespace, vpcUID string, p netip.Prefix) *galacticv1alpha1.EdgeRoute {
	t.Helper()
	var routes galacticv1alpha1.EdgeRouteList
	if err := l.c.List(context.Background(), &routes, client.InNamespace(namespace)); err != nil {
		t.Fatal(err)
	}
	for i := range routes.Items {
		r := &routes.Items[i]
		if r.Spec.VPCUID == vpcUID && r.Spec.Prefix == p.Masked().String() && r.DeletionTimestamp == nil {
			return r
		}
	}
	return nil
}

// waitAccepted waits until the route of p is accepted for attachment.
func (l *lab) waitAccepted(t *testing.T, namespace, vpcUID string, p netip.Prefix, attachment string,
	timeout time.Duration) *galacticv1alpha1.EdgeRoute {
	t.Helper()
	var r *galacticv1alpha1.EdgeRoute
	eventually(t, timeout, time.Second, "route "+p.String()+" accepted for "+attachment, func() (bool, error) {
		r = l.route(t, namespace, vpcUID, p)
		return r != nil && r.Status.Accepted != nil && r.Status.Accepted.Attachment == attachment &&
			meta.IsStatusConditionTrue(r.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted), nil
	})
	return r
}

// clientPID returns the sandbox PID of tenant's conformance client on node.
func (l *lab) clientPID(t *testing.T, tn tenant, node string) int {
	t.Helper()
	i := map[string]string{computeNode: "1", edgeNode1: "2", edgeNode2: "3"}[node]
	var pods corev1.PodList
	if err := l.c.List(context.Background(), &pods, client.InNamespace(tn.vpcNamespace),
		client.MatchingLabels{"app": "edge-client-" + i}); err != nil {
		t.Fatal(err)
	}
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning && p.DeletionTimestamp == nil {
			pid, err := sandboxPID(node, p.Namespace, p.Name)
			if err != nil {
				t.Fatal(err)
			}
			return pid
		}
	}
	t.Fatalf("no running edge-client-%s in %s (task deploy:ns10 / deploy:ns20 creates them)", i, tn.vpcNamespace)
	return 0
}
