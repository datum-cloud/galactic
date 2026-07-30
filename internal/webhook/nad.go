// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package webhook

import (
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// cniVersion is the CNI spec version this webhook writes into every NAD's
// conflist. Matches the version internal/cni's config.go expects.
const cniVersion = "1.0.0"

// pluginType is the CNI plugin type every NAD this webhook creates points at.
const pluginType = "galactic-cni"

// interfaceTypeVeth is the default interface type baked into every NAD's
// conflist (see NADDefaults.InterfaceType) — matches internal/cni/cni.go's
// interfaceTypeVeth constant. Not imported directly: internal/webhook
// deliberately avoids importing internal/cni to keep netlink-heavy
// dependencies out of the webhook binary.
const interfaceTypeVeth = "veth"

// termination mirrors internal/cni/types.go's Termination. Field tags MUST
// match exactly — this struct's JSON encoding is the wire contract between
// the NAD this webhook creates and the galactic-cni invocation Multus drives
// from it.
type termination struct {
	Network string `json:"network"`
	Via     string `json:"via,omitempty"`
}

// ipamConfig mirrors the subset of internal/cni/types.go's IPAM this webhook
// populates. See termination's doc comment on why the tags must match.
type ipamConfig struct {
	Type     string `json:"type"`
	StaticIP string `json:"static_ip,omitempty"`
}

// NADDefaults holds the galactic-owned constants baked into every NAD this
// webhook creates: MTU, interface type, IPAM policy, and terminations.
// VPCSpec has none of these fields by design — see this repo's design plan,
// "NAD content" (Option B: these come from galactic's own constants/config,
// not the VPC CR). A future revision could source per-VPC overrides from a
// ConfigMap; hardcoded defaults are sufficient for the first implementation.
type NADDefaults struct {
	MTU           int
	InterfaceType string
	IPAM          *ipamConfig
	Terminations  []termination
}

// DefaultNADDefaults returns the built-in NAD defaults used when the
// PodMutator isn't given an explicit NADDefaults.
func DefaultNADDefaults() NADDefaults {
	return NADDefaults{
		MTU:           1500,
		InterfaceType: interfaceTypeVeth,
	}
}

// cniConflist mirrors the subset of internal/cni/types.go's PluginConf this
// webhook populates. Field tags MUST match PluginConf exactly.
type cniConflist struct {
	CNIVersion    string        `json:"cniVersion"`
	Name          string        `json:"name"`
	Type          string        `json:"type"`
	VPC           string        `json:"vpc"`
	VPCName       string        `json:"vpc_name,omitempty"`
	VPCAttachment string        `json:"vpcattachment"`
	MTU           int           `json:"mtu,omitempty"`
	InterfaceType string        `json:"interface_type,omitempty"`
	Terminations  []termination `json:"terminations,omitempty"`
	IPAM          *ipamConfig   `json:"ipam,omitempty"`
}

// buildNAD constructs the NetworkAttachmentDefinition object this webhook
// creates for one pod's VPC attachment: name is the deterministic
// "<vpcBase62>-<vpcAttachmentBase62>" (see AllocateVPCAttachmentID and
// pod_mutator.go), vpcName is the VPC CR's Kubernetes object name (needed by
// galactic-cni to build VPCAttachmentSpec.VPC.Name — see PluginConf.VPCName),
// and defaults supplies the galactic-owned conflist fields VPCSpec doesn't
// carry.
func buildNAD(
	name, namespace, vpcBase62, vpcName, vpcAttachmentBase62 string, defaults NADDefaults,
) (*unstructured.Unstructured, error) {
	conf := cniConflist{
		CNIVersion:    cniVersion,
		Name:          name,
		Type:          pluginType,
		VPC:           vpcBase62,
		VPCName:       vpcName,
		VPCAttachment: vpcAttachmentBase62,
		MTU:           defaults.MTU,
		InterfaceType: defaults.InterfaceType,
		Terminations:  defaults.Terminations,
		IPAM:          defaults.IPAM,
	}
	configJSON, err := json.Marshal(conf)
	if err != nil {
		return nil, fmt.Errorf("marshal NAD conflist: %w", err)
	}

	nad := &unstructured.Unstructured{}
	nad.SetGroupVersionKind(nadGVK)
	nad.SetName(name)
	nad.SetNamespace(namespace)
	nad.SetLabels(map[string]string{
		labelVPC:          vpcName,
		labelAttachmentID: vpcAttachmentBase62,
	})
	if err := unstructured.SetNestedField(nad.Object, string(configJSON), "spec", "config"); err != nil {
		return nil, fmt.Errorf("set NAD spec.config: %w", err)
	}
	return nad, nil
}
