// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package admission

import (
	"errors"
	"fmt"
	"strings"

	authenticationv1 "k8s.io/api/authentication/v1"
)

// serviceAccountPrefix starts every ServiceAccount username the API server
// authenticates.
const serviceAccountPrefix = "system:serviceaccount:"

// PodUIDExtra is the user-info extra key in which the API server records the
// pod a bound ServiceAccount token was issued for.
const PodUIDExtra = "authentication.kubernetes.io/pod-uid"

// Identity is a provider pod as the API server authenticated it.
type Identity struct {
	ServiceAccount ServiceAccount
	PodUID         string
}

// IdentityFromUserInfo returns the identity of the caller the API server
// authenticated as u. Only a pod-bound ServiceAccount token yields one: any
// other user, or a ServiceAccount token not bound to exactly one pod, is
// refused.
func IdentityFromUserInfo(u authenticationv1.UserInfo) (Identity, error) {
	rest, ok := strings.CutPrefix(u.Username, serviceAccountPrefix)
	if !ok {
		return Identity{}, fmt.Errorf("user %q is not a ServiceAccount", u.Username)
	}
	ns, name, ok := strings.Cut(rest, ":")
	if !ok || ns == "" || name == "" || strings.Contains(name, ":") {
		return Identity{}, fmt.Errorf("malformed ServiceAccount username %q", u.Username)
	}
	uids := u.Extra[PodUIDExtra]
	if len(uids) != 1 || uids[0] == "" {
		return Identity{}, fmt.Errorf("token for %s/%s is not bound to one pod", ns, name)
	}
	return Identity{ServiceAccount: ServiceAccount{Namespace: ns, Name: name}, PodUID: uids[0]}, nil
}

func (id Identity) validate() error {
	if id.ServiceAccount.Namespace == "" || id.ServiceAccount.Name == "" || id.PodUID == "" {
		return errors.New("no pod-bound ServiceAccount identity")
	}
	return nil
}

// String formats the ServiceAccount as namespace/name.
func (sa ServiceAccount) String() string { return sa.Namespace + "/" + sa.Name }
