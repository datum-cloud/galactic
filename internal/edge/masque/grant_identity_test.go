package masque

import (
	"testing"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

func TestRefreshedGrantPreservesBindingIdentity(t *testing.T) {
	original := Grant{NetworkUID: "network-a", BindingUID: "binding-a",
		Endpoint: &galacticv1alpha1.MASQUEEndpointScope{EndpointUID: "endpoint"}}
	for _, mutate := range []func(*Grant){
		func(grant *Grant) { grant.NetworkUID = "network-b" },
		func(grant *Grant) { grant.BindingUID = "binding-b" },
		func(grant *Grant) { grant.VPCUID = "recreated-vpc" },
	} {
		changed := original
		mutate(&changed)
		if original.sameAuthority(&changed) {
			t.Fatal("refresh changed binding authority")
		}
	}
}
