package masque

import (
	"testing"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

func TestRefreshedGrantPreservesBindingIdentity(t *testing.T) {
	original := Grant{EndpointRef: &galacticv1alpha1.MASQUEEndpointReference{Namespace: "masque-system", Name: "endpoint"}}
	for _, mutate := range []func(*Grant){
		func(grant *Grant) { grant.EndpointRef = nil },
		func(grant *Grant) { grant.Service.UID = "recreated-service" },
		func(grant *Grant) { grant.VPCUID = "recreated-vpc" },
	} {
		changed := original
		mutate(&changed)
		if original.sameAuthority(&changed) {
			t.Fatal("refresh changed binding authority")
		}
	}
}
