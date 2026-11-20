package connectip

import (
	"context"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

type endpointContextKey struct{}

func WithEndpoint(ctx context.Context, endpoint galacticv1alpha1.MASQUEEndpointReference) context.Context {
	return context.WithValue(ctx, endpointContextKey{}, endpoint)
}

func EndpointFromContext(ctx context.Context) *galacticv1alpha1.MASQUEEndpointReference {
	endpoint, ok := ctx.Value(endpointContextKey{}).(galacticv1alpha1.MASQUEEndpointReference)
	if !ok {
		return nil
	}
	return &endpoint
}
