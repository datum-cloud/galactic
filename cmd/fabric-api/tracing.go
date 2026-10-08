// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"google.golang.org/grpc"

	"go.datum.net/galactic/internal/metadata"
)

// setupTracing installs W3C trace-context propagation always, and an OTLP
// trace exporter when OTEL_EXPORTER_OTLP_ENDPOINT (or the traces-specific
// variable) is set. The returned function flushes and stops it.
func setupTracing(ctx context.Context, role string) func() {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == "" {
		return func() {}
	}
	exp, err := otlptracegrpc.New(ctx)
	if err != nil {
		slog.Warn("tracing disabled: could not create OTLP exporter", "error", err)
		return func() {}
	}
	res, _ := sdkresource.Merge(sdkresource.Default(), sdkresource.NewWithAttributes(semconv.SchemaURL,
		semconv.ServiceName(appName+"-"+role), semconv.ServiceVersion(metadata.Version)))
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
	otel.SetTracerProvider(tp)
	slog.Info("tracing enabled")
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tp.Shutdown(ctx)
	}
}

func serverStats() grpc.ServerOption { return grpc.StatsHandler(otelgrpc.NewServerHandler()) }

func clientStats() grpc.DialOption { return grpc.WithStatsHandler(otelgrpc.NewClientHandler()) }
