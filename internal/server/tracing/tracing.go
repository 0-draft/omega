// Package tracing wires OpenTelemetry tracing into omega processes.
//
// The tracer provider is opt-in: by default it is a no-op. Setting
// OTEL_EXPORTER_OTLP_ENDPOINT (standard OTel env var) or passing
// --otlp-endpoint to the CLI flips on an OTLP/HTTP exporter. Setting
// OTEL_TRACES_EXPORTER=stdout switches to a JSON exporter that writes to
// stderr - useful for local debugging without a collector.
//
// Resource attributes follow OpenTelemetry semantic conventions: every
// span carries service.name, service.version, and service.instance.id so
// it lines up with anything else feeding the same backend.
package tracing

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Config holds the knobs Setup honors. Empty Endpoint with empty
// OTEL_EXPORTER_OTLP_ENDPOINT env disables the exporter.
type Config struct {
	ServiceName    string
	ServiceVersion string
	// Endpoint, if non-empty, overrides OTEL_EXPORTER_OTLP_ENDPOINT.
	// Use a host:port form (no scheme); Insecure controls TLS.
	Endpoint string
	Insecure bool
}

// ShutdownFunc flushes pending spans and tears down the provider. Safe
// to call with a nil receiver - Setup always returns a usable closer.
type ShutdownFunc func(context.Context) error

// Setup installs a global TracerProvider and propagator. It returns a
// shutdown function the caller MUST defer; otherwise spans queued in
// the batch processor will be lost on exit. When tracing is disabled,
// Setup installs the no-op provider and the returned shutdown is a
// no-op too.
func Setup(ctx context.Context, cfg Config) (ShutdownFunc, error) {
	exporterKind := os.Getenv("OTEL_TRACES_EXPORTER")
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}

	if exporterKind == "none" || os.Getenv("OTEL_SDK_DISABLED") == "true" {
		installNoop()
		return noopShutdown, nil
	}

	if exporterKind == "" && endpoint == "" {
		installNoop()
		return noopShutdown, nil
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("tracing resource: %w", err)
	}

	var exporter sdktrace.SpanExporter
	switch exporterKind {
	case "stdout":
		exporter, err = stdouttrace.New(stdouttrace.WithPrettyPrint())
	default:
		opts := []otlptracehttp.Option{}
		if endpoint != "" {
			opts = append(opts, otlptracehttp.WithEndpoint(endpoint))
		}
		if cfg.Insecure || os.Getenv("OTEL_EXPORTER_OTLP_INSECURE") == "true" {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		exporter, err = otlptracehttp.New(ctx, opts...)
	}
	if err != nil {
		return nil, fmt.Errorf("tracing exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(2*time.Second)),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp.Shutdown, nil
}

// Tracer returns the named tracer from the active provider. Convenience
// wrapper so callers don't import otel directly.
func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

func installNoop() {
	otel.SetTracerProvider(noop.NewTracerProvider())
}

func noopShutdown(context.Context) error { return nil }
