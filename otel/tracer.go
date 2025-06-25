package otel

import (
	"context"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

var (
	tracer      trace.Tracer
	otelEnabled bool
	noopTracer  = noop.NewTracerProvider().Tracer("")
)

func InitTracer(ctx context.Context, enableTracer bool, sampleRate float64, env, tempoEndpoint, nodeID, appName, version string) (trace.Tracer, func()) {
	otelEnabled = enableTracer
	// Create the primary OTLP exporter (e.g., to Tempo)
	tempoExporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(tempoEndpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create Tempo OTLP gRPC exporter")
	}

	// Construct tracer provider options
	tpOpts := []sdktrace.TracerProviderOption{
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(sampleRate)),
		sdktrace.WithSpanProcessor(sdktrace.NewBatchSpanProcessor(tempoExporter)),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(appName),
			semconv.ServiceVersionKey.String(version),
			semconv.DeploymentEnvironmentKey.String(env+"-"+nodeID),
		)),
	}

	// Add local structured logging span exporter if running locally
	if env == "local" {
		localExporter := NewLocalExporter()
		tpOpts = append(tpOpts, sdktrace.WithSpanProcessor(sdktrace.NewBatchSpanProcessor(localExporter)))
	}

	// Set global tracer provider
	tp := sdktrace.NewTracerProvider(tpOpts...)
	otel.SetTracerProvider(tp)
	tracer = otel.Tracer(env)

	return tracer, func() {
		if err := tp.Shutdown(ctx); err != nil {
			log.Fatal().Err(err).Msg("error shutting down tracer provider")
		}
	}
}

func Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	if otelEnabled {
		return tracer.Start(ctx, name, opts...)
	}
	return noopTracer.Start(ctx, name, opts...)
}
