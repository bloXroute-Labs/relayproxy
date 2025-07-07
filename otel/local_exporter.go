package otel

import (
	"context"

	"github.com/bloXroute-Labs/relayproxy"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/sdk/trace"
)

type SpanExporter struct{}

func NewLocalExporter() *SpanExporter {
	return &SpanExporter{}
}

func (e *SpanExporter) ExportSpans(_ context.Context, spans []trace.ReadOnlySpan) error {
	for _, span := range spans {
		logMetric := relayproxy.NewLogMetric(
			map[string]any{
				"name":     span.Name(),
				"traceID":  span.SpanContext().TraceID().String(),
				"duration": span.EndTime().Sub(span.StartTime()).String(),
			},
		)

		logMetric.Time("start", span.StartTime())

		logMetric.ApplyToLoggerWithLevel(log.Logger, zerolog.InfoLevel).
			Msg("new OpenTelemetry span")
	}
	return nil
}

func (e *SpanExporter) Shutdown(_ context.Context) error {
	log.Info().Msg("shutting down local span exporter")
	return nil
}
