package relayproxy

import (
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
)

type LogMetric struct {
	mu     sync.RWMutex
	fields map[string]any
}

// NewLogMetric initializes a LogMetric instance
func NewLogMetric(initialFields map[string]any) *LogMetric {
	lm := &LogMetric{
		fields: make(map[string]any, len(initialFields)),
	}
	for k, v := range initialFields {
		lm.fields[k] = v
	}
	return lm
}

// Copy creates a deep copy of LogMetric
func (l *LogMetric) Copy() *LogMetric {
	l.mu.RLock()
	defer l.mu.RUnlock()

	copy := &LogMetric{
		fields: make(map[string]any, len(l.fields)),
	}
	for k, v := range l.fields {
		copy.fields[k] = v
	}
	return copy
}

func (l *LogMetric) String(k, v string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fields[k] = v
}

func (l *LogMetric) Int64(k string, v int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fields[k] = v
}

func (l *LogMetric) Time(k string, v time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fields[k] = v
}

func (l *LogMetric) Error(err error) {
	if err == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fields["Err"] = err.Error()
}

func (l *LogMetric) Fields(fields map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, v := range fields {
		l.fields[k] = v
	}
}

func (l *LogMetric) Attributes(attrs ...attribute.KeyValue) {
	l.mu.Lock()
	defer l.mu.Unlock()
}

func (l *LogMetric) Merge(m *LogMetric) {
	if m == nil {
		return
	}

	m.mu.RLock()
	mFields := make(map[string]any, len(m.fields))
	for k, v := range m.fields {
		mFields[k] = v
	}
	m.mu.RUnlock()

	l.mu.Lock()
	defer l.mu.Unlock()
	for k, v := range mFields {
		if _, exists := l.fields[k]; !exists {
			l.fields[k] = v
		}
	}
}

func (l *LogMetric) GetFields() map[string]any {
	l.mu.RLock()
	defer l.mu.RUnlock()

	fields := make(map[string]any, len(l.fields))
	for k, v := range l.fields {
		fields[k] = v
	}
	return fields
}

func (l *LogMetric) ApplyToLoggerWithLevel(logger zerolog.Logger, level zerolog.Level) *zerolog.Event {
	l.mu.RLock()
	defer l.mu.RUnlock()

	event := logger.WithLevel(level)
	for k, v := range l.fields {
		event = event.Interface(k, v)
	}
	return event
}
