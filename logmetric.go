package relayproxy

import (
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
)

type LogMetric struct {
	mu         sync.RWMutex
	fields     map[string]any
	attributes map[string]attribute.KeyValue
}

// NewLogMetric initializes a LogMetric instance
func NewLogMetric(initialFields map[string]any, attributes []attribute.KeyValue) *LogMetric {
	lm := &LogMetric{
		fields:     make(map[string]any, len(initialFields)),
		attributes: make(map[string]attribute.KeyValue, len(attributes)),
	}
	for k, v := range initialFields {
		lm.fields[k] = v
	}
	for _, attr := range attributes {
		lm.attributes[string(attr.Key)] = attr
	}
	return lm
}

// Copy creates a deep copy of LogMetric
func (l *LogMetric) Copy() *LogMetric {
	l.mu.RLock()
	defer l.mu.RUnlock()

	copy := &LogMetric{
		fields:     make(map[string]any, len(l.fields)),
		attributes: make(map[string]attribute.KeyValue, len(l.attributes)),
	}
	for k, v := range l.fields {
		copy.fields[k] = v
	}
	for k, v := range l.attributes {
		copy.attributes[k] = v
	}
	return copy
}

func (l *LogMetric) String(k, v string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fields[k] = v
	l.attributes[k] = attribute.String(k, v)
}

func (l *LogMetric) Int64(k string, v int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fields[k] = v
	l.attributes[k] = attribute.Int64(k, v)
}

func (l *LogMetric) Time(k string, v time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fields[k] = v
	l.attributes[k] = attribute.Int64(k, v.Unix())
}

func (l *LogMetric) Error(err error) {
	if err == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fields["Err"] = err.Error()
	l.attributes["Err"] = attribute.String("Err", err.Error())
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
	for _, attr := range attrs {
		l.attributes[string(attr.Key)] = attr
	}
}

func (l *LogMetric) Merge(m *LogMetric) {
	if m == nil {
		return
	}

	m.mu.RLock()
	mFields := make(map[string]any, len(m.fields))
	mAttributes := make(map[string]attribute.KeyValue, len(m.attributes))
	for k, v := range m.fields {
		mFields[k] = v
	}
	for k, v := range m.attributes {
		mAttributes[k] = v
	}
	m.mu.RUnlock()

	l.mu.Lock()
	defer l.mu.Unlock()
	for k, v := range mFields {
		if _, exists := l.fields[k]; !exists {
			l.fields[k] = v
		}
	}
	for k, v := range mAttributes {
		if _, exists := l.attributes[k]; !exists {
			l.attributes[k] = v
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

func (l *LogMetric) GetAttributes() []attribute.KeyValue {
	l.mu.RLock()
	defer l.mu.RUnlock()

	attrs := make([]attribute.KeyValue, 0, len(l.attributes))
	for _, v := range l.attributes {
		attrs = append(attrs, v)
	}
	return attrs
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
