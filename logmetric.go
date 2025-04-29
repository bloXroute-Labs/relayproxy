package relayproxy

import (
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

type LogMetric struct {
	mu         sync.RWMutex // Allows multiple reads, blocks only on writes
	fields     map[string]zap.Field
	attributes map[string]attribute.KeyValue
}

// NewLogMetric initializes a LogMetric instance
func NewLogMetric(fields []zap.Field, attributes []attribute.KeyValue) *LogMetric {
	lm := &LogMetric{
		fields:     make(map[string]zap.Field, len(fields)),
		attributes: make(map[string]attribute.KeyValue, len(attributes)),
	}
	for _, field := range fields {
		lm.fields[field.Key] = field
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

	// Use pre-allocated capacity to avoid resizing
	lm := &LogMetric{
		fields:     make(map[string]zap.Field, len(l.fields)),
		attributes: make(map[string]attribute.KeyValue, len(l.attributes)),
	}
	for k, v := range l.fields {
		lm.fields[k] = v
	}
	for k, v := range l.attributes {
		lm.attributes[k] = v
	}
	return lm
}

// String adds a string field to the log metric
func (l *LogMetric) String(k, v string) {
	l.mu.Lock()
	l.fields[k] = zap.String(k, v)
	l.attributes[k] = attribute.String(k, v)
	l.mu.Unlock()
}

// Int64 adds an int64 field to the log metric
func (l *LogMetric) Int64(k string, v int64) {
	l.mu.Lock()
	l.fields[k] = zap.Int64(k, v)
	l.attributes[k] = attribute.Int64(k, v)
	l.mu.Unlock()
}

// Time adds a time field to the log metric
func (l *LogMetric) Time(k string, v time.Time) {
	l.mu.Lock()
	l.fields[k] = zap.Time(k, v)
	l.attributes[k] = attribute.Int64(k, v.Unix())
	l.mu.Unlock()
}

// Error adds an error field to the log metric
func (l *LogMetric) Error(err error) {
	if err == nil {
		return
	}
	l.mu.Lock()
	l.fields["Err"] = zap.Error(err)
	l.attributes["Err"] = attribute.String("Err", err.Error())
	l.mu.Unlock()
}

// Fields adds multiple fields at once, reducing lock overhead
func (l *LogMetric) Fields(fields ...zap.Field) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, field := range fields {
		l.fields[field.Key] = field
	}
}

// Attributes adds multiple attributes at once, reducing lock overhead
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
	mFields := make(map[string]zap.Field, len(m.fields))
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

// GetFields retrieves all log fields efficiently
func (l *LogMetric) GetFields() []zap.Field {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// Pre-allocate slice to avoid repeated resizing
	fields := make([]zap.Field, 0, len(l.fields))
	for _, v := range l.fields {
		fields = append(fields, v)
	}
	return fields
}

// GetAttributes retrieves all OpenTelemetry attributes efficiently
func (l *LogMetric) GetAttributes() []attribute.KeyValue {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// Pre-allocate slice to avoid repeated resizing
	attrs := make([]attribute.KeyValue, 0, len(l.attributes))
	for _, v := range l.attributes {
		attrs = append(attrs, v)
	}
	return attrs
}
