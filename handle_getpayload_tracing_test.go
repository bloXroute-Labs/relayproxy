package relayproxy

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// ----------------------------- tiny helpers -----------------------------

// Pool must return []byte (not *[]byte) because handler does: Get().([]byte)
func newBytePool(sz int) (p sync.Pool) {
	p = sync.Pool{New: func() any { return make([]byte, sz) }}
	return
}

func spanNames(spans []sdktrace.ReadOnlySpan) []string {
	out := make([]string, 0, len(spans))
	for _, sp := range spans {
		out = append(out, sp.Name())
	}
	return out
}

func expectAttrKey(t *testing.T, sp sdktrace.ReadOnlySpan, key string) {
	t.Helper()
	for _, kv := range sp.Attributes() {
		if string(kv.Key) == key {
			return
		}
	}
	t.Fatalf("span %q missing attribute key %q", sp.Name(), key)
}

func expectAttrKVString(t *testing.T, sp sdktrace.ReadOnlySpan, key, want string) {
	t.Helper()
	for _, kv := range sp.Attributes() {
		if string(kv.Key) == key {
			if v, ok := kv.Value.AsInterface().(string); ok && v == want {
				return
			}
		}
	}
	t.Fatalf("span %q missing attribute %q=%q", sp.Name(), key, want)
}

// ----------------------------- The test -----------------------------

func TestHandleGetPayload_SpansAreEmitted(t *testing.T) {
	// 1) In-memory span recorder
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(rec),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()
	otel.SetTracerProvider(tp)

	// 2) Build server (performanceStats is nil-safe in your handler)
	s := &Server{
		tracer:             otel.Tracer("relayproxy/test"),
		logger:             zerolog.Nop(),
		svc:                &MockService{},
		performanceStats:   nil,
		getPayloadBodyPool: newBytePool(64 << 10),
	}

	// 3) Request with all headers your handler expects
	body := []byte(`{"dummy":"value"}`)
	req := httptest.NewRequest(http.MethodPost, "/eth/v1/builder/blinded_blocks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(MEVBoostStartTimeUnixMS, strconv.FormatInt(time.Now().Add(-150*time.Millisecond).UnixMilli(), 10))
	req.Header.Set(HeaderDateMilliseconds, strconv.FormatInt(time.Now().UnixMilli(), 10))
	req.Header.Set(HeaderKeySlotUID, "slot_1234_parent_0xabc")
	req.Header.Set("User-Agent", "relayproxy-test/1.0")

	// Middleware-injected context keys
	ctx := req.Context()
	ctx = context.WithValue(ctx, keyClientIP, "1.2.3.4")
	ctx = context.WithValue(ctx, keyParsedURL, &url.URL{Scheme: "http", Host: "example", Path: "/eth/v1/builder/blinded_blocks"})
	ctx = context.WithValue(ctx, keyAuthHeader, "bearer X")
	ctx = context.WithValue(ctx, keyOrgID, "val-123")
	ctx = context.WithValue(ctx, keyAccountID, "acct-xyz")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// 4) Invoke handler
	s.HandleGetPayload(w, req)

	// 5) Basic HTTP checks
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d, body=%s", w.Code, w.Body.String())
	}

	// 6) Inspect spans
	spans := rec.Ended()
	if len(spans) == 0 {
		t.Fatalf("no spans recorded")
	}

	byName := map[string]sdktrace.ReadOnlySpan{}
	for _, sp := range spans {
		byName[sp.Name()] = sp
	}

	// Root span name changed: GetSpanName("handleGetPayload","START") => "rproxy-handleGetPayload-START"
	rootName := "RProxy-handleGetPayload-START"
	root, ok := byName[rootName]
	if !ok {
		t.Fatalf("missing root span %q; got names=%v", rootName, spanNames(spans))
	}

	// Expected child spans (new micro-steps)
	expectedChildren := []string{
		"RProxy-handleGetPayload-preflight",
		"RProxy-handleGetPayload-extractHeaderValues",
		"RProxy-handleGetPayload-getBoostSendTimeAndLatency",
		"RProxy-handleGetPayload-ParseBuilderContentType",
		"RProxy-handleGetPayload-headerValuesLoop",
		"RProxy-handleGetPayload-readBodyBytes",
		"RProxy-handleGetPayload-svcGetPayload",
		"RProxy-handleGetPayload-mergeLogMetric",
	}

	for _, name := range expectedChildren {
		ch, ok := byName[name]
		if !ok {
			t.Fatalf("expected child span %q not found; got names=%v", name, spanNames(spans))
		}
		if ch.SpanContext().TraceID() != root.SpanContext().TraceID() {
			t.Fatalf("child %q has different traceID than root", name)
		}
		if ch.Parent().SpanID() != root.SpanContext().SpanID() {
			t.Fatalf("child %q does not have root as parent", name)
		}
	}

	// Root attributes
	expectAttrKey(t, root, "getPayloadStartTimeUnixMS")
	expectAttrKey(t, root, "slotUID")
	expectAttrKVString(t, root, "method", http.MethodPost)
}
