package relayproxy

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// ---------- Stubs to satisfy your handler dependencies ----------

// If your real payload type is different, adjust this to match.
type testPayloadInfo struct {
	Resp []byte
}

//type MockService struct {
//	logger                    *zap.Logger
//	RegisterValidatorFunc     func(ctx context.Context, outgoingctx context.Context, in *RegistrationParams) (any, error)
//	GetHeaderFunc             func(ctx context.Context, in *HeaderRequestParams) (json.RawMessage, *common.OnHeaderDeliveredParams, error)
//	GetPayloadFunc            func(ctx context.Context, in *PayloadRequestParams) (*common.VersionedPayloadInfo, error)
//	GetPayloadV2Func          func(ctx context.Context, in *PayloadRequestParams) *ErrorResp
//	GetAccountsFunc           func(ctx context.Context) map[string]interface{}
//	SetAccountsFunc           func(ctx context.Context)
//	SendAccountFunc           func(accountID, validatorID string)
//	GetDelaySettingsFunc      func(ctx context.Context) map[string]DelaySettings
//	SetDelayForValidatorFunc  func(id string, delay, maxDelay int64)
//	SetDelayForValidatorsFunc func(settings map[string]DelaySettings)
//	DelayGetHeaderFunc        func(ctx context.Context, params DelayGetHeaderParams) (DelayGetHeaderResponse, error)
//}
//
//func (m *MockService) GetPayloadV2(ctx context.Context, log *zerolog.Logger, in *PayloadRequestParams) *ErrorResp {
//	if m.GetPayloadV2Func != nil {
//		return m.GetPayloadV2Func(ctx, in)
//	}
//	return nil
//}
//
//func (m *MockService) GetAccounts(ctx context.Context) map[string]any {
//	if m.GetAccountsFunc != nil {
//		return m.GetAccountsFunc(ctx)
//	}
//	return nil
//}
//
//func (m *MockService) SetAccounts(ctx context.Context) {
//	if m.SetAccountsFunc != nil {
//		m.SetAccountsFunc(ctx)
//		return
//	}
//}
//
//func (m *MockService) SendAccount(accountID, validatorID string) {
//	if m.SendAccountFunc != nil {
//		m.SendAccountFunc(accountID, validatorID)
//		return
//	}
//}
//func (m *MockService) GetDelaySettings(ctx context.Context) map[string]DelaySettings {
//	if m.GetDelaySettingsFunc != nil {
//		return m.GetDelaySettingsFunc(ctx)
//	}
//	return map[string]DelaySettings{}
//}
//
//func (m *MockService) SetDelayForValidator(id string, delay, maxDelay int64) {
//	if m.SetDelayForValidatorFunc != nil {
//		m.SetDelayForValidatorFunc(id, delay, maxDelay)
//		return
//	}
//}
//
//func (m *MockService) SetDelayForValidators(settings map[string]DelaySettings) {
//	if m.SetDelayForValidatorsFunc != nil {
//		m.SetDelayForValidatorsFunc(settings)
//		return
//	}
//}
//
//func (m *MockService) DelayGetHeader(ctx context.Context, in DelayGetHeaderParams) (DelayGetHeaderResponse, error) {
//	if m.DelayGetHeaderFunc != nil {
//		return m.DelayGetHeaderFunc(ctx, DelayGetHeaderParams{
//			ReceivedAt:          in.ReceivedAt,
//			Slot:                in.Slot,
//			AccountID:           in.AccountID,
//			Cluster:             in.Cluster,
//			UserAgent:           in.UserAgent,
//			ClientIP:            in.ClientIP,
//			SlotWithParentHash:  in.SlotWithParentHash,
//			BoostSendTimeUnixMS: in.BoostSendTimeUnixMS,
//			Latency:             in.Latency,
//		})
//	}
//	return DelayGetHeaderResponse{}, nil
//}
//func (m *MockService) GetSlotDuty(_ uint64) (*common.MiniValidatorLatency, error) {
//	return nil, nil
//}
//
//var _ IService = (*MockService)(nil)
//
//func (m *MockService) RegisterValidator(ctx context.Context, log *zerolog.Logger, outgoingCtx context.Context, in *RegistrationParams) (any, error) {
//	if m.RegisterValidatorFunc != nil {
//		return m.RegisterValidatorFunc(ctx, outgoingCtx, in)
//	}
//	return nil, nil
//}
//func (m *MockService) GetHeader(parentSpan trace.Span, ctx context.Context, log *zerolog.Logger, in *HeaderRequestParams) (json.RawMessage, *common.OnHeaderDeliveredParams, error) {
//	if m.GetHeaderFunc != nil {
//		return m.GetHeaderFunc(ctx, in)
//	}
//	return nil, nil, nil
//}
//
//func (m *MockService) GetPayload(ctx context.Context, log *zerolog.Logger, in *PayloadRequestParams) (*common.VersionedPayloadInfo, error) {
//	if m.GetPayloadFunc != nil {
//		return m.GetPayloadFunc(ctx, in)
//	}
//	return nil, nil
//}

// Match your production pool shape ([]byte).
func newBytePool(sz int) (p sync.Pool) {
	p = sync.Pool{New: func() any { return make([]byte, sz) }}
	return
}

// ----------------------------- The actual test -----------------------------

func TestHandleGetPayload_SpansAreEmitted(t *testing.T) {
	// 1) In-memory span recorder
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(rec),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()
	otel.SetTracerProvider(tp)

	// 2) Build server (nil-guard performanceStats in your handler defer recommended)
	s := &Server{
		tracer:             otel.Tracer("relayproxy/test"),
		logger:             zerolog.Nop(),
		svc:                &MockService{},
		performanceStats:   nil,
		getPayloadBodyPool: newBytePool(64 << 10),
	}

	// 3) Create request with headers/context the handler expects
	body := []byte(`{"dummy":"value"}`)
	req := httptest.NewRequest(http.MethodPost, "/eth/v1/builder/blinded_blocks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(MEVBoostStartTimeUnixMS, strconv.FormatInt(time.Now().Add(-150*time.Millisecond).UnixMilli(), 10))
	req.Header.Set(HeaderDateMilliseconds, strconv.FormatInt(time.Now().UnixMilli(), 10))
	req.Header.Set(HeaderKeySlotUID, "slot_1234_parent_0xabc")

	// Normally set by middleware; inject directly for test
	ctx := req.Context()
	ctx = context.WithValue(ctx, keyClientIP, "1.2.3.4")
	ctx = context.WithValue(ctx, keyParsedURL, req.URL)
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

	// 6) Inspect spans (Ended returns []sdktrace.ReadOnlySpan)
	spans := rec.Ended()
	if len(spans) == 0 {
		t.Fatalf("no spans recorded")
	}

	byName := map[string]sdktrace.ReadOnlySpan{}
	for _, sp := range spans {
		byName[sp.Name()] = sp
	}

	// Root span name should match your handler root span
	root, ok := byName["handleGetPayload"]
	if !ok {
		t.Fatalf("missing root span 'handleGetPayload'; got names=%v", spanNames(spans))
	}

	// Expected child spans you start explicitly
	expectedChildren := []string{
		"rproxy-handleGetPayload-readBodyBytes",
		"rproxy-handleGetPayload-mergeLogMetric",
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
	// after locating the root span:
	found := false
	for _, ev := range root.Events() {
		if ev.Name == "rproxy-handleGetPayload-svcGetPayload" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected event %q on root span", "rproxy-handleGetPayload-svcGetPayload")
	}

	// Check a few attributes exist on the root
	expectAttrKey(t, root, "getPayloadStartTimeUnixMS")
	expectAttrKey(t, root, "slotUID")
	expectAttrKVString(t, root, "method", http.MethodPost) // was "handleGetPayload"

}

// ----------------------------- Helpers -----------------------------

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
