package relayproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	relaygrpc "github.com/bloXroute-Labs/relay-grpc"
	"github.com/bloXroute-Labs/relayproxy/common"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

// ---------- fakes & fixtures ----------

type fakeRelayClient struct {
	PreFetchResp *relaygrpc.PreFetchGetPayloadResponse
	PreFetchErr  error
}

func (f *fakeRelayClient) SubmitBlock(context.Context, *relaygrpc.SubmitBlockRequest, ...grpc.CallOption) (*relaygrpc.SubmitBlockResponse, error) {
	return nil, nil
}
func (f *fakeRelayClient) RegisterValidator(context.Context, *relaygrpc.RegisterValidatorRequest, ...grpc.CallOption) (*relaygrpc.RegisterValidatorResponse, error) {
	return nil, nil
}
func (f *fakeRelayClient) GetHeader(context.Context, *relaygrpc.GetHeaderRequest, ...grpc.CallOption) (*relaygrpc.GetHeaderResponse, error) {
	return nil, nil
}
func (f *fakeRelayClient) GetPayload(context.Context, *relaygrpc.GetPayloadRequest, ...grpc.CallOption) (*relaygrpc.GetPayloadResponse, error) {
	return nil, nil
}
func (f *fakeRelayClient) StreamHeader(context.Context, *relaygrpc.StreamHeaderRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[relaygrpc.StreamHeaderResponse], error) {
	return nil, nil
}
func (f *fakeRelayClient) StreamBlock(context.Context, *relaygrpc.StreamBlockRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[relaygrpc.StreamBlockResponse], error) {
	return nil, nil
}
func (f *fakeRelayClient) ForwardBlock(context.Context, *relaygrpc.StreamBlockResponse, ...grpc.CallOption) (*relaygrpc.SubmitBlockResponse, error) {
	return nil, nil
}
func (f *fakeRelayClient) GetValidatorRegistration(context.Context, *relaygrpc.GetValidatorRegistrationRequest, ...grpc.CallOption) (*relaygrpc.GetValidatorRegistrationResponse, error) {
	return nil, nil
}
func (f *fakeRelayClient) PreFetchGetPayload(ctx context.Context, in *relaygrpc.PreFetchGetPayloadRequest, opts ...grpc.CallOption) (*relaygrpc.PreFetchGetPayloadResponse, error) {
	return f.PreFetchResp, f.PreFetchErr
}
func (f *fakeRelayClient) StreamBuilder(context.Context, *relaygrpc.StreamBuilderRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[relaygrpc.StreamBuilderResponse], error) {
	return nil, nil
}
func (f *fakeRelayClient) StreamSlotInfo(context.Context, *relaygrpc.StreamSlotRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[relaygrpc.StreamSlotResponse], error) {
	return nil, nil
}
func (f *fakeRelayClient) Ping(context.Context, *relaygrpc.PingRequest, ...grpc.CallOption) (*relaygrpc.PingResponse, error) {
	return nil, nil
}
func (f *fakeRelayClient) SendHeaderDelivered(context.Context, *relaygrpc.HeaderDeliveredRequest, ...grpc.CallOption) (*relaygrpc.HeaderDeliveredResponse, error) {
	return nil, nil
}
func (f *fakeRelayClient) AdjustLatestBlockPayload(context.Context, *relaygrpc.AdjustLatestBlockPayloadRequest, ...grpc.CallOption) (*relaygrpc.AdjustLatestBlockPayloadResponse, error) {
	return nil, nil
}

type httpServerCfg struct {
	Port     string
	OK       bool
	Delay    time.Duration
	LastBody map[string]any
}

func startHTTPFixedPortServer(t *testing.T, cfg *httpServerCfg) (stop func()) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(common.PathPrefetchBlock, func(w http.ResponseWriter, r *http.Request) {
		if cfg.Delay > 0 {
			time.Sleep(cfg.Delay)
		}
		defer r.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		cfg.LastBody = body
		w.Header().Set("Content-Type", "application/json")
		if cfg.OK {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":                      uint32(codes.OK),
				"message":                   "ok",
				"versionedExecutionPayload": []byte{0x01, 0x02},
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":    uint32(13),
			"message": "fail",
		})
	})

	ln, err := net.Listen("tcp", "127.0.0.1"+cfg.Port)
	if err != nil {
		t.Fatalf("listen http %s: %v", cfg.Port, err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	return func() { _ = srv.Shutdown(context.Background()) }
}

func newTestService(t *testing.T, buf *bytes.Buffer) *Service {
	t.Helper()
	logger := zerolog.New(buf).Level(zerolog.DebugLevel).With().Timestamp().Logger()
	return &Service{
		tracer:                         trace.NewNoopTracerProvider().Tracer("test"),
		logger:                         logger,
		getPayloadResponseForProxySlot: cache.New(10*time.Minute, 20*time.Minute),
		version:                        "test",
		secretToken:                    "secret",
	}
}

func newFields() preFetcherFields {
	return preFetcherFields{
		clientIP:       "1.2.3.4",
		authHeader:     "bearer X",
		slot:           123,
		parentHash:     "0xparent",
		blockHash:      "0xblock",
		proposerPubKey: "0xpubkey",
		builderPubKey:  "0xbuilder",
		blockValue:     "0",
	}
}

func countLogs(buf *bytes.Buffer, needle string) int {
	data := buf.String()
	count := 0
	start := 0
	nb := []byte(needle)
	for {
		i := bytes.Index([]byte(data[start:]), nb)
		if i < 0 {
			break
		}
		count++
		start += i + len(nb)
	}
	return count
}

// ---------- tests ----------

func TestPrefetch_GRPCSuccess_HTTPFail_LogsOnce(t *testing.T) {
	// HTTP fails; gRPC succeeds. Since "first success wins", we DO NOT expect HTTP failure summary now.
	stop := startHTTPFixedPortServer(t, &httpServerCfg{Port: ":18555", OK: false})
	defer stop()

	var logBuf bytes.Buffer
	s := newTestService(t, &logBuf)

	rc := &fakeRelayClient{
		PreFetchResp: &relaygrpc.PreFetchGetPayloadResponse{
			Code:                      uint32(codes.OK),
			Message:                   "ok",
			VersionedExecutionPayload: []byte{0xaa},
		},
		PreFetchErr: nil,
	}

	pc := &common.ParentClient{
		SafeClient: &common.Client{
			URL:         "127.0.0.1:5015", // HTTP maps to :18550 (not running) → would fail, but we exit on gRPC success
			NodeID:      "node-a",
			RelayClient: rc,
		},
	}
	s.clients = []*common.ParentClient{pc}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	fields := newFields()
	logMetric := NewLogMetric(map[string]any{"testcase": "grpc_success_http_fail_no_summary"})
	success := new(bool)

	spanCtx, span := s.tracer.Start(ctx, "test")
	defer span.End()

	start := time.Now()
	s.prefetchPayloadGRPC(ctx, spanCtx, &fields, logMetric, span, "req-1", start, success)
	if !*success {
		t.Fatalf("expected success from gRPC path")
	}

	// Exactly one gRPC success log
	if got := countLogs(&logBuf, "prefetch gRPC: succeeded"); got != 1 {
		t.Fatalf("want 1 gRPC success log, got %d\nlogs:\n%s", got, logBuf.String())
	}
	// No HTTP success (we never reached it in time)
	if got := countLogs(&logBuf, "prefetch HTTP: succeeded"); got != 0 {
		t.Fatalf("want 0 HTTP success logs, got %d", got)
	}
	// No HTTP failure summary in early-exit-on-success policy
	if got := countLogs(&logBuf, "prefetch HTTP: all attempts failed"); got != 0 {
		t.Fatalf("want 0 HTTP failure summaries, got %d", got)
	}
}

func TestPrefetch_GRPFFail_HTTPSuccess_LogsOnce(t *testing.T) {
	// gRPC fails; HTTP succeeds. Since first success wins, DO NOT expect gRPC failure summary.
	stop := startHTTPFixedPortServer(t, &httpServerCfg{Port: ":18555", OK: true})
	defer stop()

	var logBuf bytes.Buffer
	s := newTestService(t, &logBuf)

	rc := &fakeRelayClient{
		PreFetchResp: nil,
		PreFetchErr:  context.DeadlineExceeded,
	}

	pc := &common.ParentClient{
		SafeClient: &common.Client{
			URL:         "127.0.0.1", // HTTP maps to :18555 and will succeed
			NodeID:      "node-b",
			RelayClient: rc,
		},
	}
	s.clients = []*common.ParentClient{pc}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	fields := newFields()
	logMetric := NewLogMetric(map[string]any{"testcase": "grpc_fail_http_success_no_summary"})
	success := new(bool)

	spanCtx, span := s.tracer.Start(ctx, "test")
	defer span.End()

	start := time.Now()
	s.prefetchPayloadGRPC(ctx, spanCtx, &fields, logMetric, span, "req-2", start, success)
	if !*success {
		t.Fatalf("expected success from HTTP path")
	}

	// Exactly one HTTP success log
	if got := countLogs(&logBuf, "prefetch HTTP: succeeded"); got != 1 {
		t.Fatalf("want 1 HTTP success log, got %d\nlogs:\n%s", got, logBuf.String())
	}
	// No gRPC failure summary due to early exit
	if got := countLogs(&logBuf, "prefetch gRPC: all attempts failed"); got != 0 {
		t.Fatalf("want 0 gRPC failure summaries, got %d", got)
	}
	// No gRPC success either
	if got := countLogs(&logBuf, "prefetch gRPC: succeeded"); got != 0 {
		t.Fatalf("want 0 gRPC success logs, got %d", got)
	}
}

func TestPrefetch_BothFail_LogsOnceEachFailure(t *testing.T) {
	// Both sides fail → expect both failure summaries.
	stop := startHTTPFixedPortServer(t, &httpServerCfg{Port: ":18555", OK: false})
	defer stop()

	var logBuf bytes.Buffer
	s := newTestService(t, &logBuf)

	rc := &fakeRelayClient{
		PreFetchResp: nil,
		PreFetchErr:  context.DeadlineExceeded,
	}

	pc := &common.ParentClient{
		SafeClient: &common.Client{
			URL:         "127.0.0.1", // :18555 (failing)
			NodeID:      "node-c",
			RelayClient: rc,
		},
	}
	s.clients = []*common.ParentClient{pc}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	fields := newFields()
	logMetric := NewLogMetric(map[string]any{"testcase": "both_fail"})
	success := new(bool)

	spanCtx, span := s.tracer.Start(ctx, "test")
	defer span.End()

	start := time.Now()
	s.prefetchPayloadGRPC(ctx, spanCtx, &fields, logMetric, span, "req-3", start, success)
	if *success {
		t.Fatalf("expected overall failure")
	}

	if got := countLogs(&logBuf, "prefetch gRPC: all attempts failed"); got != 1 {
		t.Fatalf("want 1 gRPC failure summary, got %d\nlogs:\n%s", got, logBuf.String())
	}
	if got := countLogs(&logBuf, "prefetch HTTP: all attempts failed"); got != 1 {
		t.Fatalf("want 1 HTTP failure summary, got %d", got)
	}
	if got := countLogs(&logBuf, "prefetch gRPC: succeeded"); got != 0 {
		t.Fatalf("want 0 gRPC success logs, got %d", got)
	}
	if got := countLogs(&logBuf, "prefetch HTTP: succeeded"); got != 0 {
		t.Fatalf("want 0 HTTP success logs, got %d", got)
	}
}

func TestPrefetch_BothSucceed_FirstWins_AtMostOnceEachSuccess(t *testing.T) {
	// Either protocol may win; no failure summaries in this scenario.
	stop := startHTTPFixedPortServer(t, &httpServerCfg{Port: ":18555", OK: true, Delay: 5 * time.Millisecond})
	defer stop()

	var logBuf bytes.Buffer
	s := newTestService(t, &logBuf)

	rc := &fakeRelayClient{
		PreFetchResp: &relaygrpc.PreFetchGetPayloadResponse{
			Code:                      uint32(codes.OK),
			Message:                   "ok",
			VersionedExecutionPayload: []byte{0xbb},
		},
		PreFetchErr: nil,
	}

	pc := &common.ParentClient{
		SafeClient: &common.Client{
			URL:         "127.0.0.1", // :18555 HTTP may also succeed
			NodeID:      "node-d",
			RelayClient: rc,
		},
	}
	s.clients = []*common.ParentClient{pc}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	fields := newFields()
	logMetric := NewLogMetric(map[string]any{"testcase": "both_succeed"})
	success := new(bool)

	spanCtx, span := s.tracer.Start(ctx, "test")
	defer span.End()

	start := time.Now()
	s.prefetchPayloadGRPC(ctx, spanCtx, &fields, logMetric, span, "req-4", start, success)
	if !*success {
		t.Fatalf("expected success")
	}

	grpcSucc := countLogs(&logBuf, "prefetch gRPC: succeeded")
	httpSucc := countLogs(&logBuf, "prefetch HTTP: succeeded")
	if grpcSucc > 1 || httpSucc > 1 {
		t.Fatalf("expected <=1 success log per protocol, got grpc=%d http=%d\nlogs:\n%s", grpcSucc, httpSucc, logBuf.String())
	}
	if got := countLogs(&logBuf, "prefetch gRPC: all attempts failed"); got != 0 {
		t.Fatalf("unexpected gRPC failure summaries (%d)", got)
	}
	if got := countLogs(&logBuf, "prefetch HTTP: all attempts failed"); got != 0 {
		t.Fatalf("unexpected HTTP failure summaries (%d)", got)
	}
}

func TestPrefetch_CacheHitShortCircuits_SingleInfoLog(t *testing.T) {
	var logBuf bytes.Buffer
	s := newTestService(t, &logBuf)

	key := common.GetKeyForCachingPayload(123, "0xparent", "0xblock", "0xpubkey")
	_ = s.getPayloadResponseForProxySlot.Add(key, &common.PayloadResponseForProxy{
		MarshalledPayloadResponse: []byte{0xcc},
		BlockValue:                "0",
	}, cache.DefaultExpiration)

	s.clients = nil // ensure cache-only path

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	fields := newFields()
	logMetric := NewLogMetric(map[string]any{"testcase": "cache_hit"})
	success := new(bool)

	spanCtx, span := s.tracer.Start(ctx, "test")
	defer span.End()

	start := time.Now()
	s.prefetchPayloadGRPC(ctx, spanCtx, &fields, logMetric, span, "req-5", start, success)
	if !*success {
		t.Fatalf("expected success from cache")
	}
	if got := countLogs(&logBuf, "prefetch: cache hit"); got != 1 {
		t.Fatalf("want single 'cache hit' info log, got %d\nlogs:\n%s", got, logBuf.String())
	}
	if got := countLogs(&logBuf, "all attempts failed"); got != 0 {
		t.Fatalf("unexpected failure summaries in cache-hit path")
	}
}
