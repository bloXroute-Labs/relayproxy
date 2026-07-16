package relayproxy

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	relaygrpc "github.com/bloXroute-Labs/relay-grpc"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Registration forwarding is asynchronous: RegisterValidator enqueues, and a
// dispatcher forwards each registration in its own goroutine with its own
// deadline, gated by an in-flight byte budget rather than a fixed worker count.
// Epoch boundaries deliver thousands of ~200KB batches within seconds, so drain
// concurrency must scale with the burst (a fixed 16-worker pool caused ~250
// drop-oldest evictions per epoch); the relays have always absorbed this
// concurrency — the byte budget only caps how much memory in-flight requests can
// pin when relays stall (MEV-1984/MEV-1985). The queue is bounded by task count
// and total payload bytes; when it overflows, the oldest queued registrations
// are shed (drop-oldest) so clients always receive success — validators re-send
// every epoch, and a saturated queue means the registration relays are failing,
// where delivery would fail under any shedding policy.
const (
	// maxRegistrationPayloadBytes is anti-abuse only and must stay far above any
	// legitimate batch: every mainnet validator (~880k) registering in a single
	// request is ~160MB SSZ / ~440MB JSON at ~180/~500 bytes per registration.
	maxRegistrationPayloadBytes = 512 << 20
	regQueueMaxTasks            = 4096 // max queued registrations
	// regQueueMaxBytes must be >= maxRegistrationPayloadBytes so a max-size
	// request can always enqueue into an empty queue; typical epoch-wide
	// registration volume observed through one proxy is only tens of MB.
	regQueueMaxBytes = 768 << 20
	// regMaxInFlightBytes caps the total payload bytes being forwarded
	// concurrently — at the observed ~200KB per batch this allows ~330 parallel
	// forwards, draining an epoch-boundary burst in seconds. Note gRPC amplifies
	// each in-flight payload ~7-9x in heap (marshal copy, transport and pooled
	// response buffers, measured 2026-07-16), so the real transient cost is
	// several times this budget; regMaxInFlightTasks additionally bounds
	// goroutine count when payloads are tiny.
	regMaxInFlightBytes     = 64 << 20
	regMaxInFlightTasks     = 4096
	regForwardMaxAttempts   = 3
	regForwardRetryBackoff  = time.Second
	regQueueMonitorInterval = 30 * time.Second
)

// registrationTask is one registration waiting to be forwarded to the relays.
type registrationTask struct {
	req      *relaygrpc.RegisterValidatorRequest
	md       metadata.MD // outgoing metadata captured from the handler (e.g. ssz content type)
	log      zerolog.Logger
	attempts int
}

func (s *Service) RegisterValidator(ctx context.Context, log *zerolog.Logger, outgoingCtx context.Context, in *RegistrationParams) (any, error) {
	parentSpan := trace.SpanFromContext(ctx)
	_, span := s.tracer.Start(ctx, "registerValidator-enqueue")
	defer span.End()

	id := uuid.NewString()

	*log = log.With().
		Str("method", "registerValidator").
		Str("clientIP", in.ClientIP).
		Str("reqID", id).
		Str("traceID", parentSpan.SpanContext().TraceID().String()).
		Str("in.ValidatorID", in.ValidatorID).
		Str("accountID", in.AccountID).
		Str("authHeader", in.AuthHeader).
		Bool("proposerMevProtect", in.ProposerMevProtect).
		Time("receivedAt", in.ReceivedAt).
		Logger()
	parentSpan.SetAttributes(
		attribute.String("method", "registerValidator"),
		attribute.String("clientIP", in.ClientIP),
		attribute.String("reqID", id),
		attribute.String("in.ValidatorID", in.ValidatorID),
		attribute.String("traceID", parentSpan.SpanContext().TraceID().String()),
		attribute.Int64("receivedAt", in.ReceivedAt.Unix()),
		attribute.String("authHeader", in.AuthHeader),
		attribute.Bool("proposerMevProtect", in.ProposerMevProtect),
	)

	req := &relaygrpc.RegisterValidatorRequest{
		ReqId:              id,
		Payload:            in.Payload,
		ClientIp:           in.ClientIP,
		Version:            s.version,
		ReceivedAt:         timestamppb.New(in.ReceivedAt),
		AuthHeader:         in.AuthHeader,
		SecretToken:        s.secretToken,
		ComplianceList:     in.ComplianceList,
		ProposerMevProtect: in.ProposerMevProtect,
		SkipOptimism:       in.SkipOptimism,
	}

	md, _ := metadata.FromOutgoingContext(outgoingCtx)
	task := &registrationTask{req: req, md: md, log: *log}

	s.ensureRegistrationWorkers()
	s.enqueueRegistration(task, span)
	return struct{}{}, nil
}

// enqueueRegistration adds a registration to the forwarding queue, evicting the
// oldest queued registrations to make room when the task or byte cap is hit
// (drop-oldest). Clients therefore always get a success response; shed
// registrations are logged and re-sent by validators on their next epoch cycle.
// A saturated queue only occurs when the registration relays are failing, in
// which case delivery would fail regardless of shedding policy.
func (s *Service) enqueueRegistration(task *registrationTask, span trace.Span) {
	payloadBytes := int64(len(task.req.Payload))
	s.registrationQueueBytes.Add(payloadBytes)

	// bounded so a pathological race with concurrent enqueuers cannot spin forever
	for range regQueueMaxTasks + 1 {
		if s.registrationQueueBytes.Load() <= regQueueMaxBytes {
			select {
			case s.registrationQueue <- task:
				return
			default:
			}
		}
		if !s.evictOldestRegistration(span) {
			break // nothing left to evict yet still no room: give up on the new task
		}
	}

	s.registrationQueueBytes.Add(-payloadBytes)
	span.SetStatus(otelcodes.Error, "registration dropped, could not make room in queue")
	task.log.Error().
		Int64("payloadBytes", payloadBytes).
		Int("queuedTasks", len(s.registrationQueue)).
		Int64("queuedBytes", s.registrationQueueBytes.Load()).
		Msg("Dropping registration, could not make room in full queue")
}

// evictOldestRegistration sheds the head of the queue (the oldest pending
// registration). Reports false when the queue is empty.
func (s *Service) evictOldestRegistration(span trace.Span) bool {
	select {
	case dropped := <-s.registrationQueue:
		s.registrationQueueBytes.Add(-int64(len(dropped.req.Payload)))
		span.AddEvent("evicted oldest queued registration")
		dropped.log.Error().
			Int("payloadBytes", len(dropped.req.Payload)).
			Int("queuedTasks", len(s.registrationQueue)).
			Int64("queuedBytes", s.registrationQueueBytes.Load()).
			Msg("Evicting oldest queued registration to admit a newer one")
		return true
	default:
		return false
	}
}

func (s *Service) ensureRegistrationWorkers() {
	s.registrationWorkersOnce.Do(func() {
		if s.registrationQueue == nil {
			s.registrationQueue = make(chan *registrationTask, regQueueMaxTasks)
		}
		s.regInFlightBytes = semaphore.NewWeighted(regMaxInFlightBytes)
		s.regInFlightSlots = make(chan struct{}, regMaxInFlightTasks)
		go s.registrationDispatcher()
		go s.monitorRegistrationQueue()
	})
}

// monitorRegistrationQueue periodically logs the registration queue backlog
// (quiet while the queue is empty) and the forwarding outcomes since the last
// tick — forwardedOK is the positive confirmation that registrations are
// reaching the relays (quiet when there was no registration activity at all).
func (s *Service) monitorRegistrationQueue() {
	ticker := time.NewTicker(regQueueMonitorInterval)
	defer ticker.Stop()
	for range ticker.C {
		queuedTasks := len(s.registrationQueue)
		queuedBytes := s.registrationQueueBytes.Load()
		if queuedTasks != 0 || queuedBytes != 0 {
			s.logger.Info().
				Int("queuedTasks", queuedTasks).
				Int("maxTasks", regQueueMaxTasks).
				Int64("queuedBytes", queuedBytes).
				Int64("maxBytes", regQueueMaxBytes).
				Msg("Registration queue backlog")
		}

		forwardedOK := s.regForwardedOK.Swap(0)
		failedAttempts := s.regForwardFailedAttempts.Swap(0)
		dropped := s.regForwardDropped.Swap(0)
		succeededAfterRetry := s.regSucceededAfterRetry.Swap(0)
		if forwardedOK != 0 || failedAttempts != 0 || dropped != 0 {
			s.logger.Info().
				Int64("forwardedOK", forwardedOK).
				Int64("failedAttempts", failedAttempts).
				Int64("dropped", dropped).
				Int64("succeededAfterRetry", succeededAfterRetry).
				Dur("interval", regQueueMonitorInterval).
				Msg("Registration forwarding stats")
		}
	}
}

// registrationDispatcher drains the queue, forwarding each registration in its
// own goroutine. Concurrency is limited by the in-flight byte budget and task
// slot cap; when both are exhausted (relays stalled with the budget's worth of
// requests outstanding) the dispatcher blocks, applying backpressure into the
// bounded queue, whose drop-oldest overflow is then the shedding mechanism.
func (s *Service) registrationDispatcher() {
	for task := range s.registrationQueue {
		payloadBytes := int64(len(task.req.Payload))
		// clamp: a payload above the whole budget (allowed up to
		// maxRegistrationPayloadBytes) must not block Acquire forever
		weight := min(payloadBytes, regMaxInFlightBytes)
		s.regInFlightSlots <- struct{}{}
		// weighted Acquire only fails on ctx cancellation; Background never cancels
		_ = s.regInFlightBytes.Acquire(context.Background(), weight)
		s.registrationQueueBytes.Add(-payloadBytes)

		go func(t *registrationTask, n int64) {
			defer func() {
				s.regInFlightBytes.Release(n)
				<-s.regInFlightSlots
			}()
			s.forwardRegistration(t)
		}(task, weight)
	}
}

// forwardRegistration sends one queued registration to the registration relays,
// retrying transient failures with backoff. Each attempt carries its own deadline
// so a stalled relay connection cannot pin the payload in transport buffers.
func (s *Service) forwardRegistration(task *registrationTask) {
	for {
		task.attempts++

		attemptCtx := context.Background()
		if task.md != nil {
			attemptCtx = metadata.NewOutgoingContext(attemptCtx, task.md)
		}
		attemptCtx = metadata.AppendToOutgoingContext(attemptCtx, "authorization", s.authKey)
		attemptCtx, cancel := context.WithTimeout(attemptCtx, regRequestTimeout)
		attemptCtx, span := s.tracer.Start(attemptCtx, "registerValidator-forward")
		span.SetAttributes(
			attribute.String("reqID", task.req.ReqId),
			attribute.Int("attempt", task.attempts),
		)

		_, errResp := s.registerValidatorForClient(attemptCtx, task.req)
		span.End()
		cancel()

		if errResp == nil {
			s.regForwardedOK.Add(1)
			if task.attempts > 1 {
				s.regSucceededAfterRetry.Add(1)
			}
			return
		}
		s.regForwardFailedAttempts.Add(1)

		if task.attempts >= regForwardMaxAttempts || !isRetryableRegistrationError(errResp) {
			s.regForwardDropped.Add(1)
			task.log.Error().Str("err", errResp.Error()).Int("attempts", task.attempts).Msg("Dropping validator registration")
			return
		}

		task.log.Warn().Str("err", errResp.Error()).Int("attempts", task.attempts).Msg("Retrying validator registration")
		time.Sleep(regForwardRetryBackoff)
	}
}

// isRetryableRegistrationError reports whether a forward attempt is worth
// retrying: relay rejections (4xx other than timeout) are permanent — e.g. an
// expired or malformed registration — while timeouts and 5xx are transient.
func isRetryableRegistrationError(errResp *ErrorResp) bool {
	return errResp.Code == http.StatusRequestTimeout || errResp.Code >= http.StatusInternalServerError
}

func (s *Service) registerValidatorForClient(_ctx context.Context, req *relaygrpc.RegisterValidatorRequest) (*relaygrpc.RegisterValidatorResponse, *ErrorResp) {
	_ctx, regSpan := s.tracer.Start(_ctx, "registerValidator-registerValidatorForClient")
	var (
		out *relaygrpc.RegisterValidatorResponse
		err error
	)

	for range s.registrationClients {
		req.NodeId = s.nodeID

		s.registrationRelayMutex.Lock()
		selectedRelay := s.registrationClients[s.currentRegistrationRelayIndex]
		s.currentRegistrationRelayIndex = (s.currentRegistrationRelayIndex + 1) % len(s.registrationClients)
		s.registrationRelayMutex.Unlock()

		out, err = selectedRelay.SafeClient.RegisterValidator(_ctx, req)
		url := selectedRelay.SafeClient.URL

		if err != nil || out == nil || out.Code != uint32(codes.OK) {
			if err != nil {
				if strings.Contains(err.Error(), "expired on") {
					break
				}
				s.logger.Warn().Str("url", url).Err(err).Msg("failed to register validator")
			}
			continue
		}

		regSpan.SetStatus(otelcodes.Ok, "relay returned success response code")
		regSpan.End()
		return out, nil
	}

	regSpan.SetStatus(otelcodes.Error, "relay registration failed")
	regSpan.End()

	if err != nil {
		if strings.Contains(err.Error(), errContextDeadlineString) {
			return nil, toErrorResp(http.StatusRequestTimeout, err.Error())
		}
		return nil, toErrorResp(http.StatusInternalServerError, err.Error())
	}

	if out == nil {
		return nil, toErrorResp(http.StatusInternalServerError, "empty response from relay")
	}

	if out.Code != uint32(codes.OK) {
		return nil, toErrorResp(http.StatusBadRequest, "relay returned failure response code "+strconv.FormatUint(uint64(out.Code), 10))
	}

	return nil, toErrorResp(http.StatusInternalServerError, "no relay client available")
}
