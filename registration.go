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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Registration forwarding is asynchronous: RegisterValidator enqueues and a fixed
// worker pool forwards to the registration relays, each attempt with its own
// deadline. The queue is bounded by task count and total payload bytes, so a
// registration burst against slow relays pins a bounded amount of memory instead
// of accumulating unbounded gRPC send buffers (MEV-1984).
const (
	// maxRegistrationPayloadBytes is anti-abuse only and must stay far above any
	// legitimate batch: every mainnet validator (~880k) registering in a single
	// request is ~160MB SSZ / ~440MB JSON at ~180/~500 bytes per registration.
	maxRegistrationPayloadBytes = 512 << 20
	regQueueMaxTasks            = 4096 // max queued registrations
	// regQueueMaxBytes must be >= maxRegistrationPayloadBytes so a max-size
	// request can always enqueue into an empty queue; typical epoch-wide
	// registration volume observed through one proxy is only tens of MB.
	regQueueMaxBytes        = 768 << 20
	regQueueWorkers         = 16
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

	payloadBytes := int64(len(in.Payload))
	if s.registrationQueueBytes.Add(payloadBytes) > regQueueMaxBytes {
		s.registrationQueueBytes.Add(-payloadBytes)
		span.SetStatus(otelcodes.Error, "registration queue byte limit reached")
		log.Error().
			Int64("payloadBytes", payloadBytes).
			Int("queuedTasks", len(s.registrationQueue)).
			Int64("queuedBytes", s.registrationQueueBytes.Load()).
			Msg("Registration queue byte limit reached, rejecting registration with 503")
		return nil, toErrorResp(http.StatusServiceUnavailable, "registration queue is full")
	}

	select {
	case s.registrationQueue <- task:
		return struct{}{}, nil
	default:
		s.registrationQueueBytes.Add(-payloadBytes)
		span.SetStatus(otelcodes.Error, "registration queue task limit reached")
		log.Error().
			Int64("payloadBytes", payloadBytes).
			Int("queuedTasks", len(s.registrationQueue)).
			Int64("queuedBytes", s.registrationQueueBytes.Load()).
			Msg("Registration queue task limit reached, rejecting registration with 503")
		return nil, toErrorResp(http.StatusServiceUnavailable, "registration queue is full")
	}
}

func (s *Service) ensureRegistrationWorkers() {
	s.registrationWorkersOnce.Do(func() {
		if s.registrationQueue == nil {
			s.registrationQueue = make(chan *registrationTask, regQueueMaxTasks)
		}
		for range regQueueWorkers {
			go s.registrationWorker()
		}
		go s.monitorRegistrationQueue()
	})
}

// monitorRegistrationQueue periodically logs the registration queue backlog so
// its distance from the regQueueMaxTasks/regQueueMaxBytes limits can be
// monitored; quiet while the queue is empty.
func (s *Service) monitorRegistrationQueue() {
	ticker := time.NewTicker(regQueueMonitorInterval)
	defer ticker.Stop()
	for range ticker.C {
		queuedTasks := len(s.registrationQueue)
		queuedBytes := s.registrationQueueBytes.Load()
		if queuedTasks == 0 && queuedBytes == 0 {
			continue
		}
		s.logger.Info().
			Int("queuedTasks", queuedTasks).
			Int("maxTasks", regQueueMaxTasks).
			Int64("queuedBytes", queuedBytes).
			Int64("maxBytes", regQueueMaxBytes).
			Msg("Registration queue backlog")
	}
}

func (s *Service) registrationWorker() {
	for task := range s.registrationQueue {
		s.registrationQueueBytes.Add(-int64(len(task.req.Payload)))
		s.forwardRegistration(task)
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
			return
		}

		if task.attempts >= regForwardMaxAttempts || !isRetryableRegistrationError(errResp) {
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
