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

func (s *Service) RegisterValidator(ctx context.Context, log *zerolog.Logger, outgoingCtx context.Context, in *RegistrationParams) (any, error) {
	var (
		errChan  = make(chan *ErrorResp, len(s.clients))
		respChan = make(chan *relaygrpc.RegisterValidatorResponse, len(s.clients))
		_err     *ErrorResp
	)
	timer := time.NewTimer(regRequestTimeout)
	defer timer.Stop()

	parentSpan := trace.SpanFromContext(ctx)
	ctx = trace.ContextWithSpan(outgoingCtx, parentSpan)
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", in.AuthHeader)
	ctx, span := s.tracer.Start(ctx, "registerValidator-start")
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

	ctx, spanWait := s.tracer.Start(ctx, "RegisterValidator-waitForResponse")
	go func(_ctx context.Context, req *relaygrpc.RegisterValidatorRequest) {
		defer spanWait.End(trace.WithTimestamp(time.Now()))

		out, err := s.registerValidatorForClient(ctx, req)
		if err != nil {
			spanWait.SetAttributes(attribute.String("error", err.Error()))
			errChan <- err
			return
		}
		respChan <- out
	}(ctx, req)

	ctx, spanSuccess := s.tracer.Start(ctx, "RegisterValidator-waitForSuccessfulResponse")
	select {
	case <-ctx.Done():
		return nil, toErrorResp(http.StatusInternalServerError, ctx.Err().Error())
	case _err = <-errChan:
		// first error captured
	case <-respChan:
		return struct{}{}, nil
	case <-timer.C:
		log.Warn().Dur("timeout", regRequestTimeout).Msg("timer hit: relay request timeout")
		return struct{}{}, nil
	}
	spanSuccess.End(trace.WithTimestamp(time.Now()))

	if _err != nil {
		if _err.Code == http.StatusRequestTimeout {
			log.Info().Msg("relay request timeout")
			return struct{}{}, nil
		}
	}

	return nil, _err
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
