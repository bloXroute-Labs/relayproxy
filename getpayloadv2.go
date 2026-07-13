package relayproxy

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	relaygrpc "github.com/bloXroute-Labs/relay-grpc"
	"github.com/bloXroute-Labs/relayproxy/common"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Service) GetPayloadV2(ctx context.Context, log *zerolog.Logger, in *PayloadRequestParams) error {
	startTime := time.Now().UTC()
	id := uuid.NewString()

	parentSpan := trace.SpanFromContext(ctx)
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", s.authKey)
	authKey := s.authKey
	if in.AuthHeader != "" {
		authKey = in.AuthHeader
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", authKey)

	*log = log.With().
		Time("getPayloadV2StartTime", startTime).
		Str("method", getPayloadV2).
		Time("receivedAt", in.ReceivedAt).
		Str("reqID", id).
		Bool("isAuthHeaderProvided", in.AuthHeader != "").
		Logger()
	log.Info().Msg("received getPayloadTrusted")
	ctx, span := s.tracer.Start(ctx, "getPayload-start")
	var (
		slotInt       int64
		blockHashStr  string
		parentHashStr string
		blockValueStr string
		uKey          string
		latency       int64
	)
	defer func() {
		_, logTimingSpan := s.tracer.Start(ctx, "getPayload-logTimingSpan")
		parentSpan.SetAttributes(
			attribute.String("method", getPayloadV2),
			attribute.String("reqID", id),
			attribute.Int64("receivedAt", in.ReceivedAt.Unix()),
			attribute.Int64("slot", slotInt),
			attribute.String("blockHash", blockHashStr),
			attribute.String("parentHash", parentHashStr),
			attribute.String("blockValue", blockValueStr),
			attribute.String("uniqueKey", uKey),
			attribute.Int64("latency", latency),
		)
		logTimingSpan.End()
		span.End()
	}()
	_, timeToRelayRequestSpan := s.tracer.Start(ctx, "getPayload-TimeToRelayRequest")

	if in.GetPayloadStartTimeUnixMS != "" {
		if getPayloadStartTime, err := strconv.ParseInt(in.GetPayloadStartTimeUnixMS, 10, 64); err == nil {
			latency = in.ReceivedAt.Sub(time.UnixMilli(getPayloadStartTime)).Milliseconds()
		} else {
			log.Warn().Err(err).Msg("failed to parse getPayloadStartTimeUnixMS")
		}
	}

	req := &relaygrpc.GetPayloadRequest{
		ReqId:       id,
		Payload:     in.Payload,
		ClientIp:    in.ClientIP,
		Version:     s.version,
		ReceivedAt:  timestamppb.New(in.ReceivedAt),
		SecretToken: s.secretToken,
	}
	timeToRelayRequestSpan.End()

	_, prefetchPayloadToSignedBlindedBeaconBlockSpan := s.tracer.Start(ctx, "getPayload-prefetchPayloadToSignedBlindedBeaconBlockSpan")
	blindedBeaconBlock, errRes := s.prefetchPayloadToSignedBlindedBeaconBlock(ctx, in.Payload)
	if errRes != nil {
		log.Error().Err(errRes).Msg("prefetchPayloadToSignedBlindedBeaconBlock failed")
		go s.sendPayloadStats(in.Payload, log, false, nil, startTime, time.Now(), 0, id, latency, *in, errRes.Error())
		return errRes
	}
	slot, err := blindedBeaconBlock.Slot()
	if err != nil {
		return toErrorResp(http.StatusBadRequest, "failed to get slot")
	}
	blockHash, err := blindedBeaconBlock.ExecutionBlockHash()
	if err != nil {
		return toErrorResp(http.StatusBadRequest, "failed to get block hash")
	}
	parentHash, err := blindedBeaconBlock.ExecutionParentHash()
	if err != nil {
		return toErrorResp(http.StatusBadRequest, "failed to get parent hash")
	}
	slotInt = int64(slot)
	blockHashStr = blockHash.String()
	parentHashStr = parentHash.String()
	uKey = fmt.Sprintf("slot_%v_bHash_%v_pHash_%v", slotInt, blockHashStr, parentHashStr)
	*log = log.With().
		Int64("slot", slotInt).
		Str("blockHash", blockHashStr).
		Str("parentHash", parentHashStr).
		Str("validatorID", in.ValidatorID).
		Str("uKey", uKey).
		Logger()
	prefetchPayloadToSignedBlindedBeaconBlockSpan.End()

	go func() {
		if s.OnPayloadRequested == nil {
			log.Warn().Msg("skipping OnPayloadRequested")
			return
		}
		var pubkeyStr string
		miniSlotDuty, err := s.IDataService.GetSlotDuty(uint64(slot))
		if err == nil && miniSlotDuty != nil && miniSlotDuty.Registration != nil && miniSlotDuty.Registration.Message != nil {
			pub := miniSlotDuty.Registration.Message.Pubkey
			pubkeyStr = pub.String()
		}
		proposerRequestStartTimeUnixMS, _ := strconv.ParseInt(in.GetPayloadStartTimeUnixMS, 10, 64)
		err = s.OnPayloadRequested(uint64(slot), blockHashStr, parentHashStr, pubkeyStr, in.ClientIP, in.ReceivedAt, &blindedBeaconBlock.VersionedSignedBlindedBeaconBlock, proposerRequestStartTimeUnixMS, in.ValidatorID)
		if err != nil {
			log.Error().Err(err).Msg("failed to call OnPayloadRequested")
		}
	}()

	payloadInfoChan := make(chan *common.VersionedPayloadInfo, 1)

	// validate and fetch payload from cache
	go func(ctx context.Context, l zerolog.Logger, parent trace.Span) {
		ctx, childSpan := s.tracer.Start(ctx, "validateAndFetchPayload")
		defer childSpan.End()

		start := time.Now()

		payloadInfo, err := s.validateAndFetchPayload(ctx, blindedBeaconBlock)
		if err == nil && payloadInfo != nil {
			select {
			case payloadInfoChan <- payloadInfo:
			default:
			}
			if err != nil {
				l.Warn().Err(err).Msg("validateAndFetchPayload-GetPayloadV2 returned payload with partial error")
			}
		} else {
			l.Warn().Err(err).Msg("validateAndFetchPayload-GetPayloadV2 returned no payload")
		}

		l.Info().
			Time("startTime", start).
			Time("currentTime", time.Now()).
			Dur("duration", time.Since(start)).
			Uint64("slot", uint64(slot)).
			Str("parentHash", parentHash.String()).
			Str("blockHash", blockHash.String()).
			Msg("Finished validateAndFetchPayload-GetPayloadV2 from local cache")
	}(ctx, *log, parentSpan)

	// Fetch payload from relays
	clientUrls := make([]string, 0, len(s.clients))
	clientNodeIDs := make([]string, 0, len(s.clients))

	for _, client := range s.clients {
		clientUrls = append(clientUrls, client.SafeClient.URL)
		clientNodeIDs = append(clientNodeIDs, client.SafeClient.NodeID)

		go func(c *common.ParentClient, parent trace.Span) {
			ctx, childSpan := s.tracer.Start(ctx, "getPayloadWithRetry")
			defer childSpan.End()

			start := time.Now()
			log.Info().
				Time("currentTime", start).
				Uint64("slot", uint64(slot)).
				Str("parentHash", parentHash.String()).
				Str("blockHash", blockHash.String()).
				Str("safeClientURL", c.SafeClient.URL).
				Str("safeClientNodeID", c.SafeClient.NodeID).
				Msg("Start getPayloadWithRetry-GetPayloadV2 from remote node")

			resp, err := s.getPayloadWithRetry(ctx, c.SafeClient, childSpan, req, maxGetPayloadRetry)
			if err != nil {
				log.Error().
					Err(err).
					Time("currentTime", start).
					Uint64("slot", uint64(slot)).
					Str("parentHash", parentHash.String()).
					Str("blockHash", blockHash.String()).
					Str("safeClientURL", c.SafeClient.URL).
					Str("safeClientNodeID", c.SafeClient.NodeID).
					Msg("Failed getPayloadWithRetry-GetPayloadV2")
			} else if resp != nil {
				select {
				case payloadInfoChan <- resp:
				default:
					log.Warn().Str("blockHash", blockHash.String()).Msg("Failed getPayloadWithRetry-GetPayload, payloadInfoChan is full")
				}
			}

			log.Info().
				Time("currentTime", start).
				Dur("duration", time.Since(start)).
				Str("safeClientURL", c.SafeClient.URL).
				Str("safeClientNodeID", c.SafeClient.NodeID).
				Msg("Finished getPayloadWithRetry-GetPayloadV2 from remote node")
		}(client, parentSpan)
	}

	select {
	case payloadInfo := <-payloadInfoChan:
		// async publish
		go func() {
			if s.BlockPublishFunc != nil {
				s.BlockPublishFunc(s.tracer, s.logger, payloadInfo, blindedBeaconBlock,
					s.blockPublishingGatewayClient, s.gatewayAuthKey)
			}
		}()

		// collect stats
		slotStartTime := GetSlotStartTime(s.beaconGenesisTime, int64(payloadInfo.Slot), s.secondsPerSlot)
		msIntoSlot := in.ReceivedAt.Sub(slotStartTime).Milliseconds()
		duration := time.Since(startTime)

		go s.sendPayloadStats(in.Payload, log, true, payloadInfo, startTime, slotStartTime, msIntoSlot, id, latency, *in, "")

		blockValueStr = payloadInfo.GetBlockValue()
		*log = log.With().
			Int64("latency", latency).
			Dur("duration", duration).
			Int64("slotStartTime", slotStartTime.UnixMilli()).
			Int64("msIntoSlot", msIntoSlot).
			Str("blockValue", blockValueStr).
			Logger()

		log.Info().Msg("Payload successfully fetched in GetPayloadV2")

		// return success response only
		return nil

	case <-time.After(getPayloadRequestCutoffMs * time.Millisecond):
	}

	// if timeout → failure
	log.Error().
		Strs("clientUrls", clientUrls).
		Strs("clientNodeIDs", clientNodeIDs).
		Msg("timeout waiting for payload response")

	go s.sendPayloadStats(in.Payload, log, false, nil, startTime, time.Now(), 0, id, latency, *in, "timeout waiting for payload response,no execution payload for this request")
	return &ErrorResp{http.StatusBadRequest, "no execution payload for this request"}
}
