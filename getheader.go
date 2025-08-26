package relayproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	relaygrpc "github.com/bloXroute-Labs/relay-grpc"
	"github.com/bloXroute-Labs/relayproxy/common"
	"github.com/bloXroute-Labs/relayproxy/fastjson"
	"github.com/bloXroute-Labs/relayproxy/fluentstats"
	"github.com/bloXroute-Labs/relayproxy/httpclient"
	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Service) GetHeader(ctx context.Context, log *zerolog.Logger, in *HeaderRequestParams) (json.RawMessage, *common.OnHeaderDeliveredParams, error) {
	id := uuid.NewString()
	parentSpan := trace.SpanFromContext(ctx)
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)
	ctx, span := s.tracer.Start(ctx, "getHeader-start")
	defer span.End()

	k := "slot-" + in.Slot + "-parentHash-" + in.ParentHash

	delayCtx, delayGetHeaderSpan := s.tracer.Start(ctx, "getHeader-delayGetHeader")

	delayGetHeaderResponse, err := s.DelayGetHeader(delayCtx, DelayGetHeaderParams{
		ReceivedAt:          in.ReceivedAt,
		Slot:                in.Slot,
		AccountID:           in.AccountID,
		Cluster:             in.Cluster,
		UserAgent:           in.UserAgent,
		ClientIP:            in.ClientIP,
		SlotWithParentHash:  k,
		BoostSendTimeUnixMS: in.GetHeaderStartTimeUnixMS,
		Latency:             in.Latency,
	})
	delayGetHeaderSpan.End(trace.WithTimestamp(time.Now()))

	_, preStoringHeaderSpan := s.tracer.Start(ctx, "getHeader-preStoringHeaderSpan")
	sleep := delayGetHeaderResponse.Sleep // TODO: refactor for the error handling
	maxSleep := delayGetHeaderResponse.MaxSleep
	slotStartTime := delayGetHeaderResponse.SlotStartTime
	latency := delayGetHeaderResponse.Latency

	startTime := time.Now().UTC()

	*log = log.With().
		Str("method", getHeader).
		Str("reqID", id).
		Str("key", k).
		Str("slot", in.Slot).
		Int64("slotStartTimeUnix", slotStartTime.Unix()).
		Str("slotStartTime", slotStartTime.UTC().String()).
		Int64("sleep", sleep).
		Int64("maxSleep", maxSleep).
		Logger()

	parentSpan.SetAttributes(
		attribute.String("method", getHeader),
		attribute.String("req", id),
		attribute.Int64("receivedAt", in.ReceivedAt.Unix()),
		attribute.String("key", k),
		attribute.String("slot", in.Slot),
		attribute.Int64("slotStartTimeUnix", slotStartTime.Unix()),
		attribute.String("slotStartTime", slotStartTime.UTC().String()),
		attribute.Int64("sleep", sleep),
		attribute.Int64("maxSleep", maxSleep),
	)

	log.Info().Msg("received getHeader")
	if err != nil {
		preStoringHeaderSpan.End(trace.WithTimestamp(time.Now()))
		return nil, nil, toErrorResp(http.StatusNoContent, err.Error())
	}

	_, parseUintHeaderSpan := s.tracer.Start(ctx, "getHeader-parseUint")
	_slot, err := fastParseUint(in.Slot)
	if err != nil {
		parseUintHeaderSpan.End(trace.WithTimestamp(time.Now()))
		preStoringHeaderSpan.End(trace.WithTimestamp(time.Now()))
		return nil, nil, toErrorResp(http.StatusNoContent, errInvalidSlot.Error())
	}

	parseUintHeaderSpan.End(trace.WithTimestamp(time.Now()))

	_, slotTimeMeasureSpan := s.tracer.Start(ctx, "getHeader-slotTimeMeasure")
	msIntoSlotIncludingDelay := time.Since(slotStartTime).Milliseconds()
	msIntoSlot := in.ReceivedAt.Sub(slotStartTime).Milliseconds() // without sleep and using received at
	*log = log.With().
		Int64("msIntoSlot", msIntoSlot).
		Int64("msIntoSlotIncludingDelay", msIntoSlotIncludingDelay).
		Logger()

	parentSpan.SetAttributes(
		attribute.Int64("msTntoSlot", msIntoSlot),
		attribute.Int64("msIntoSlotIncludingDelay", msIntoSlotIncludingDelay),
	)

	slotTimeMeasureSpan.End(trace.WithTimestamp(time.Now()))

	preStoringHeaderSpan.End(trace.WithTimestamp(time.Now()))

	_, storingHeaderSpan := s.tracer.Start(ctx, "getHeader-storingHeader")
	//TODO: send fluentd stats for StatusNoContent error cases

	if len(in.PubKey) != 98 {
		storingHeaderSpan.End(trace.WithTimestamp(time.Now()))
		return nil, nil, toErrorResp(http.StatusNoContent, errInvalidPubkey.Error())
	}

	if len(in.ParentHash) != 66 {
		storingHeaderSpan.End(trace.WithTimestamp(time.Now()))
		return nil, nil, toErrorResp(http.StatusNoContent, errInvalidHash.Error())
	}

	fetchGetHeaderStartTime := time.Now().UTC()
	keyForCachingBids := s.keyForCachingBids(_slot, in.ParentHash, in.PubKey)
	slotBestHeader, err := s.GetTopBuilderBid(keyForCachingBids)
	if err != nil && s.OnHeaderBidRetrieved != nil {
		var newBestHeader *common.Bid
		newBestHeaderCh := make(chan *common.Bid, 1)
		go func() {
			onHeaderBidRetrievedStart := time.Now()
			newBestHeader, replaceable, err := s.OnHeaderBidRetrieved(ctx, slotBestHeader, *log, parentSpan, _slot, in.ParentHash, slotBestHeader.BuilderPubkey, in.AccountID)
			log.Info().Bool("replaceable", replaceable).Dur("onHeaderBidRetrievedDuration", time.Since(onHeaderBidRetrievedStart)).Msg("OnHeaderBidRetrieved duration")
			if err != nil {
				log.Error().Err(err).Msg("OnHeaderBidRetrieved error")
				newBestHeaderCh <- nil
				return
			}
			newBestHeaderCh <- newBestHeader
		}()
		select {
		case replacementHeader := <-newBestHeaderCh:
			if replacementHeader != nil {
				newBestHeader = newBestHeader
			}
		case <-time.After(time.Duration(delayGetHeaderResponse.ReplacementDelayMs * int64(time.Millisecond))):
			log.Warn().Msg("OnHeaderBidRetrieved timeout")
			err = errors.New("OnHeaderBidRetrieved timeout")
			newBestHeader, err = s.GetTopBuilderBid(keyForCachingBids)
			if err != nil {
				log.Error().Err(err).Msg("GetTopBuilderBid after OnHeaderBidRetrieved timeout error")
			}
		}
		if newBestHeader != nil {
			log.Info().Msg("replacing best bid with new bid from OnHeaderBidRetrieved")
			// slotBestHeader = newBestHeader
		}
	}
	fetchGetHeaderDurationMS := time.Since(fetchGetHeaderStartTime).Milliseconds()
	headerReqDuration := time.Since(in.ReceivedAt)
	statsUserAgent := in.UserAgent
	if in.Cluster != "" {
		statsUserAgent += "/" + in.Cluster
	}

	if slotBestHeader == nil || err != nil {
		msg := fmt.Sprintf("header value is not present for the requested key %v", keyForCachingBids)
		span.AddEvent("Header value is not present", trace.WithAttributes(attribute.String("msg", msg)))
		go func() {
			headerStats := GetHeaderStatsRecord{
				RequestReceivedAt:        in.ReceivedAt,
				FetchGetHeaderStartTime:  fetchGetHeaderStartTime.String(),
				FetchGetHeaderDurationMS: fetchGetHeaderDurationMS,
				Duration:                 time.Since(startTime),
				MsIntoSlot:               msIntoSlot,
				ParentHash:               in.ParentHash,
				PubKey:                   in.PubKey,
				BlockHash:                "",
				ReqID:                    id,
				ClientIP:                 in.ClientIP,
				BlockValue:               "",
				Succeeded:                false,
				NodeID:                   s.nodeID,
				Slot:                     int64(_slot),
				AccountID:                in.AccountID,
				ValidatorID:              in.ValidatorID,
				Latency:                  latency,
				UserAgent:                statsUserAgent,
			}
			s.fluentD.LogToFluentD(fluentstats.Record{
				Type: TypeRelayProxyGetHeader,
				Data: headerStats,
			}, time.Now().UTC(), s.nodeID, StatsRelayProxyGetHeader)
		}()
		return nil, nil, toErrorResp(http.StatusNoContent, "Header value is not present")
	}
	if slotBestHeader.AccountID != "" {
		in.AccountID = slotBestHeader.AccountID
		if s.accountsLists.AccountIDToInfo[in.AccountID] != nil &&
			s.accountsLists.AccountIDToInfo[in.AccountID].UseAccountAsValidator {
			in.ValidatorID = in.AccountID
		}
	}
	uKey := fmt.Sprintf("slot_%v_bHash_%v_pHash_%v", in.Slot, slotBestHeader.BlockHash, in.ParentHash) // TODO:add pubkey
	blockValue := new(big.Int).SetBytes(slotBestHeader.Value)
	*log = log.With().
		Str("blockHash", slotBestHeader.BlockHash).
		Str("blockValue", blockValue.String()).
		Str("uniqueKey", uKey).
		Logger()
	parentSpan.SetAttributes(
		attribute.String("blockHash", slotBestHeader.BlockHash),
		attribute.String("blockValue", blockValue.String()),
		attribute.String("uniqueKey", uKey),
	)
	storingHeaderSpan.End(trace.WithTimestamp(time.Now()))

	go func() {
		slotStats := SlotStatsRecord{
			HeaderReqID:               id,
			HeaderReqReceivedAt:       in.ReceivedAt,
			HeaderReqDuration:         headerReqDuration, // this is not used
			HeaderReqDurationInMs:     headerReqDuration.Milliseconds(),
			HeaderDelayInMs:           sleep,
			HeaderMaxDelayInMs:        maxSleep,
			HeaderMsIntoSlot:          msIntoSlot,
			HeaderMsIntoSlotWithDelay: msIntoSlotIncludingDelay,
			HeaderSucceeded:           true,
			HeaderDeliveredBlockHash:  slotBestHeader.BlockHash,
			HeaderBlockValue:          weiToEther(blockValue),
			HeaderUserAgent:           statsUserAgent,
			HeaderStartTimeUnixMs:     in.GetHeaderStartTimeUnixMS,
			Slot:                      _slot,
			SlotStartTime:             slotStartTime,
			ParentHash:                in.ParentHash,
			PubKey:                    in.PubKey,
			ClientIP:                  in.ClientIP,
			NodeID:                    s.nodeID,
			AccountID:                 in.AccountID,
			ValidatorID:               in.ValidatorID,
			GetHeaderLatency:          latency,
			HeaderSlotUID:             in.SlotUID,
		}

		if v, ok := s.slotStats.Get(k); !ok {
			slotStatsSlice := make([]SlotStatsRecord, 0, 5)
			slotStatsSlice = append(slotStatsSlice, slotStats)
			s.slotStats.Set(k, slotStatsSlice, cache.DefaultExpiration)

			s.slotStatsEventCh <- slotStatsEvent{
				Slot:      int64(_slot),
				SlotKey:   k,
				UserAgent: in.UserAgent,
			}

		} else {
			slotStatsSlice := v.([]SlotStatsRecord)
			slotStatsSlice = append(slotStatsSlice, slotStats)
			s.slotStats.Set(k, slotStatsSlice, cache.DefaultExpiration)
		}

		headerStats := GetHeaderStatsRecord{
			RequestReceivedAt:        in.ReceivedAt,
			FetchGetHeaderStartTime:  fetchGetHeaderStartTime.String(),
			FetchGetHeaderDurationMS: fetchGetHeaderDurationMS,
			Duration:                 time.Since(in.ReceivedAt),
			MsIntoSlot:               msIntoSlot,
			ParentHash:               in.ParentHash,
			PubKey:                   in.PubKey,
			BlockHash:                slotBestHeader.BlockHash,
			ReqID:                    id,
			ClientIP:                 in.ClientIP,
			BlockValue:               weiToEther(blockValue),
			Succeeded:                true,
			NodeID:                   s.nodeID,
			Slot:                     int64(_slot),
			AccountID:                in.AccountID,
			ValidatorID:              in.ValidatorID,
			Latency:                  latency,
			UserAgent:                statsUserAgent,
			SlotUID:                  in.SlotUID,
			HeaderStartTimeUnixMs:    in.GetHeaderStartTimeUnixMS,
		}
		s.fluentD.LogToFluentD(fluentstats.Record{
			Type: TypeRelayProxyGetHeader,
			Data: headerStats,
		}, time.Now().UTC(), s.nodeID, StatsRelayProxyGetHeader)
	}()

	// send in payload to pre fetcher event
	s.preFetchPayloadChan <- preFetcherFields{
		clientIP:        in.ClientIP,
		authHeader:      in.AuthHeader,
		slot:            _slot,
		parentHash:      in.ParentHash,
		blockHash:       slotBestHeader.BlockHash,
		proposerPubKey:  in.PubKey,
		builderPubKey:   slotBestHeader.BuilderPubkey,
		blockValue:      weiToEther(blockValue),
		client:          slotBestHeader.Client,
		payloadFetchUrl: slotBestHeader.PayloadFetchUrl,
	}

	signedHeaderResponse, prevSigned, err := slotBestHeader.GetSignedHeaderResponse(s.secretKey, &s.publicKey, s.builderSigningDomain)
	if err != nil {
		log.Error().Err(err).Msg("failed to get signed header")
	}
	if prevSigned {
		log.Debug().Msg("previously signed header")
	} else {
		log.Debug().Msg("newly signed header")
	}

	onHeaderDeliveredParams := &common.OnHeaderDeliveredParams{
		SignedHeaderResponse:     signedHeaderResponse,
		Slot:                     _slot,
		GetHeaderRequestID:       in.SlotUID,
		ProposerPubkey:           in.PubKey,
		GetHeaderStartTimeUnixMS: in.GetHeaderStartTimeUnixMS,
		ExtraData:                slotBestHeader.BuilderExtraData,
	}

	return json.RawMessage(signedHeaderResponse), onHeaderDeliveredParams, nil
}

func (s *Service) StartPreFetcher(ctx context.Context) {
	for fields := range s.preFetchPayloadChan {
		go func(fields preFetcherFields) {
			_ctx, cancel := context.WithTimeout(ctx, preFetcherRequestTimeout)
			defer cancel()
			s.PreFetchGetPayload(_ctx, fields)
		}(fields)
	}
}

func (s *Service) PreFetchGetPayload(ctx context.Context, fields preFetcherFields) {
	var clientURL string
	startTime := time.Now().UTC()
	id := uuid.NewString()
	parentSpan := trace.SpanFromContext(ctx)
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", s.authKey)
	spanctx, span := s.tracer.Start(ctx, "preFetchGetPayload-start")
	uKey := fmt.Sprintf("slot_%v_bHash_%v_pHash_%v", fields.slot, fields.blockHash, fields.parentHash)
	defer func() {
		span.SetAttributes(
			attribute.String("method", preFetchPayload),
			attribute.String("clientIP", fields.clientIP),
			attribute.String("clientURL", clientURL),
			attribute.String("reqID", id),
			attribute.Int64("receivedAt", startTime.Unix()),
			attribute.String("traceID", parentSpan.SpanContext().TraceID().String()),
			attribute.String("authHeader", fields.authHeader),
			attribute.String("secretToken", s.secretToken),
			attribute.String("uKey", uKey),
			attribute.Int64("slot", int64(fields.slot)),
			attribute.String("blockHash", fields.blockHash),
		)
		span.End()
	}()

	if fields.client != nil {
		clientURL = fields.client.SafeClient.URL
	}

	logMetric := NewLogMetric(
		map[string]any{
			"method":      preFetchPayload,
			"receivedAt":  startTime,
			"clientIP":    fields.clientIP,
			"clientURL":   clientURL,
			"reqID":       id,
			"traceID":     parentSpan.SpanContext().TraceID().String(),
			"secretToken": s.secretToken,
			"authHeader":  fields.authHeader,
			"uKey":        uKey,
			"slot":        int64(fields.slot),
			"blockHash":   fields.blockHash,
		},
	)

	s.logger.Info().Fields(logMetric.GetFields()).Msg("received preFetchGetPayload")

	// If necessary, fetch the Optimistic V3 payload directly from the specified builder URL(s)
	if fields.payloadFetchUrl != "" {
		s.prefetchPayloadFromBuilder(ctx, spanctx, &fields, logMetric.Copy())
		return
	}

	s.prefetchPayloadGRPC(ctx, spanctx, &fields, logMetric.Copy(), span, id, startTime)
}

func (s *Service) prefetchPayloadGRPC(
	ctx context.Context,
	spanctx context.Context,
	fields *preFetcherFields,
	logMetric *LogMetric,
	span trace.Span,
	reqID string,
	startTime time.Time,
) {
	req := &relaygrpc.PreFetchGetPayloadRequest{
		ReqId:       reqID,
		Version:     s.version,
		SecretToken: s.secretToken,
		Slot:        fields.slot,
		ParentHash:  fields.parentHash,
		BlockHash:   fields.blockHash,
		Pubkey:      fields.proposerPubKey,
		ClientIp:    fields.clientIP,
		ReceivedAt:  timestamppb.New(startTime),
	}

	var (
		errChan            = make(chan *ErrorResp, len(s.clients)+2)
		respChan           = make(chan *relaygrpc.PreFetchGetPayloadResponse, len(s.clients)+2)
		payloadCacheKey    = common.GetKeyForCachingPayload(fields.slot, fields.parentHash, fields.blockHash, fields.proposerPubKey)
		wg                 sync.WaitGroup
		prefetchedRequests = 0
		succeeds           = false
	)

	// Goroutine to handle cache
	prefetchedRequests += 1
	if s.getPayloadResponseForProxySlot == nil {
		s.logger.Error().Fields(logMetric.GetFields()).Msg("PreFetchGetPayload :: cache is nil")
		errChan <- toErrorResp(http.StatusInternalServerError, "cache is nil")
	}

	if cachedValue, exists := s.getPayloadResponseForProxySlot.Get(payloadCacheKey); exists && cachedValue != nil {
		payloadResponseForProxy, ok := cachedValue.(*common.PayloadResponseForProxy)
		if !ok {
			s.logger.Error().Fields(logMetric.GetFields()).Msg("failed to cast cached value to GetPayloadResponseForProxy")
			errChan <- toErrorResp(http.StatusInternalServerError, "failed to cast cached value")
		}
		marshaledVal, err := payloadResponseForProxy.GetMarshalledResponse()
		if err != nil {
			s.logger.Error().Fields(logMetric.GetFields()).Msg("failed to marshal cached value to GetPayloadResponseForProxy")
			errChan <- toErrorResp(http.StatusInternalServerError, "failed to marshal cached value")
		}

		resp := &relaygrpc.PreFetchGetPayloadResponse{
			Code:                      uint32(codes.OK),
			Message:                   "Pre fetch getPayload succeeded",
			VersionedExecutionPayload: marshaledVal,
		}

		s.logger.Info().Fields(logMetric.GetFields()).Msg("PreFetchGetPayload-cache hit")

		respChan <- resp
		succeeds = true
	} else {
		errChan <- toErrorResp(http.StatusBadRequest, "local payload not found")
	}

	if !succeeds {
		clients := s.clients
		if fields.client != nil {
			clients = append(clients, fields.client)
		}

		// Goroutines to fetch payloads
		prefetchedRequests += len(clients)
		for _, client := range clients {
			wg.Add(1)
			go func(client *common.ParentClient) {
				defer wg.Done()
				prefetchLogger := s.logger.With().Fields(logMetric.GetFields()).Logger()
				s.prefetchPayload(ctx, spanctx, client.SafeClient, req, span, errChan, respChan, prefetchLogger)
			}(client)
		}
	}
	// Wait for all goroutines to finish
	defer func() {
		go func() {
			wg.Wait()
			close(respChan)
			close(errChan)
		}()
	}()

	// Process responses
	for i := 0; i < prefetchedRequests; i++ {
		select {
		case <-ctx.Done():
			s.logger.Warn().Fields(logMetric.GetFields()).Msg("PreFetchGetPayload :: Context canceled")
		case _err := <-errChan:
			s.logger.Error().Fields(logMetric.GetFields()).Interface("error", _err).Msg("PreFetchGetPayload :: Received error")
		case out := <-respChan:
			proxyCacheKey := common.GetKeyForCachingPayload(fields.slot, fields.parentHash, fields.blockHash, fields.proposerPubKey)

			payloadResponse := &common.PayloadResponseForProxy{
				MarshalledPayloadResponse: out.VersionedExecutionPayload,
				BlockValue:                fields.blockValue,
			}

			if err := s.getPayloadResponseForProxySlot.Add(proxyCacheKey, payloadResponse, cache.DefaultExpiration); err != nil {
				s.logger.Warn().Fields(logMetric.GetFields()).Err(err).Msg("PreFetchGetPayload :: respChan :: cache execution payload failed")
				return
			}

			s.logger.Info().Fields(logMetric.GetFields()).Msg("PreFetchGetPayload :: respChan :: preFetchGetPayload succeeded")
			return
		}
	}
}

func (s *Service) prefetchPayloadFromBuilder(ctx context.Context, spanCtx context.Context, fields *preFetcherFields, logMetric *LogMetric) {
	_, span := s.tracer.Start(ctx, "prefetchPayloadFromBuilder")
	var success atomic.Bool

	defer func() {
		span.SetAttributes(attribute.Bool("success", success.Load()))
		span.End()
	}()

	payloadUrlsData := common.SafeSplit(fields.payloadFetchUrl, common.PayloadUrlsTypeSeparator)

	if len(payloadUrlsData) != common.PayloadUrlsDataExpectedLength {
		logMetric.Fields(map[string]any{"payloadUrlsData": payloadUrlsData})
		s.logger.Error().Err(errors.New("invalid payload URL format")).Fields(logMetric.GetFields()).Msg("Failed to fetch Optimistic V3 payload from builder")
		return
	}

	payloadUrlType := payloadUrlsData[common.PayloadUrlTypeIndex]
	payloadUrlsCSV := payloadUrlsData[common.PayloadUrlsCSVIndex]
	payloadUrls := common.SafeSplit(payloadUrlsCSV, ",")

	logMetric.Fields(map[string]any{
		"payloadUrlsData": payloadUrlsData,
		"payloadUrls":     payloadUrls,
	})

	span.SetAttributes(
		attribute.String("payloadUrlType", payloadUrlType),
		attribute.StringSlice("payloadUrls", payloadUrls),
	)

	switch common.PayloadUrlType(payloadUrlType) {
	case common.PayloadUrlTypeHTTP:
		success.Store(s.clientPreFetchGetPayloadHTTP(ctx, logMetric, fields, payloadUrls))
		return
	case common.PayloadUrlTypeGRPC:
		// We only support HTTP requests for Optimistic V3 payloads from builders for now
		s.logger.Warn().Fields(logMetric.GetFields()).Msg("Ignoring fetch Optimistic V3 payload request with 'grpc' URL type")
		return
	default:
		s.logger.Error().Err(errors.New("invalid payload URL type")).Fields(logMetric.GetFields()).Msg("Failed to fetch Optimistic V3 payload from builder")
		return
	}
}

func (s *Service) clientPreFetchGetPayloadHTTP(
	ctx context.Context,
	logMetric *LogMetric,
	fields *preFetcherFields,
	payloadUrls []string,
) bool {
	_, fetchSpan := s.tracer.Start(ctx, "clientPreFetchGetPayloadHTTP")
	defer func() {
		fetchSpan.SetAttributes(
			attribute.Int64("slot", int64(fields.slot)),
			attribute.String("blockHash", fields.blockHash),
			attribute.String("parentHash", fields.parentHash),
			attribute.String("proposerPubkey", fields.proposerPubKey),
			attribute.String("builderPubkey", fields.builderPubKey),
		)
		fetchSpan.End()
	}()

	payload, err := s.prepareGetPayloadV3Request(fields.blockHash)
	if err != nil {
		s.logger.Error().Err(err).Fields(logMetric.GetFields()).Msg("failed to prepare HTTP get_payload_v3 request")
		return false
	}

	responseChan := make(chan *common.VersionedSubmitBlockRequest, len(payloadUrls))

	// Send request to all builders
	for _, payloadUrl := range payloadUrls {
		url := payloadUrl + common.PathGetPayloadV3

		go func() {
			result := new(common.VersionedSubmitBlockRequest)
			code, durationMS, err := httpclient.FetchSSZ(http.MethodPost, url, payload, result, nil, true)

			// TODO: should we try with JSON if ssz fails?
			if err != nil {
				s.logger.Error().
					Fields(logMetric.GetFields()).
					Err(err).Str("url", url).
					Int("code", code).
					Int64("durationMS", durationMS).
					Msg("failed to prefetch payload with HTTP")
				return
			}

			// Send to response channel
			responseChan <- result
		}()
	}

	// Process first positive response from builder (or timeout)
	return s.processGetPayloadV3Responses(ctx, responseChan, logMetric, fields)
}

func (s *Service) prepareGetPayloadV3Request(blockHash string) (*common.SignedGetPayloadV3, error) {
	getPayloadV3 := &common.GetPayloadV3{
		BlockHash:      phase0.Hash32(gethcommon.HexToHash(blockHash)),
		RequestTs:      uint64(time.Now().UnixMilli()),
		RelayPublicKey: s.publicKey,
	}

	signature, err := ssz.SignMessage(getPayloadV3, s.builderSigningDomain, s.secretKey)
	if err != nil {
		return nil, err
	}

	return &common.SignedGetPayloadV3{
		Message:   getPayloadV3,
		Signature: signature,
	}, nil
}

func (s *Service) processGetPayloadV3Responses(
	ctx context.Context,
	responseChan chan *common.VersionedSubmitBlockRequest,
	logMetric *LogMetric,
	fields *preFetcherFields,
) bool {
	for {
		select {
		case <-ctx.Done():
			s.logger.Error().Fields(logMetric.GetFields()).Msg("PreFetchGetPayloadV3 :: context cancelled")
			return false
		case response := <-responseChan:
			if response == nil {
				s.logger.Error().Fields(logMetric.GetFields()).Msg("PreFetchGetPayloadV3 :: failed to prefetch payload with HTTP, received nil payload from builder")
				continue
			}

			getPayloadResponseSpec, err := common.BuildGetPayloadResponse(response)
			if err != nil {
				s.logger.Fatal().Fields(logMetric.GetFields()).Err(err)
			}

			getPayloadResponse := common.VersionedSubmitBlindedBlockResponse{VersionedSubmitBlindedBlockResponse: *getPayloadResponseSpec}
			proxyCacheKey := common.GetKeyForCachingPayload(fields.slot, fields.parentHash, fields.blockHash, fields.proposerPubKey)

			payloadResponse := &common.PayloadResponseForProxy{
				PayloadResponse: getPayloadResponse,
				BlockValue:      fields.blockValue,
			}

			if err := s.getPayloadResponseForProxySlot.Add(proxyCacheKey, payloadResponse, cache.DefaultExpiration); err != nil {
				s.logger.Warn().Fields(logMetric.GetFields()).Err(err).Msg("PreFetchGetPayloadV3 :: cache execution payload already exists")
				return true
			}

			s.logger.Info().Fields(logMetric.GetFields()).Msg("PreFetchGetPayloadV3 :: preFetchGetPayload succeeded")
			return true
		case <-time.After(common.OptimisticV3FetchPayloadTimeout):
			s.logger.Error().Fields(logMetric.GetFields()).Msg("PreFetchGetPayloadV3 :: timeout waiting for prefetch payload HTTP response")
			return false
		}
	}
}

func (s *Service) prefetchPayloadToSignedBlindedBeaconBlock(ctx context.Context, payload []byte) (*common.VersionedSignedBlindedBeaconBlock, *ErrorResp) {
	_, readPayload := s.tracer.Start(ctx, "validateAndFetchPayload-readPayload")

	bodyString := string(payload)
	blockHashIndex := strings.LastIndex(bodyString, "\"block_hash\"")

	if blockHashIndex == -1 {
		return nil, toErrorResp(http.StatusBadRequest, "invalid input")
	}
	readPayload.End(trace.WithTimestamp(time.Now()))

	_, decodeJSONSpan := s.tracer.Start(ctx, "validateAndFetchPayload-decodeJSON")
	signedBlindedBeaconBlock, err := fastjson.UnmarshalToSignedBlindedBeaconBlock(bodyString)
	if err != nil {
		decodeJSONSpan.End(trace.WithTimestamp(time.Now()))
		return nil, toErrorResp(http.StatusBadRequest, err.Error())
	}
	decodeJSONSpan.End(trace.WithTimestamp(time.Now()))
	return signedBlindedBeaconBlock, nil
}
func (s *Service) prefetchPayload(
	ctx context.Context,
	spanctx context.Context,
	client *common.Client,
	req *relaygrpc.PreFetchGetPayloadRequest,
	span trace.Span,
	errChan chan *ErrorResp,
	respChan chan *relaygrpc.PreFetchGetPayloadResponse,
	logger zerolog.Logger,
) {
	clientCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	exitSignal := false
	wg := &sync.WaitGroup{}
	mu := &sync.Mutex{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5 && !exitSignal; i++ {
			childCtx, childSpan := s.tracer.Start(spanctx, "PreFetchGetPayload")
			_, reqSpan := s.tracer.Start(childCtx, "PreFetchGetPayload-request")
			childSpan.SetAttributes(
				attribute.String("url", client.URL),
				attribute.String("nodeID", client.NodeID),
			)
			out, err := client.PreFetchGetPayload(clientCtx, req)
			reqSpan.End()
			if exitSignal {
				childSpan.End()
				return
			}
			if err != nil {
				logger.Error().
					Err(err).
					Str("url", client.URL).
					Msg("prefetchPayload: error fetching payload")
				span.SetStatus(otelcodes.Error, err.Error())
				time.Sleep(100 * time.Millisecond)
				childSpan.End()
				continue
			}

			if out == nil {
				logger.Error().
					Str("url", client.URL).
					Msg("prefetchPayload: received nil payload from relay")
				span.SetStatus(otelcodes.Error, "nil payload")
				time.Sleep(100 * time.Millisecond)
				childSpan.End()
				continue
			}

			if out.Code != uint32(codes.OK) {
				logger.Error().
					Uint32("code", out.Code).
					Str("message", out.Message).
					Str("url", client.URL).
					Msg("prefetchPayload: invalid payload or failure response code")
				span.SetStatus(otelcodes.Error, out.Message)
				time.Sleep(100 * time.Millisecond)
				childSpan.End()
				continue
			}

			logger.Info().
				Str("url", client.URL).
				Msg("prefetchPayload: preFetchGetPayload succeeded")
			mu.Lock()
			if !exitSignal {
				exitSignal = true
				respChan <- out
				cancel()
			}
			mu.Unlock()
			childSpan.End()
			return
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5 && !exitSignal; i++ {
			reqCtx, childSpan := s.tracer.Start(spanctx, "PreFetchGetPayloadPlaceHTTPRequest")
			childSpan.SetAttributes(
				attribute.String("url", client.URL),
				attribute.String("nodeID", client.NodeID),
			)
			out, err := s.PreFetchGetPayloadPlaceHTTPRequest(clientCtx, reqCtx, req, client.URL, client.NodeID)
			if exitSignal {
				childSpan.End()
				return
			}
			if err != nil {
				logger.Error().
					Err(err).
					Str("url", client.URL).
					Msg("prefetchPayload: error fetching payload")
				span.SetStatus(otelcodes.Error, err.Error())
				time.Sleep(100 * time.Millisecond)
				childSpan.End()
				continue
			}

			if out == nil {
				logger.Error().
					Str("url", client.URL).
					Msg("prefetchPayload: received nil payload from relay")
				span.SetStatus(otelcodes.Error, "nil payload")
				time.Sleep(100 * time.Millisecond)
				childSpan.End()
				continue
			}

			if out.Code != uint32(codes.OK) {
				logger.Error().
					Uint32("code", out.Code).
					Str("message", out.Message).
					Str("url", client.URL).
					Msg("prefetchPayload: invalid payload or failure response code")
				span.SetStatus(otelcodes.Error, out.Message)
				time.Sleep(100 * time.Millisecond)
				childSpan.End()
				continue
			}

			logger.Info().
				Str("url", client.URL).
				Msg("prefetchPayload: preFetchGetPayload succeeded")
			mu.Lock()
			if !exitSignal {
				exitSignal = true
				respChan <- out
				cancel()
			}
			mu.Unlock()
			childSpan.End()
			return
		}
	}()

	wg.Wait()
	if exitSignal {
		return
	}

	errChan <- toErrorResp(http.StatusInternalServerError, "relay failed all attempts")
}

func (s *Service) PreFetchGetPayloadPlaceHTTPRequest(ctx context.Context, reqCtx context.Context, origReq *relaygrpc.PreFetchGetPayloadRequest, url string, nodeID string) (*relaygrpc.PreFetchGetPayloadResponse, error) {
	reqData := common.PreFetchGetPayloadRequestHTTP{
		Slot:       origReq.GetSlot(),
		ParentHash: origReq.GetParentHash(),
		BlockHash:  origReq.GetBlockHash(),
		Pubkey:     origReq.GetPubkey(),
		ClientIp:   origReq.GetClientIp(),
		ReceivedAt: origReq.GetReceivedAt(),
	}
	_, marshalSpan := s.tracer.Start(reqCtx, "PreFetchGetPayloadPlaceHTTPRequest-marshal")
	reqJSON, err := json.Marshal(reqData)
	marshalSpan.End()
	if err != nil {
		return nil, err
	}
	originalURL := url
	port := ":18555"

	if strings.Contains(url, ":") {
		host, portNumber, err := net.SplitHostPort(url)
		if err != nil {
			return nil, err
		}
		url = host
		if portNumber == "5015" {
			port = ":18550"
		}
	}

	finalURL := "http://" + url + port + common.PathPrefetchBlock
	s.logger.Info().Str("nodeID", nodeID).Str("finalURL", finalURL).Str("originalURL", originalURL).Msg("making prefetch request")
	req, err := http.NewRequest("GET", finalURL, bytes.NewReader(reqJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	_, requestSpan := s.tracer.Start(reqCtx, "PreFetchGetPayloadPlaceHTTPRequest-request")
	resp, err := client.Do(req)
	requestSpan.End()
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	_, unmarshalSpan := s.tracer.Start(reqCtx, "PreFetchGetPayloadPlaceHTTPRequest-unmarshal")
	var respData common.PreFetchGetPayloadResponseHTTP
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil && err != io.EOF {
		unmarshalSpan.End()
		return nil, err
	}
	unmarshalSpan.End()
	return &relaygrpc.PreFetchGetPayloadResponse{
		Code:                      respData.Code,
		Message:                   respData.Message,
		VersionedExecutionPayload: respData.VersionedExecutionPayload,
	}, nil
}
