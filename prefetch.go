package relayproxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	relaygrpc "github.com/bloXroute-Labs/relay-grpc"
	"github.com/bloXroute-Labs/relay-grpc/optimisticv3"
	"github.com/bloXroute-Labs/relayproxy/common"
	"github.com/bloXroute-Labs/relayproxy/httpclient"
	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Service) StartPreFetcher(ctx context.Context) {
	for fields := range s.preFetchPayloadChan {
		go func(fields preFetcherFields) {
			prefetchCtx, cancel := context.WithTimeout(ctx, preFetcherRequestTimeout)
			defer cancel()
			s.PreFetchGetPayload(prefetchCtx, fields)
		}(fields)
	}
}

func (s *Service) PreFetchGetPayload(ctx context.Context, fields preFetcherFields) {
	startTime := time.Now().UTC()
	var (
		success bool
	)
	var msIntoSlotPrefetchStart int64
	if !fields.slotStartTime.IsZero() {
		msIntoSlotPrefetchStart = time.Since(fields.slotStartTime).Milliseconds()
	}
	prefetchID := uuid.NewString()
	// record prefetch start into flow cache
	go s.IDataService.GetFlowService().RecordPrefetchStart(fields.slot, fields.parentHash, fields.blockHash, fields.proposerPubKey, fields.blockValue, s.nodeID, PrefetchFlowEvent{
		PrefetchID:              prefetchID,
		GetHeaderReqID:          fields.getHeaderReqID,
		StartedAt:               startTime,
		MsIntoSlotPrefetchStart: msIntoSlotPrefetchStart,
	})

	spanCtx, span := s.tracer.Start(ctx, GetSpanName("prefetch", "START"))
	defer func() {
		totalMs := time.Since(startTime).Milliseconds()
		var msIntoSlotPrefetchEnd int64
		if !fields.slotStartTime.IsZero() {
			msIntoSlotPrefetchEnd = time.Since(fields.slotStartTime).Milliseconds()
		}

		span.SetAttributes(
			attribute.Int64("prefetch.total_ms", totalMs),
			attribute.Bool("prefetch.success", success),
			attribute.Int64("prefetch.slot", int64(fields.slot)),
			attribute.String("prefetch.blockHash", fields.blockHash),
			attribute.String("prefetch.parentHash", fields.parentHash),
			attribute.String("prefetch.proposerPubkey", fields.proposerPubKey),
			attribute.Int64("prefetch.msIntoSlot_start", msIntoSlotPrefetchStart),
			attribute.Int64("prefetch.msIntoSlot_end", msIntoSlotPrefetchEnd),
			attribute.Int64("prefetch.msIntoSlot_getHeader_including_delay", fields.msIntoSlotGetHeaderIncludingDelay),
			attribute.String("prefetch.getHeader_req_id", fields.getHeaderReqID),
			attribute.String("prefetch.id", prefetchID),
			attribute.String("prefetch.clientURL", fields.client.String()),
		)
		span.End()

		s.performancestats.SetEndpointStats(
			"PreFetchGetPayload-rproxy",
			uint64(time.Since(startTime).Microseconds()),
			success,
			100,
		)
	}()

	uKey := "slot_" + strconv.FormatUint(fields.slot, 10) + "_bHash_" + fields.blockHash + "_pHash_" + fields.parentHash
	prefetchLogger := s.logger.With().
		Str("method", preFetchPayload).
		Time("prefetchStartedAt", startTime).
		Str("clientIP", fields.clientIP).
		Str("clientURL", fields.client.String()).
		Str("prefetchID", prefetchID).
		Str("traceID", span.SpanContext().TraceID().String()).
		Str("uKey", uKey).
		Int64("slot", int64(fields.slot)). // or Uint64 if you prefer
		Str("parentHash", fields.parentHash).
		Str("blockHash", fields.blockHash).
		Int64("msIntoSlotStart", msIntoSlotPrefetchStart).
		Int64("msIntoSlotGetHeaderIncludingDelay", fields.msIntoSlotGetHeaderIncludingDelay).
		Str("getHeaderReqID", fields.getHeaderReqID).Logger()
	prefetchLogger.Info().Msg("received prefetchPayload")

	if fields.payloadFetchUrl != "" {
		subStart := time.Now()
		_, sub := s.tracer.Start(spanCtx, GetSpanName("prefetch", "builderHTTPorGRPC"))
		success = s.prefetchPayloadFromBuilder(ctx, spanCtx, &fields, prefetchLogger)
		sub.SetAttributes(
			attribute.Bool("success", success),
			attribute.Int64("duration_ms", time.Since(subStart).Milliseconds()),
		)
		sub.End()
		// TODO: NOTE: builder path does not currently call RecordPrefetchDone.
		// once v3 support implemented, wire it into processGetPayloadV3Responses.
		return
	}

	go s.prefetchCache(spanCtx, fields, prefetchLogger, prefetchID, fields.getHeaderReqID, startTime)
	go s.prefetchGRPC(ctx, spanCtx, s.clients, prefetchLogger, fields, prefetchID, startTime)
	//prefetchHTTP()

}
func (s *Service) prefetchGRPC(
	ctx context.Context,
	spanCtx context.Context,
	clients []*common.ParentClient,
	baseLogger zerolog.Logger,
	fields preFetcherFields,
	reqID string,
	prefetchStartTime time.Time,
) (result *prefetchResult, err error) {

	var (
		success         bool
		payloadSize     int
		errStr          string
		payloadCacheKey string
	)

	defer func() {
		durationMs := time.Since(prefetchStartTime).Milliseconds()

		success = err == nil && result != nil
		source := FlowSourcePrefetchGRPC
		url := ""
		nodeID := ""

		if success {
			if result != nil && result.resp != nil {
				payloadSize = len(result.resp.VersionedExecutionPayload)
			}
			source = result.source
			url = result.url
			nodeID = result.nodeID
		} else {
			if err != nil {
				errStr = err.Error()
			} else {
				errStr = "no_winner"
			}
		}

		go s.IDataService.GetFlowService().RecordPrefetchDone(
			fields.slot,
			fields.parentHash,
			fields.blockHash,
			fields.proposerPubKey,
			reqID,
			fields.getHeaderReqID,
			success,
			durationMs,
			source,
			url,
			nodeID,
			payloadSize,
			errStr,
		)
	}()

	if len(clients) == 0 {
		err = fmt.Errorf("no downstream clients")
		return nil, err
	}

	gctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	resultCh := make(chan *prefetchResult, 1)
	//errChan := make(chan *ErrorResp, len(s.clients))
	req := &relaygrpc.PreFetchGetPayloadRequest{
		ReqId:       reqID,
		Version:     s.version,
		SecretToken: s.secretToken,
		Slot:        fields.slot,
		ParentHash:  fields.parentHash,
		BlockHash:   fields.blockHash,
		Pubkey:      fields.proposerPubKey,
		ClientIp:    fields.clientIP,
		ReceivedAt:  timestamppb.New(prefetchStartTime),
	}

	for _, parent := range clients {
		client := parent.GetFastClient()
		url := parent.String()
		wg.Add(1)
		go func(client *common.Client, url string, req *relaygrpc.PreFetchGetPayloadRequest) {
			defer wg.Done()

			clientLogger := baseLogger.With().Str("downstream_url", url).Logger()

			res, pErr := s.prefetchGRPCSingle(gctx, spanCtx, client, req, clientLogger)
			if pErr != nil || res == nil {
				return
			}

			select {
			case resultCh <- res:
				cancel()
			default:
			}
		}(client, url, req)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	if res, ok := <-resultCh; ok && res != nil {
		result = res
		err = nil
		payloadCacheKey = common.GetKeyForCachingPayload(
			fields.slot,
			fields.parentHash,
			fields.blockHash,
			fields.proposerPubKey,
		)
		payloadResponse := &common.PayloadResponseForProxy{
			MarshalledPayloadResponse: res.resp.VersionedExecutionPayload,
			BlockValue:                fields.blockValue,
		}
		payloadSize = len(res.resp.VersionedExecutionPayload)
		_ = s.getPayloadResponseForProxySlot.Add(
			payloadCacheKey,
			payloadResponse,
			cache.DefaultExpiration,
		)

		return result, nil
	}

	err = fmt.Errorf("relay failed gRPC prefetch attempts")
	return nil, err
}

func (s *Service) prefetchGRPCSingle(
	ctx context.Context,
	spanCtx context.Context,
	client *common.Client,
	req *relaygrpc.PreFetchGetPayloadRequest,
	logger zerolog.Logger,
) (*prefetchResult, error) {
	clientCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	clientURL := ""
	clientNodeID := ""
	if client != nil {
		clientURL = client.URL
		clientNodeID = client.NodeID
	}

	reqStart := time.Now()
	_, childSpan := s.tracer.Start(spanCtx, GetSpanName("prefetch", "gRPC"))
	defer childSpan.End()

	childSpan.SetAttributes(
		attribute.String("url", clientURL),
		attribute.String("nodeID", clientNodeID),
	)

	out, err := client.PreFetchGetPayload(clientCtx, req)
	reqDurMs := time.Since(reqStart).Milliseconds()

	if err == nil && out != nil && out.Code == uint32(codes.OK) {
		logger.Info().
			Str("url", clientURL).
			Str("nodeID", clientNodeID).
			Int64("duration_ms", reqDurMs).
			Msg("prefetch gRPC: succeeded")

		childSpan.SetAttributes(
			attribute.Int64("request_duration_ms", reqDurMs),
			attribute.Int("payload_size_bytes", len(out.VersionedExecutionPayload)),
		)

		return &prefetchResult{
			resp:   out,
			source: FlowSourcePrefetchGRPC,
			url:    clientURL,
			nodeID: clientNodeID,
		}, nil
	}

	var msg string
	if err != nil {
		msg = err.Error()
	} else if out != nil {
		msg = fmt.Sprintf("non-OK code from relay: %d, message=%s", out.Code, out.Message)
	} else {
		msg = "nil response from relay"
	}

	logger.Info().
		Str("url", clientURL).
		Str("nodeID", clientNodeID).
		Int64("duration_ms", reqDurMs).
		Str("error", msg).
		Msg("prefetch gRPC: failed")

	childSpan.SetAttributes(
		attribute.Int64("request_duration_ms", reqDurMs),
		attribute.String("error", msg),
	)

	return nil, fmt.Errorf("%s", msg)
}

func (s *Service) prefetchCache(spanCtx context.Context, fields preFetcherFields, log zerolog.Logger, prefetchID, getHeaderReqID string, prefetchStartTime time.Time) bool {
	cacheStart := time.Now()
	var (
		success         bool
		payloadSize     int
		errStr          string
		payloadCacheKey string
	)
	// ---- Cache check span ----
	_, cacheSpan := s.tracer.Start(spanCtx, GetSpanName("prefetch", "cacheCheck"))
	defer func() {
		cacheSpan.SetAttributes(
			attribute.Int64("duration_ms", time.Since(cacheStart).Milliseconds()),
		)
		cacheSpan.End()
		log.Info().
			Str("payloadCacheKey", payloadCacheKey).
			Int("payload_size_bytes", payloadSize).
			Msg("PreFetchPayload :: prefetch succeeded (cache-fastpath)")
		go s.IDataService.GetFlowService().RecordPrefetchDone(
			fields.slot,
			fields.parentHash,
			fields.blockHash,
			fields.proposerPubKey,
			prefetchID,
			getHeaderReqID,
			success,
			time.Since(prefetchStartTime).Milliseconds(),
			FlowSourcePrefetchCache, // cache or builder, etc.
			s.nodeID,                // e.g. s.nodeID or builder URL
			"",                      // if you have one
			payloadSize,
			errStr,
		)
	}()

	payloadCacheKey = common.GetKeyForCachingPayload(
		fields.slot,
		fields.parentHash,
		fields.blockHash,
		fields.proposerPubKey,
	)

	if s.getPayloadResponseForProxySlot == nil {
		errStr = "nil_cache"
		cacheSpan.SetAttributes(attribute.String("result", errStr))
		log.Error().
			Msg("PreFetchPayload :: cache is nil")
		return false
	}

	cachedValue, exists := s.getPayloadResponseForProxySlot.Get(payloadCacheKey)
	if !exists || cachedValue == nil {
		errStr = "cache_miss"
		cacheSpan.SetAttributes(attribute.String("result", "miss"))
		log.Debug().
			Str("payloadCacheKey", payloadCacheKey).
			Msg("PreFetchPayload :: cache miss – local payload not found")
		return false
	}

	payloadResponseForProxy, ok := cachedValue.(*common.PayloadResponseForProxy)
	if !ok {
		errStr = "cast_error"
		cacheSpan.SetAttributes(attribute.String("result", "cast_error"))
		log.Error().
			Str("payloadCacheKey", payloadCacheKey).
			Msg("PreFetchPayload :: failed to cast cached value to *PayloadResponseForProxy")
		return false
	}

	marshaledVal, err := payloadResponseForProxy.GetMarshalledResponse()
	if err != nil {
		errStr = err.Error()
		cacheSpan.SetAttributes(attribute.String("result", "marshal_error"))
		log.Error().
			Err(err).
			Str("payloadCacheKey", payloadCacheKey).
			Msg("PreFetchPayload :: failed to marshal cached value")
		return false
	}

	payloadResponse := &common.PayloadResponseForProxy{
		MarshalledPayloadResponse: marshaledVal,
		BlockValue:                fields.blockValue,
	}

	// Allow "already exists"
	_ = s.getPayloadResponseForProxySlot.Add(
		payloadCacheKey,
		payloadResponse,
		cache.DefaultExpiration,
	)

	payloadSize = len(marshaledVal)

	cacheSpan.SetAttributes(
		attribute.String("result", "hit_fastpath"),
		attribute.Int("payload_size_bytes", payloadSize),
	)

	success = true
	return true
}

func (s *Service) prefetchPayloadFromBuilder(
	ctx context.Context,
	spanCtx context.Context,
	fields *preFetcherFields,
	log zerolog.Logger,
) bool {
	_, span := s.tracer.Start(spanCtx, GetSpanName("prefetch", "fromBuilder"))
	var success atomic.Bool
	defer func() {
		span.SetAttributes(attribute.Bool("success", success.Load()))
		span.End()
	}()

	payloadUrlsData := common.SafeSplit(fields.payloadFetchUrl, optimisticv3.PayloadUrlsTypeSeparator)
	if len(payloadUrlsData) != optimisticv3.PayloadUrlsDataExpectedLength {
		err := errors.New("invalid payload URL format")

		log.Debug().
			Strs("payloadUrlsData", payloadUrlsData).
			Err(err).
			Msg("Failed to fetch Optimistic V3 payload from builder")

		return success.Load()
	}

	payloadUrlType := payloadUrlsData[optimisticv3.PayloadUrlTypeIndex]
	payloadUrlsCSV := payloadUrlsData[optimisticv3.PayloadUrlsCSVIndex]
	payloadUrls := common.SafeSplit(payloadUrlsCSV, ",")

	span.SetAttributes(
		attribute.String("payloadUrlType", payloadUrlType),
		attribute.StringSlice("payloadUrls", payloadUrls),
	)

	// enrich logger with URL info for all subsequent logs
	log = log.With().
		Str("payloadUrlType", payloadUrlType).
		Strs("payloadUrls", payloadUrls).
		Logger()

	switch optimisticv3.PayloadUrlType(payloadUrlType) {
	case optimisticv3.PayloadUrlTypeHTTP:
		success.Store(s.builderPreFetchGetPayloadHTTP(ctx, log, fields, payloadUrls))
		return success.Load()

	case optimisticv3.PayloadUrlTypeGRPC:
		log.Debug().
			Msg("Ignoring fetch Optimistic V3 payload request with 'grpc' URL type")
		return success.Load()

	default:
		log.Debug().
			Err(errors.New("invalid payload URL type")).
			Msg("Failed to fetch Optimistic V3 payload from builder")
		return success.Load()
	}
}

func (s *Service) builderPreFetchGetPayloadHTTP(
	ctx context.Context,
	log zerolog.Logger,
	fields *preFetcherFields,
	payloadUrls []string,
) bool {
	_, fetchSpan := s.tracer.Start(ctx, GetSpanName("prefetch", "builderHttpFanout"))
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
		log.Debug().
			Err(err).
			Msg("failed to prepare HTTP get_payload_v3 request")
		return false
	}

	responseChan := make(chan *common.VersionedSubmitBlockRequest, len(payloadUrls))

	// Send request to all builders
	for _, payloadUrl := range payloadUrls {
		url := payloadUrl + common.PathGetPayloadV3

		go func(url string, log zerolog.Logger) {
			result := new(common.VersionedSubmitBlockRequest)
			reqStart := time.Now()
			code, durationMS, err := httpclient.FetchSSZ(http.MethodPost, url, payload, result, nil, true)
			if err != nil {
				log.Debug().
					Err(err).
					Str("url", url).
					Int("code", code).
					Int64("durationMS", durationMS).
					Int64("duration_ms_measured", time.Since(reqStart).Milliseconds()).
					Msg("failed to prefetch builder payload with HTTP")
				return
			}

			// success path
			log.Debug().
				Str("url", url).
				Int("code", code).
				Int64("durationMS", durationMS).
				Int64("duration_ms_measured", time.Since(reqStart).Milliseconds()).
				Msg("successful prefetch builder payload HTTP response")

			responseChan <- result
		}(url, log)
	}

	// Process first positive response from builder (or timeout)
	return s.processGetPayloadV3Responses(ctx, responseChan, log, fields)
}

func (s *Service) processGetPayloadV3Responses(
	ctx context.Context,
	responseChan <-chan *common.VersionedSubmitBlockRequest,
	log zerolog.Logger,
	fields *preFetcherFields,
) bool {
	for {
		select {
		case <-ctx.Done():
			log.Debug().Msg("PreFetchPayloadV3 :: context cancelled")
			return false

		case response := <-responseChan:
			if response == nil {
				log.Debug().Msg("PreFetchPayloadV3 :: nil payload from builder")
				continue
			}

			getPayloadResponseSpec, err := common.BuildGetPayloadResponse(response)
			if err != nil {
				log.Debug().Err(err).Msg("PreFetchPayloadV3 :: BuildGetPayloadResponse failed")
				continue
			}

			getPayloadResponse := common.VersionedSubmitBlindedBlockResponse{
				VersionedSubmitBlindedBlockResponse: *getPayloadResponseSpec,
			}

			proxyCacheKey := common.GetKeyForCachingPayload(
				fields.slot,
				fields.parentHash,
				fields.blockHash,
				fields.proposerPubKey,
			)

			payloadResponse := &common.PayloadResponseForProxy{
				PayloadResponse: getPayloadResponse,
				BlockValue:      fields.blockValue,
			}

			if err := s.getPayloadResponseForProxySlot.Add(proxyCacheKey, payloadResponse, cache.DefaultExpiration); err != nil {
				log.Debug().
					Err(err).
					Msg("PreFetchPayloadV3 :: cache already exists")
				// payload already ready in cache
				return true
			}

			log.Info().Msg("PreFetchPayloadV3 :: HTTP builder prefetch succeeded")
			return true

		case <-time.After(common.OptimisticV3FetchPayloadTimeout):
			log.Warn().Msg("PreFetchPayloadV3 :: timeout waiting for builder HTTP response")
			return false
		}
	}
}

func (s *Service) prepareGetPayloadV3Request(blockHash string) (*optimisticv3.SignedGetPayloadV3, error) {
	getPayloadV3 := &optimisticv3.GetPayloadV3{
		BlockHash:      phase0.Hash32(gethcommon.HexToHash(blockHash)),
		RequestTs:      uint64(time.Now().UnixMilli()),
		RelayPublicKey: s.publicKey,
	}
	signature, err := ssz.SignMessage(getPayloadV3, s.builderSigningDomain, s.secretKey)
	if err != nil {
		return nil, err
	}
	return &optimisticv3.SignedGetPayloadV3{Message: getPayloadV3, Signature: signature}, nil
}
