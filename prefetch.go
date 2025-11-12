package relayproxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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
	//go s.IDataService.GetFlowService().RecordPrefetchStart(fields.slot, fields.parentHash, fields.blockHash, fields.proposerPubKey, fields.blockValue, s.nodeID, PrefetchFlowEvent{
	//	PrefetchID:              prefetchID,
	//	GetHeaderReqID:          fields.getHeaderReqID,
	//	StartedAt:               startTime,
	//	MsIntoSlotPrefetchStart: msIntoSlotPrefetchStart,
	//})
	clients := s.clients
	if fields.client != nil {
		clients = append(clients, fields.client)
	}

	spanCtx, span := s.tracer.Start(ctx, GetSpanName("prefetch", "START"))
	defer func() {
		totalMs := time.Since(startTime).Milliseconds()
		var msIntoSlotPrefetchEnd int64
		if !fields.slotStartTime.IsZero() {
			msIntoSlotPrefetchEnd = time.Since(fields.slotStartTime).Milliseconds()
		}

		span.SetAttributes(
			attribute.Int64("total_ms", totalMs),
			attribute.Bool("success", success),
			attribute.Int64("slot", int64(fields.slot)),
			attribute.String("blockHash", fields.blockHash),
			attribute.String("parentHash", fields.parentHash),
			attribute.String("proposerPubkey", fields.proposerPubKey),
			attribute.Int64("msIntoSlot_start", msIntoSlotPrefetchStart),
			attribute.Int64("msIntoSlot_end", msIntoSlotPrefetchEnd),
			attribute.Int64("msIntoSlot_getHeader_including_delay", fields.msIntoSlotGetHeaderIncludingDelay),
			attribute.String("getHeader_req_id", fields.getHeaderReqID),
			attribute.String("id", prefetchID),
			attribute.String("clientURL", fields.client.String()),
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

	//TODO: SKIP if in local cache
	go s.prefetchGRPC(ctx, spanCtx, clients, prefetchLogger, fields, prefetchID, startTime)
	//prefetchHTTP()

}

type prefetchResult struct {
	resp *relaygrpc.PreFetchGetPayloadResponse
	url  string
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
		payloadCacheKey string
	)

	defer func() {
		durationMs := time.Since(prefetchStartTime).Milliseconds()

		success = err == nil && result != nil
		//source := FlowSourcePrefetchGRPC
		if success {
			if result != nil && result.resp != nil {
				payloadSize = len(result.resp.VersionedExecutionPayload)
			}
			//source = result.source
			baseLogger.Info().
				Int("payload_size_bytes", payloadSize).
				Str("winner_url", result.url).
				Int64("endedAt", durationMs).
				Msg("prefetchGRPC :: succeeded")
		} else {
			baseLogger.Error().Err(err).
				Int("payload_size_bytes", payloadSize).
				Str("url", result.url).
				Int64("endedAt", durationMs).
				Msg("prefetchGRPC :: failed")
		}
	}()

	if len(clients) == 0 {
		err = fmt.Errorf("no downstream clients")
		return nil, err
	}

	gctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	resultCh := make(chan *prefetchResult, 1)
	errCh := make(chan error, len(clients))
	errList := make([]string, 0, len(clients))
	requestCount := len(clients)
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
		url := parent.String()
		wg.Add(1)
		go func(client *common.Client, url string, req *relaygrpc.PreFetchGetPayloadRequest) {
			defer wg.Done()

			clientLogger := baseLogger.With().Str("downstream_url", url).Logger()

			res, pErr := s.prefetchGRPCSingle(gctx, spanCtx, client, req, clientLogger)
			if pErr != nil || res == nil {
				select {
				case errCh <- pErr:
				default:
				}
				return
			}

			select {
			case resultCh <- res:
				cancel()
			default:
			}
		}(parent.SafeClient, url, req)
	}

	go func() {
		wg.Wait()
		close(resultCh)
		close(errCh)
	}()

	for i := 0; i < requestCount; i++ {
		select {
		case <-gctx.Done():
			return
		case res := <-resultCh:
			result = res
			err = nil
			payloadCacheKey = common.GetKeyForCachingPayload(
				fields.slot,
				fields.parentHash,
				fields.blockHash,
				fields.proposerPubKey,
			)
			payloadResponse := &common.PayloadResponseForProxy{
				MarshalledPayloadResponse: result.resp.VersionedExecutionPayload,
				BlockValue:                fields.blockValue,
			}
			payloadSize = len(result.resp.VersionedExecutionPayload)
			_ = s.getPayloadResponseForProxySlot.Add(
				payloadCacheKey,
				payloadResponse,
				cache.DefaultExpiration,
			)
			success = true
			return result, nil
		case _err := <-errCh:
			if _err != nil {
				errList = append(errList, _err.Error())
			}
		}
	}
	err = errors.New(strings.Join(errList, ";"))
	return
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
	var errMsg, clientURL string

	if client != nil {
		clientURL = client.URL
	}

	reqStart := time.Now()
	_, childSpan := s.tracer.Start(spanCtx, GetSpanName("prefetch", "gRPC"))
	defer childSpan.End()

	childSpan.SetAttributes(
		attribute.String("url", clientURL),
	)

	out, err := client.PreFetchGetPayload(clientCtx, req)
	reqDurMs := time.Since(reqStart).Milliseconds()

	if err == nil && out != nil && out.Code == uint32(codes.OK) {
		if len(out.VersionedExecutionPayload) != 0 {
			logger.Info().
				Str("url", clientURL).
				Int64("duration_ms", reqDurMs).
				Msg("prefetch gRPC: succeeded")

			childSpan.SetAttributes(
				attribute.Int64("request_duration_ms", reqDurMs),
				attribute.Int("payload_size_bytes", len(out.VersionedExecutionPayload)),
			)

			return &prefetchResult{
				resp: out,
				url:  clientURL,
			}, nil
		} else {
			errMsg = "zero len VersionedExecutionPayload"
		}
	} else if out != nil && out.Code != uint32(codes.OK) {
		errMsg = out.Message
	} else if err != nil {
		errMsg = err.Error()
	} else {
		errMsg = "nil response from relay"
	}

	logger.Info().
		Str("url", clientURL).
		Int64("duration_ms", reqDurMs).
		Str("error", errMsg).
		Msg("prefetch gRPC: failed")

	childSpan.SetAttributes(
		attribute.Int64("request_duration_ms", reqDurMs),
		attribute.String("error", errMsg),
	)

	return nil, fmt.Errorf("%s", errMsg)
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
