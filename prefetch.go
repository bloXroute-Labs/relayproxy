package relayproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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

const prefetchContextTimeout = 4 * time.Second

var (
	prefetchHttpOnce   sync.Once
	prefetchHttpClient *http.Client
)

func getPrefetchHttpClient() *http.Client {
	prefetchHttpOnce.Do(func() {
		prefetchHttpClient = &http.Client{
			Timeout: 950 * time.Millisecond,
		}
	})
	return prefetchHttpClient
}

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
		successGRPC    bool
		successCache   bool
		successBuilder bool
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
	clients := s.clients
	clientURL := ""
	if fields.client != nil {
		clients = append(clients, fields.client)
		clientURL = fields.client.String()
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
			attribute.Bool("successCache", successCache),
			attribute.Bool("successGRPC", successGRPC),
			attribute.Bool("successBuilder", successBuilder),
			attribute.Int64("slot", int64(fields.slot)),
			attribute.String("blockHash", fields.blockHash),
			attribute.String("parentHash", fields.parentHash),
			attribute.String("proposerPubkey", fields.proposerPubKey),
			attribute.Int64("msIntoSlot_start", msIntoSlotPrefetchStart),
			attribute.Int64("msIntoSlot_end", msIntoSlotPrefetchEnd),
			attribute.Int64("msIntoSlot_getHeader_including_delay", fields.msIntoSlotGetHeaderIncludingDelay),
			attribute.String("getHeader_req_id", fields.getHeaderReqID),
			attribute.String("id", prefetchID),
			attribute.String("clientURL", clientURL),
		)
		span.End()

		s.performancestats.SetEndpointStats(
			"PreFetchGetPayload-rproxy",
			uint64(time.Since(startTime).Microseconds()),
			successCache || successGRPC || successBuilder,
			100,
		)
	}()

	uKey := "slot_" + strconv.FormatUint(fields.slot, 10) + "_bHash_" + fields.blockHash + "_pHash_" + fields.parentHash
	prefetchLogger := s.logger.With().
		Time("currentTime", time.Now().UTC()).
		Str("method", preFetchPayload).
		Time("prefetchStartedAt", startTime).
		Str("clientIP", fields.clientIP).
		Str("clientURL", clientURL).
		Int("clientCount", len(clients)).
		Str("prefetchID", prefetchID).
		Str("traceID", span.SpanContext().TraceID().String()).
		Str("uKey", uKey).
		Int64("slot", int64(fields.slot)). // or Uint64 if you prefer
		Str("parentHash", fields.parentHash).
		Str("blockHash", fields.blockHash).
		Int64("msIntoSlotStart", msIntoSlotPrefetchStart).
		Int64("msIntoSlotGetHeaderIncludingDelay", fields.msIntoSlotGetHeaderIncludingDelay).
		Str("getHeaderReqID", fields.getHeaderReqID).
		Str("builderPayloadFetchURL", fields.payloadFetchUrl).
		Logger()
	prefetchLogger.Info().Msg("received prefetchPayload")

	if fields.payloadFetchUrl != "" {
		subStart := time.Now()
		_, sub := s.tracer.Start(spanCtx, GetSpanName("prefetch", "builderHTTPorGRPC"))
		successBuilder = s.prefetchPayloadFromBuilder(ctx, spanCtx, &fields, prefetchLogger)
		sub.SetAttributes(
			attribute.Bool("success", successBuilder),
			attribute.Int64("duration_ms", time.Since(subStart).Milliseconds()),
		)
		sub.End()
		// TODO: NOTE: builder path does not currently call RecordPrefetchDone.
		// once v3 support implemented, wire it into processGetPayloadV3Responses.
		return
	}

	//Check if in local cache
	cacheLookupStart := time.Now()
	var (
		payloadSize int
		errMsg      string
	)
	payloadCacheKey := common.GetKeyForCachingPayload(fields.slot, fields.parentHash, fields.blockHash, fields.proposerPubKey)
	cachedValue, exists := s.getPayloadResponseForProxySlot.Get(payloadCacheKey)
	cacheLookupDurationMs := time.Since(cacheLookupStart).Milliseconds()
	prefetchLogger = prefetchLogger.With().Int64("cacheLookupDurationMs", cacheLookupDurationMs).Logger()

	if exists && cachedValue != nil {
		_, localCacheSpan := s.tracer.Start(spanCtx, GetSpanName("prefetch", "localCacheCheck"))
		payloadResponseForProxy, ok := cachedValue.(*common.PayloadResponseForProxy)
		if !ok {
			errMsg = "failed to cast cached value to GetPayloadResponseForProxy"
			prefetchLogger.Error().Msg(errMsg)
		} else {
			marshalResponseStart := time.Now()
			payload, err := payloadResponseForProxy.GetSszMarshalledResponse()
			marshalResponseDurationMs := time.Since(marshalResponseStart).Milliseconds()
			prefetchLogger = prefetchLogger.With().Int64("marshalResponseDurationMs", marshalResponseDurationMs).Logger()

			if err != nil {
				errMsg = "failed to get marshalled cached value from GetPayloadResponseForProxy"
				prefetchLogger.Error().Err(err).Msg(errMsg)
			} else {
				payloadSize = len(payload)
				successCache = true
				localCacheSpan.End()
				prefetchLogger.Info().
					Bool("successCache", successCache).
					Msg("Prefetch payload available in local cache, do not require grpc and http remote call")
				return
			}
		}
		localCacheSpan.End()
	} else {
		errMsg = "payload cache unavailable, key: " + payloadCacheKey
	}
	go s.IDataService.GetFlowService().RecordPrefetchDone(
		fields.slot,
		fields.parentHash,
		fields.blockHash,
		fields.proposerPubKey,
		prefetchID,
		fields.getHeaderReqID,
		successCache,
		cacheLookupDurationMs,
		FlowSourcePrefetchCache,
		clientURL,
		s.nodeID,
		payloadSize,
		errMsg,
	)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		prefetchLogger.Info().Time("currentTime", time.Now().UTC()).Msg("Starting prefetchGRPC")
		res, err := s.prefetchGRPC(ctx, spanCtx, clients, prefetchLogger, fields, prefetchID, startTime)
		if err == nil && res != nil {
			successGRPC = true
		}
	}()
	wg.Wait()
}

type prefetchResult struct {
	resp *relaygrpc.PreFetchGetPayloadResponse
	url  string
}

type prefetchResultHTTP struct {
	resp common.PreFetchGetPayloadResponseHTTP
	url  string
}

func (s *Service) prefetchHTTP(ctx context.Context,
	spanCtx context.Context,
	clients []*common.ParentClient,
	baseLogger zerolog.Logger,
	fields preFetcherFields,
	reqID string,
	prefetchStartTime time.Time) (result *prefetchResultHTTP, err error) {

	var (
		success         bool
		payloadSize     int
		payloadCacheKey string
		url             string
	)
	spanCtx, span := s.tracer.Start(spanCtx, GetSpanName("prefetch", "HTTPWrapper"))
	defer func() {
		durationMs := time.Since(prefetchStartTime).Milliseconds()

		success = err == nil && result != nil
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}

		targetClientIP := ""
		if fields.client != nil {
			targetClientIP = fields.client.String()
		}

		//source := FlowSourcePrefetchGRPC
		if success {
			if result != nil {
				payloadSize = len(result.resp.SszVersionedExecutionPayload)
			}
			//source = result.source
			baseLogger.Info().
				Time("currentTime", time.Now().UTC()).
				Int("payload_size_bytes", payloadSize).
				Str("winner_url", result.url).
				Str("targetClientIP", targetClientIP).
				Int64("duration_ms", durationMs).
				Msg("prefetchHTTP :: succeeded")
		} else {
			baseLogger.Error().Err(err).
				Time("currentTime", time.Now().UTC()).
				Int("payload_size_bytes", payloadSize).
				Str("url", url).
				Str("targetClientIP", targetClientIP).
				Time("currentTime", time.Now().UTC()).
				Int64("duration_ms", durationMs).
				Msg("prefetchHTTP :: failed")
		}
		span.SetAttributes(
			attribute.Int64("slot", int64(fields.slot)),
			attribute.String("parentHash", fields.parentHash),
			attribute.String("blockHash", fields.blockHash),
			attribute.Bool("success", success),
			attribute.String("targetClientIP", targetClientIP),
			attribute.String("error", errMsg),
		)
		span.End()
		go s.IDataService.GetFlowService().RecordPrefetchDone(
			fields.slot,
			fields.parentHash,
			fields.blockHash,
			fields.proposerPubKey,
			reqID,
			fields.getHeaderReqID,
			success,
			durationMs,
			FlowSourcePrefetchHTTP,
			url,
			"",
			payloadSize,
			errMsg,
		)
	}()

	if len(clients) == 0 {
		err = fmt.Errorf("no downstream clients")
		return nil, err
	}

	gctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	resultCh := make(chan *prefetchResultHTTP, 1)
	errCh := make(chan error, len(clients))
	errList := make([]string, 0, len(clients))
	requestCount := len(clients)

	for _, parent := range clients {
		parentURL := parent.String()
		wg.Add(1)
		go func(client *common.Client, parentURL string) {
			defer wg.Done()

			clientLogger := baseLogger.With().
				Time("prefetchStartTime", prefetchStartTime).
				Str("downstreamURL", parentURL).
				Str("clientURL", client.URL).
				Str("clientNodeID", client.NodeID).
				Logger()

			prefetchHTTPSingleStart := time.Now()
			clientLogger.Info().
				Time("currentTime", prefetchHTTPSingleStart).
				Msg("Starting prefetchHTTPSingle")

			defer func(clientLogger *zerolog.Logger) {
				clientLogger.Info().
					Time("currentTime", time.Now().UTC()).
					Dur("prefetchHTTPSingleDuration", time.Since(prefetchHTTPSingleStart)).
					Msg("Finishing prefetchHTTPSingle")
			}(&clientLogger)

			res, pErr := s.prefetchHTTPSingle(gctx, spanCtx, client, clientLogger, fields, reqID, prefetchStartTime)
			if pErr != nil || res == nil {
				select {
				case errCh <- pErr:
				default:
				}
				return
			}

			select {
			case resultCh <- res:
			default:
			}
		}(parent.SafeClient, parentURL)
	}

	go func() {
		wg.Wait()
		close(resultCh)
		close(errCh)
	}()

	for i := 0; i < requestCount; i++ {
		select {
		case <-gctx.Done():
			return nil, gctx.Err()
		case res := <-resultCh:
			if res != nil {
				result = res
				err = nil
				payloadCacheKey = common.GetKeyForCachingPayload(
					fields.slot,
					fields.parentHash,
					fields.blockHash,
					fields.proposerPubKey,
				)
				payloadResponse := &common.PayloadResponseForProxy{
					SszMarshalledPayloadResponse: result.resp.SszVersionedExecutionPayload,
					BlockValue:                   fields.blockValue,
				}
				payloadSize = len(result.resp.SszVersionedExecutionPayload)
				_ = s.getPayloadResponseForProxySlot.Add(
					payloadCacheKey,
					payloadResponse,
					cache.DefaultExpiration,
				)
				return result, nil
			}
		case _err := <-errCh:
			if _err != nil {
				errList = append(errList, _err.Error())
			}
		}
	}
	err = errors.New(strings.Join(errList, ";"))
	return
}

func (s *Service) prefetchHTTPSingle(ctx context.Context,
	spanCtx context.Context,
	client *common.Client,
	baseLogger zerolog.Logger,
	fields preFetcherFields,
	reqID string,
	prefetchStartTime time.Time,
) (*prefetchResultHTTP, error) {
	clientCtx, cancel := context.WithTimeout(ctx, prefetchContextTimeout)
	defer cancel()
	var clientURL string

	if client != nil {
		clientURL = client.URL
	}

	req := common.PreFetchGetPayloadRequestHTTP{
		Slot:           fields.slot,
		ParentHash:     fields.parentHash,
		BlockHash:      fields.blockHash,
		Pubkey:         fields.proposerPubKey,
		ClientIp:       fields.clientIP,
		ReceivedAt:     timestamppb.New(prefetchStartTime),
		GetHeaderReqID: fields.getHeaderReqID,
		PrefetchReqID:  reqID,
		NodeID:         s.nodeID,
	}

	jsonMarshalStart := time.Now()
	reqBytes, err := json.Marshal(req)
	jsonMarshalDuration := time.Since(jsonMarshalStart)
	baseLogger = baseLogger.With().Dur("jsonMarshalDuration", jsonMarshalDuration).Str("clientURL", clientURL).Logger()
	if err != nil {
		baseLogger.Error().Err(err).Time("currentTime", time.Now().UTC()).Msg("prefetch HTTP: failed")
		return nil, fmt.Errorf("failed to marshal prefetch http req %v", err.Error())
	}

	url, err := getURL(clientURL)
	if err != nil {
		baseLogger.Error().Err(err).Time("currentTime", time.Now().UTC()).Msg("prefetch HTTP: failed")
		return nil, fmt.Errorf("failed to parse prefetch http clientURL:%v,error: %v", clientURL, err.Error())
	}

	httpReq, err := http.NewRequestWithContext(clientCtx, http.MethodGet, url, bytes.NewReader(reqBytes))
	if err != nil {
		baseLogger.Error().Err(err).Time("currentTime", time.Now().UTC()).Msg("prefetch HTTP: failed")
		return nil, fmt.Errorf("failed to marshal prefetch http req %v", err.Error())
	}
	httpReq.Header.Set("Content-Type", "application/json")

	reqStart := time.Now()
	_, childSpan := s.tracer.Start(spanCtx, GetSpanName("prefetch", "HTTP"))
	defer childSpan.End()

	childSpan.SetAttributes(
		attribute.String("originalURL", clientURL),
		attribute.String("url", url),
	)
	res, err := getPrefetchHttpClient().Do(httpReq)
	reqDurMs := time.Since(reqStart).Milliseconds()
	baseLogger = baseLogger.With().Int64("duration_ms", reqDurMs).Logger()
	if err != nil {
		baseLogger.Error().Err(err).Time("currentTime", time.Now().UTC()).Msg("prefetch HTTP: failed")
		return nil, err
	}

	if res.StatusCode >= http.StatusMultipleChoices {
		statusCodeErr := fmt.Errorf("Received invalid status code %d", res.StatusCode)
		baseLogger.Error().Err(statusCodeErr).Time("currentTime", time.Now().UTC()).Msg("prefetch HTTP: failed")
		return nil, statusCodeErr
	}

	defer res.Body.Close()
	var respData common.PreFetchGetPayloadResponseHTTP
	if err = json.NewDecoder(res.Body).Decode(&respData); err != nil && err != io.EOF {
		baseLogger.Error().Err(err).Time("currentTime", time.Now().UTC()).Msg("prefetch HTTP: failed")
		return nil, err
	}

	baseLogger.Info().Time("currentTime", time.Now().UTC()).Msg("prefetch HTTP: succeeded")

	childSpan.SetAttributes(
		attribute.Int64("request_duration_ms", reqDurMs),
		attribute.Int("payload_size_bytes", len(respData.SszVersionedExecutionPayload)),
	)
	errMsg := ""
	if respData.Code == uint32(codes.OK) {
		if len(respData.SszVersionedExecutionPayload) != 0 {
			baseLogger.Info().Time("currentTime", time.Now().UTC()).Msg("prefetch http: succeeded")

			childSpan.SetAttributes(
				attribute.Int64("request_duration_ms", reqDurMs),
				attribute.Int("payload_size_bytes", len(respData.SszVersionedExecutionPayload)),
			)

			return &prefetchResultHTTP{
				resp: respData,
				url:  url,
			}, nil
		} else {
			return nil, errors.New("zero len VersionedExecutionPayload")
		}
	} else if respData.Code != uint32(codes.OK) {
		errMsg = respData.Message
	} else if err != nil {
		errMsg = err.Error()
	} else {
		errMsg = "nil response from relay"
	}
	return nil, errors.New(errMsg)
}

func getURL(url string) (string, error) {
	port := ":18555"

	if strings.Contains(url, ":") {
		host, portNumber, err := net.SplitHostPort(url)
		if err != nil {
			return "", err
		}
		url = host
		if portNumber == "5015" {
			port = ":18550"
		}
	}

	finalURL := "http://" + url + port + common.PathPrefetchBlock
	return finalURL, nil
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
		url             string
	)
	spanCtx, span := s.tracer.Start(spanCtx, GetSpanName("prefetch", "gRPCWrapper"))
	defer func() {
		durationMs := time.Since(prefetchStartTime).Milliseconds()

		success = err == nil && result != nil
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}

		targetClientIP := ""
		if fields.client != nil {
			targetClientIP = fields.client.String()
		}

		//source := FlowSourcePrefetchGRPC
		if success {
			if result != nil && result.resp != nil {
				url = result.url
				payloadSize = len(result.resp.SszVersionedExecutionPayload)
			}
			//source = result.source
			baseLogger.Info().
				Time("currentTime", time.Now().UTC()).
				Int("payload_size_bytes", payloadSize).
				Str("winner_url", url).
				Str("targetClientIP", targetClientIP).
				Int64("durationMs", durationMs).
				Msg("prefetchGRPC :: succeeded")
		} else {
			baseLogger.Error().Err(err).
				Time("currentTime", time.Now().UTC()).
				Int("payload_size_bytes", payloadSize).
				Str("url", url).
				Str("targetClientIP", targetClientIP).
				Int64("durationMs", durationMs).
				Msg("prefetchGRPC :: failed")
		}
		span.SetAttributes(
			attribute.Int64("slot", int64(fields.slot)),
			attribute.String("parentHash", fields.parentHash),
			attribute.String("blockHash", fields.blockHash),
			attribute.Bool("success", success),
			attribute.String("targetClientIP", targetClientIP),
			attribute.String("error", errMsg),
		)
		span.End()
		go s.IDataService.GetFlowService().RecordPrefetchDone(
			fields.slot,
			fields.parentHash,
			fields.blockHash,
			fields.proposerPubKey,
			reqID,
			fields.getHeaderReqID,
			success,
			durationMs,
			FlowSourcePrefetchGRPC,
			url,
			"",
			payloadSize,
			errMsg,
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
		parentURL := parent.String()
		wg.Add(1)
		go func(client *common.Client, parentURL string, req *relaygrpc.PreFetchGetPayloadRequest) {
			defer wg.Done()

			clientLogger := baseLogger.With().
				Str("requestID", req.ReqId).
				Str("reqVersion", req.Version).
				Str("reqClientIP", req.ClientIp).
				Str("reqVersion", req.Version).
				Time("prefetchStartTime", prefetchStartTime).
				Str("downstreamURL", parentURL).
				Str("clientURL", client.URL).
				Str("clientNodeID", client.NodeID).
				Logger()

			prefetchGRPCSingleStart := time.Now()
			clientLogger.Info().
				Time("currentTime", prefetchGRPCSingleStart).
				Msg("Starting prefetchGRPCSingle")

			defer func(clientLogger *zerolog.Logger) {
				clientLogger.Info().
					Time("currentTime", time.Now().UTC()).
					Dur("prefetchGRPCSingleDuration", time.Since(prefetchGRPCSingleStart)).
					Msg("Finishing prefetchGRPCSingle")
			}(&clientLogger)

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
			default:
			}
		}(parent.SafeClient, parentURL, req)
	}

	go func() {
		wg.Wait()
		close(resultCh)
		close(errCh)
	}()

	for i := 0; i < requestCount; i++ {
		select {
		case <-gctx.Done():
			return nil, gctx.Err()
		case res := <-resultCh:
			if res != nil {
				result = res
				err = nil
				payloadCacheKey = common.GetKeyForCachingPayload(
					fields.slot,
					fields.parentHash,
					fields.blockHash,
					fields.proposerPubKey,
				)
				payloadResponse := &common.PayloadResponseForProxy{
					SszMarshalledPayloadResponse: result.resp.SszVersionedExecutionPayload,
					BlockValue:                   fields.blockValue,
				}
				payloadSize = len(result.resp.SszVersionedExecutionPayload)
				_ = s.getPayloadResponseForProxySlot.Add(
					payloadCacheKey,
					payloadResponse,
					cache.DefaultExpiration,
				)
				return result, nil
			} else {
				return nil, errors.New("empty response,either channel closed before reading it")
			}
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
	clientCtx, cancel := context.WithTimeout(ctx, prefetchContextTimeout)
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
		if len(out.SszVersionedExecutionPayload) != 0 {
			logger.Info().
				Time("currentTime", time.Now().UTC()).
				Str("url", clientURL).
				Int64("duration_ms", reqDurMs).
				Msg("prefetch gRPC: succeeded")

			childSpan.SetAttributes(
				attribute.Int64("request_duration_ms", reqDurMs),
				attribute.Int("payload_size_bytes", len(out.SszVersionedExecutionPayload)),
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

	logger.Error().
		Time("currentTime", time.Now().UTC()).
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
		url := payloadUrl

		// Add the proper path if it's not already included in the url
		if !strings.HasSuffix(url, common.PathGetPayloadV3) {
			url += common.PathGetPayloadV3
		}

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

			if s.optimisticV3FetchedPayloadsChan != nil {
				select {
				case s.optimisticV3FetchedPayloadsChan <- response:
				default:
					log.Error().
						Str("blockHash", fields.blockHash).
						Msg("PreFetchPayloadV3 :: failed to send Optimistic V3 fetched payload for processing, channel is full")
				}
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
