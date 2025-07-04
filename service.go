package relayproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	relaygrpc "github.com/bloXroute-Labs/relay-grpc"
	"github.com/bloXroute-Labs/relayproxy/common"
	"github.com/bloXroute-Labs/relayproxy/fastjson"
	"github.com/bloXroute-Labs/relayproxy/fluentstats"
	"github.com/bloXroute-Labs/relayproxy/httpclient"
)

const (
	regRequestTimeout        = 1 * time.Second
	preFetcherRequestTimeout = 3 * time.Second

	// cache
	BuilderBidsCleanupInterval      = 60 * time.Second // 5 slots
	ExecutionPayloadCleanupInterval = 60 * time.Second // 5 slots
	slotStatsCleanupInterval        = 60 * time.Second // 5 slots
	cacheKeySeparator               = "_"

	maxGetPayloadRetry                = 3
	getPayloadInterval                = 150 * time.Millisecond
	preFetchPayloadChanBufSize        = 100
	getPayloadRequestCutoffMs         = 4000
	duplicateSlotCacheCleanupInterval = 180 * time.Second // 30 slots
	reconnectTime                     = 6000
)

var (
	// errors
	errInvalidSlot           = errors.New("invalid slot")
	errInvalidPubkey         = errors.New("invalid pubkey")
	errInvalidHash           = errors.New("invalid hash")
	errContextDeadlineString = "context deadline exceeded"
)

type IService interface {
	IDataService
	RegisterValidator(ctx context.Context, log *zerolog.Logger, outgoingCtx context.Context, in *RegistrationParams) (any, error)
	GetHeader(ctx context.Context, log *zerolog.Logger, in *HeaderRequestParams) (json.RawMessage, error)
	GetPayload(ctx context.Context, log *zerolog.Logger, in *PayloadRequestParams) (*common.VersionedPayloadInfo, error)
	GetPayloadTrusted(ctx context.Context, log *zerolog.Logger, in *PayloadRequestParams) (*common.VersionedPayloadInfo, error)
}
type Service struct {
	// data service
	IDataService

	logger      zerolog.Logger
	version     string // build version
	nodeID      string // UUID
	authKey     string
	secretToken string

	tracer                         trace.Tracer
	fluentD                        fluentstats.Stats
	builderBidsForProxySlot        *cache.Cache
	builderExistingBlockHash       *cache.Cache
	getPayloadResponseForProxySlot *cache.Cache
	preFetchPayloadChan            chan preFetcherFields

	beaconGenesisTime  int64
	secondsPerSlot     int64
	slotStats          *cache.Cache
	slotStatsEvent     *cache.Cache
	duplicateSlotCache *cache.Cache
	slotStatsEventCh   chan slotStatsEvent
	ethNetworkDetails  *common.EthNetworkDetails

	clients                       []*common.ParentClient
	streamingClients              []*common.ParentClient
	streamingBlockClients         []*common.ParentClient
	registrationClients           []*common.ParentClient
	currentRegistrationRelayIndex int
	registrationRelayMutex        sync.Mutex

	secretKey            *bls.SecretKey
	publicKey            phase0.BLSPubKey
	builderSigningDomain phase0.Domain

	listenAddress     string
	GrpcListenAddress string
	forwardedBlockCh  *chan common.ForwardedBlockInfo

	builderInfo *cache.Cache

	accountsLists       *AccountsLists
	walletAccounts      *map[string]*common.WalletAccount
	miniProposerSlotMap *SyncMap[uint64, *common.MiniValidatorLatency]

	blockPublishingGatewayClient interface{}
	gatewayAuthKey               string
	blockPublishFunc             func(tracer trace.Tracer, logger zerolog.Logger, payloadInfo *common.VersionedPayloadInfo, signedBeaconBlock *common.VersionedSignedBlindedBeaconBlock, blockPublishingGatewayClient interface{}, authKey string)
}

type slotStatsEvent struct {
	Slot      int64
	SlotKey   string
	UserAgent string
}

type preFetcherFields struct {
	clientIP        string
	authHeader      string
	slot            uint64
	parentHash      string
	blockHash       string
	proposerPubKey  string
	builderPubKey   string
	blockValue      string
	client          *common.ParentClient
	payloadFetchUrl string
}

func NewService(opts ...ServiceOption) *Service {

	svc := &Service{
		preFetchPayloadChan:           make(chan preFetcherFields, preFetchPayloadChanBufSize),
		slotStats:                     cache.New(slotStatsCleanupInterval, slotStatsCleanupInterval),
		slotStatsEvent:                cache.New(slotStatsCleanupInterval, slotStatsCleanupInterval),
		duplicateSlotCache:            cache.New(duplicateSlotCacheCleanupInterval, duplicateSlotCacheCleanupInterval), // cache to avoid emitting duplicate stats
		slotStatsEventCh:              make(chan slotStatsEvent, 100),
		registrationRelayMutex:        sync.Mutex{},
		currentRegistrationRelayIndex: 0,
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

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
	log.Info().Msg("received registration")
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
		out, err := s.registerValidatorForClient(ctx, req)
		if err != nil {
			errChan <- err
			return
		}
		respChan <- out
	}(ctx, req)
	spanWait.End(trace.WithTimestamp(time.Now()))

	ctx, spanSuccess := s.tracer.Start(ctx, "RegisterValidator-waitForSuccessfulResponse")
	select {
	case <-ctx.Done():
		return nil, toErrorResp(http.StatusInternalServerError, ctx.Err().Error())
	case _err = <-errChan:
		// first error captured
	case <-respChan:
		return struct{}{}, nil
	case <-timer.C:
		log.Error().Msg("timer hit: relay request timeout")
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
			s.logger.Warn().Str("url", url).Err(err).Msg("failed to register validator")
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
		return nil, toErrorResp(http.StatusBadRequest, "relay returned failure response code"+strconv.FormatUint(uint64(out.Code), 10))
	}

	return nil, toErrorResp(http.StatusInternalServerError, "no relay client available")
}
func (s *Service) StartStreamHeaders(ctx context.Context, wg *sync.WaitGroup) {

	for _, client := range s.streamingClients {
		wg.Add(1)
		go func(_ctx context.Context, c *common.ParentClient) {
			defer wg.Done()
			s.handleStream(_ctx, c)
		}(ctx, client)
	}
	wg.Wait()
}

func (s *Service) handleStream(ctx context.Context, client *common.ParentClient) {
	parentSpan := trace.SpanFromContext(ctx)
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)
	_, span := s.tracer.Start(ctx, "handleStream-streamHeader")
	defer span.End(trace.WithTimestamp(time.Now().UTC()))

	traceID := parentSpan.SpanContext().TraceID().String()

	span.SetAttributes(
		attribute.String("method", "streamHeader"),
		attribute.String("url", client.SafeClient.URL),
		attribute.String("traceID", traceID),
	)

	var (
		lastConnectTime time.Time
	)

	for {

		select {
		case <-ctx.Done():
			s.logger.Warn().
				Str("traceID", traceID).
				Msg("stream header context cancelled")
			return

		default:

			active, safe := client.GetActiveClient(lastConnectTime)
			if safe {
				s.logger.Warn().Str("method", "streamHeader").Time("lastConnectTime", lastConnectTime).Str("fastURL", client.FastClient.URL).Str("safeURL", client.SafeClient.URL).Msg("Fallback to safe IP used")
			} else {
				s.logger.Info().Str("method", "streamHeader").Time("lastConnectTime", lastConnectTime).Str("fastURL", client.FastClient.URL).Str("safeURL", client.SafeClient.URL).Msg("fast IP used")
			}
			lastConnectTime = time.Now()

			if _, err := s.StreamHeader(ctx, active, client); err != nil {
				s.logger.Warn().
					Str("url", active.URL).
					Str("traceID", traceID).
					Err(err).
					Msg("failed to stream header. Sleeping and then reconnecting")

				span.SetAttributes(
					attribute.Int64("sleepingFor", reconnectTime),
					attribute.String("error", err.Error()),
				)
			} else {
				s.logger.Warn().
					Str("url", active.URL).
					Str("traceID", traceID).
					Msg("stream header stopped. Sleeping and then reconnecting")

				span.SetAttributes(
					attribute.Int64("sleepingFor", reconnectTime),
					attribute.String("error", "stream header stopped."),
				)
			}

			time.Sleep(reconnectTime * time.Millisecond)
		}
	}
}

func (s *Service) StreamHeader(ctx context.Context, client *common.Client, parentClient *common.ParentClient) (*relaygrpc.StreamHeaderResponse, error) {
	parentSpan := trace.SpanFromContext(ctx)
	method := "streamHeader"
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", s.authKey)
	streamHeaderCtx, span := s.tracer.Start(ctx, "streamHeader-start")
	defer span.End(trace.WithTimestamp(time.Now().UTC()))
	id := uuid.NewString()
	client.NodeID = fmt.Sprintf("%v-%v-%v-%v", s.nodeID, client.URL, id, time.Now().UTC().Format("15:04:05.999999999"))
	stream, err := client.StreamHeader(ctx, &relaygrpc.StreamHeaderRequest{
		ReqId:       id,
		NodeId:      client.NodeID,
		Version:     s.version,
		SecretToken: s.secretToken,
	})
	logMetric := NewLogMetric(
		map[string]any{
			"method": method,
			"nodeID": client.NodeID,
			"reqID":  id,
			"url":    client.URL,
		},
	)

	s.logger.Info().Fields(logMetric.GetFields()).Msg("streaming headers")
	if err != nil {
		logMetric.Error(err)
		s.logger.Warn().Fields(logMetric.GetFields()).Err(err).Msg("failed to stream header")
		span.SetStatus(otelcodes.Error, err.Error())
		return nil, err
	}
	done := make(chan struct{})
	var once sync.Once
	closeDone := func() {
		once.Do(func() {
			s.logger.Info().Msg("calling close done once")
			close(done)
		})
	}
	logMetricCopy := logMetric.Copy()
	go func(lm *LogMetric) {
		select {
		case <-stream.Context().Done():
			lm.Error(stream.Context().Err())
			s.logger.Warn().Fields(lm.GetFields()).Msg("stream context cancelled, closing connection")
			closeDone()
		case <-ctx.Done():
			logMetric.Error(ctx.Err())
			s.logger.Warn().Fields(logMetric.GetFields()).Msg("context cancelled, closing connection")
			closeDone()
		}
	}(logMetricCopy)

	streamReceiveCtx, streamReceiveSpan := s.tracer.Start(streamHeaderCtx, "StreamHeader-streamReceive")

	for {
		select {
		case <-done:
			return nil, nil
		default:
		}

		header, err := stream.Recv()
		receivedAt := time.Now().UTC()
		latency := time.Since(header.GetSendTime().AsTime()).Milliseconds()

		if err == io.EOF {
			s.logger.Warn().Err(err).Fields(logMetric.GetFields()).Msg("stream received EOF")
			streamReceiveSpan.SetStatus(otelcodes.Error, err.Error())
			closeDone()
			break
		}

		_s, ok := status.FromError(err)
		if !ok {
			s.logger.Warn().Err(err).Fields(logMetric.GetFields()).Msg("invalid grpc error status")
			streamReceiveSpan.SetStatus(otelcodes.Error, "invalid grpc error status")
			continue
		}

		if _s.Code() == codes.Canceled {
			logMetric.Error(err)
			s.logger.Warn().Err(err).Fields(logMetric.GetFields()).Msg("received cancellation signal, shutting down")
			streamReceiveSpan.SetStatus(otelcodes.Error, "received cancellation signal")
			closeDone()
			break
		}

		if _s.Code() != codes.OK {
			s.logger.Warn().Err(_s.Err()).Str("code", _s.Code().String()).Fields(logMetric.GetFields()).Msg("server unavailable, try reconnecting")
			streamReceiveSpan.SetStatus(otelcodes.Error, "server unavailable, try reconnecting")
			closeDone()
			break
		}

		if err != nil {
			s.logger.Warn().Err(err).Fields(logMetric.GetFields()).Msg("failed to receive stream, disconnecting the stream")
			streamReceiveSpan.SetStatus(otelcodes.Error, err.Error())
			closeDone()
			break
		}

		if header.GetBlockHash() == "" {
			s.logger.Trace().Fields(logMetric.GetFields()).Msg("received empty stream")
			continue
		}

		// Process header
		lm := logMetric.Copy()

		k := s.keyForCachingBids(header.GetSlot(), header.GetParentHash(), header.GetPubkey())
		uKey := fmt.Sprintf("slot_%v_bHash_%v_pHash_%v", header.GetSlot(), header.GetBlockHash(), header.GetParentHash())

		lm.Fields(map[string]any{
			"keyForCachingBids": k,
			"slot":              header.GetSlot(),
			"in.ParentHash":     header.GetParentHash(),
			"blockHash":         header.GetBlockHash(),
			"pubKey":            header.GetPubkey(),
			"builderPubKey":     header.GetBuilderPubkey(),
			"extraData":         header.GetBuilderExtraData(),
			"traceID":           parentSpan.SpanContext().TraceID().String(),
			"uniqueKey":         uKey,
			"receivedAt":        receivedAt,
			"paidBlxr":          header.GetPaidBlxr(),
			"accountID":         header.GetAccountId(),
			"payloadFetchUrl":   header.GetPayloadFetchUrl(),
		})

		var (
			duplicateReceiveTime int64
			addedAt              int64
			source               string
		)

		if val, exist := s.builderExistingBlockHash.Get(header.GetBlockHash()); exist {
			if v, ok := val.(common.DuplicateBlock); ok {
				addedAt = v.Time
				source = v.Source
			}
			duplicateReceiveTime = time.Now().UTC().UnixMilli()
			lm.Fields(map[string]any{
				"receivedAt": duplicateReceiveTime,
				"addedAt":    addedAt,
				"diff":       duplicateReceiveTime - addedAt,
				"source":     source,
			})

			s.logger.Warn().Fields(lm.GetFields()).Msg("block hash already exist")
			continue
		}
		// update block hash map if not seen already
		s.builderExistingBlockHash.Set(header.GetBlockHash(), common.DuplicateBlock{
			Time:   time.Now().UTC().UnixMilli(),
			Source: "proxy-header-" + GetHost(client.URL),
		}, cache.DefaultExpiration)

		lm.Fields(map[string]any{
			"blockValue":        new(big.Int).SetBytes(header.GetValue()).String(),
			"relayReceiveAt":    header.GetRelayReceiveTime().AsTime(),
			"streamSentAt":      header.GetSendTime().AsTime(),
			"streamLatencyInMs": time.Since(header.GetSendTime().AsTime()).Milliseconds(),
		})

		s.logger.Info().Fields(lm.GetFields()).Msg("received header")

		headerStream := HeaderStreamReceivedRecord{
			RelayReceivedAt:   header.GetRelayReceiveTime().AsTime(),
			ReceivedAt:        receivedAt,
			SentAt:            header.GetSendTime().AsTime(),
			StreamLatencyInMS: latency,
			Slot:              int64(header.GetSlot()),
			ParentHash:        header.GetParentHash(),
			PubKey:            header.GetPubkey(),
			BlockHash:         header.GetBlockHash(),
			BlockValue:        weiToEther(new(big.Int).SetBytes(header.GetValue())),
			BuilderPubKey:     header.GetBuilderPubkey(),
			BuilderExtraData:  header.GetBuilderExtraData(),
			PaidBLXR:          header.GetPaidBlxr(),
			ClientIP:          GetHost(client.URL),
			NodeID:            s.nodeID,
			AccountID:         header.GetAccountId(),
			Method:            method,
			PayloadFetchUrl:   header.GetPayloadFetchUrl(),
		}

		go func(streamCopy HeaderStreamReceivedRecord) {
			s.fluentD.LogToFluentD(fluentstats.Record{
				Type: TypeRelayProxyHeaderStreamReceived,
				Data: streamCopy,
			}, time.Now().UTC(), s.nodeID, StatsRelayProxyHeaderStreamReceived)
		}(headerStream)

		// Store the bid for builder pubkey
		_, storeBidsSpan := s.tracer.Start(streamReceiveCtx, "StreamHeader-storeBids")
		payloadURL := "grpc;" + client.URL
		headerSubmissionV3, err := common.RelayGrpcHeaderSubmissionToVersioned(header, []byte(payloadURL))
		if err != nil && header.GetPayload() == nil {
			s.logger.Error().Fields(logMetric.GetFields()).Msg("failed to convert to versioned header submission")
			continue
		}
		bid := common.NewBid(
			header.GetValue(),
			header.GetPayload(),
			headerSubmissionV3,
			header.GetBlockHash(),
			header.GetBuilderPubkey(),
			header.GetBuilderExtraData(),
			header.GetAccountId(),
			parentClient,
			header.GetPayloadFetchUrl(),
		)
		s.setBuilderBidForProxySlot(k, header.GetBuilderPubkey(), bid, header.GetSlot())
		storeBidsSpan.SetAttributes(
			attribute.String("method", method),
			attribute.String("nodeID", client.NodeID),
			attribute.String("url", client.URL),
			attribute.String("reqID", id),
			attribute.String("blockValue", new(big.Int).SetBytes(header.GetValue()).String()),
			attribute.String("relayReceiveAt", header.GetRelayReceiveTime().AsTime().String()),
			attribute.String("streamSentAt", header.GetSendTime().AsTime().String()),
			attribute.Int64("streamLatencyInMs", latency),

			attribute.String("keyForCachingBids", k),
			attribute.Int64("slot", int64(header.GetSlot())),
			attribute.String("in.ParentHash", header.GetParentHash()),
			attribute.String("blockHash", header.GetBlockHash()),
			attribute.String("pubKey", header.GetPubkey()),
			attribute.String("builderPubKey", header.GetBuilderPubkey()),
			attribute.String("extraData", header.GetBuilderExtraData()),
			attribute.String("traceID", parentSpan.SpanContext().TraceID().String()),
			attribute.String("uniqueKey", uKey),
			attribute.String("receivedAt", receivedAt.String()),
			attribute.Bool("paidBlxr", header.GetPaidBlxr()),
			attribute.String("accountID", header.GetAccountId()),
			attribute.String("payloadFetchUrl", header.GetPayloadFetchUrl()),
		)
		if duplicateReceiveTime > 0 {
			storeBidsSpan.SetAttributes(
				attribute.String("blockHash", header.GetBlockHash()),
				attribute.Int64("receivedAt", duplicateReceiveTime),
				attribute.Int64("addedAt", addedAt),
				attribute.Int64("diff", duplicateReceiveTime-addedAt),
				attribute.String("source", source),
			)
		}
		storeBidsSpan.End(trace.WithTimestamp(time.Now()))
	}

	<-done
	streamReceiveSpan.End(trace.WithTimestamp(time.Now()))

	s.logger.Warn().Fields(logMetric.GetFields()).Msg("closing connection")
	return nil, nil
}

func (s *Service) GetHeader(ctx context.Context, log *zerolog.Logger, in *HeaderRequestParams) (json.RawMessage, error) {
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
		return nil, toErrorResp(http.StatusNoContent, err.Error())
	}

	_, parseUintHeaderSpan := s.tracer.Start(ctx, "getHeader-parseUint")
	_slot, err := fastParseUint(in.Slot)
	if err != nil {
		parseUintHeaderSpan.End(trace.WithTimestamp(time.Now()))
		preStoringHeaderSpan.End(trace.WithTimestamp(time.Now()))
		return nil, toErrorResp(http.StatusNoContent, errInvalidSlot.Error())
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
		return nil, toErrorResp(http.StatusNoContent, errInvalidPubkey.Error())
	}

	if len(in.ParentHash) != 66 {
		storingHeaderSpan.End(trace.WithTimestamp(time.Now()))
		return nil, toErrorResp(http.StatusNoContent, errInvalidHash.Error())
	}

	fetchGetHeaderStartTime := time.Now().UTC()
	keyForCachingBids := s.keyForCachingBids(_slot, in.ParentHash, in.PubKey)
	slotBestHeader, err := s.GetTopBuilderBid(keyForCachingBids)
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
		return nil, toErrorResp(http.StatusNoContent, "Header value is not present")
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
	return json.RawMessage(signedHeaderResponse), nil
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
	defer span.End()

	if fields.client != nil {
		clientURL = fields.client.SafeClient.URL
	}

	uKey := fmt.Sprintf("slot_%v_bHash_%v_pHash_%v", fields.slot, fields.blockHash, fields.parentHash)

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
	defer fetchSpan.End()

	fetchSpan.SetAttributes(
		attribute.Int64("slot", int64(fields.slot)),
		attribute.String("blockHash", fields.blockHash),
		attribute.String("parentHash", fields.parentHash),
		attribute.String("proposerPubkey", fields.proposerPubKey),
		attribute.String("builderPubkey", fields.builderPubKey),
	)

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

func (s *Service) validateAndFetchPayload(ctx context.Context, signedBlindedBeaconBlock *common.VersionedSignedBlindedBeaconBlock) (*common.VersionedPayloadInfo, *ErrorResp) {
	slot, err := signedBlindedBeaconBlock.Slot()
	if err != nil {
		return nil, toErrorResp(http.StatusBadRequest, "failed to get slot")
	}

	blockHash, err := signedBlindedBeaconBlock.ExecutionBlockHash()
	if err != nil {
		return nil, toErrorResp(http.StatusBadRequest, "failed to get block hash")
	}
	blockHashString := blockHash.String()

	parentHash, err := signedBlindedBeaconBlock.ExecutionParentHash()
	if err != nil {
		return nil, toErrorResp(http.StatusBadRequest, "failed to get parent hash")
	}

	_, checkRequestTimingSpan := s.tracer.Start(ctx, "validateAndFetchPayload-checkRequestTiming")

	slotStartTime := GetSlotStartTime(s.beaconGenesisTime, int64(slot), s.secondsPerSlot)
	msIntoSlot := time.Since(slotStartTime).Milliseconds()

	if msIntoSlot < 0 {
		_msSinceSlotStart := time.Now().UTC().UnixMilli() - slotStartTime.UnixMilli()
		if _msSinceSlotStart < 0 {
			delayMillis := (_msSinceSlotStart * -1) + int64(rand.Intn(50))
			time.Sleep(time.Duration(delayMillis) * time.Millisecond)
		}
	} else if msIntoSlot > int64(getPayloadRequestCutoffMs) {
		checkRequestTimingSpan.End(trace.WithTimestamp(time.Now()))
		return nil, toErrorResp(http.StatusBadRequest, "timestamp too late")
	}
	checkRequestTimingSpan.End(trace.WithTimestamp(time.Now()))

	_, fetchProposerForSlotSpan := s.tracer.Start(ctx, "validateAndFetchPayload-fetchProposerForSlot")
	miniSlotDuty, err := s.IDataService.GetSlotDuty(uint64(slot))
	if err != nil || miniSlotDuty == nil {
		return nil, toErrorResp(http.StatusBadRequest, fmt.Sprintf("slot %v not found in memory", slot))
	}
	pub := miniSlotDuty.Registration.Message.Pubkey
	pubkeyStr := pub.String()

	fetchProposerForSlotSpan.End(trace.WithTimestamp(time.Now()))

	_, verifySignatureSpan := s.tracer.Start(ctx, "validateAndFetchPayload-verifySignature")
	ok, err := fastjson.CheckProposerSignature(s.ethNetworkDetails, signedBlindedBeaconBlock, pub[:])
	if !ok || err != nil {
		verifySignatureSpan.End(trace.WithTimestamp(time.Now()))
		return nil, toErrorResp(http.StatusBadRequest, "invalid signature")
	}
	verifySignatureSpan.End(trace.WithTimestamp(time.Now()))

	_, fetchPayloadFromCacheSpan := s.tracer.Start(ctx, "validateAndFetchPayload-fetchPayloadFromCache")
	proxyCacheKey := common.GetKeyForCachingPayload(uint64(slot), parentHash.String(), blockHashString, pubkeyStr)
	defer fetchPayloadFromCacheSpan.End()

	var payloadResponse *common.PayloadResponseForProxy
	var found bool

	for i := 0; i < 20; i++ { // try for 1s with 50ms interval
		if val, ok := s.getPayloadResponseForProxySlot.Get(proxyCacheKey); ok {
			casted, castOk := val.(*common.PayloadResponseForProxy)
			if castOk {
				payloadResponse = casted
				found = true
				break
			}
			break
		}
		// not found, wait and retry
		time.Sleep(50 * time.Millisecond)
	}
	if found {
		versionedPayloadInfo, err := payloadResponse.BuildVersionedPayloadInfo(uint64(slot), parentHash.String(), blockHashString, pubkeyStr)
		if err != nil {
			return nil, toErrorResp(http.StatusOK, "failed to build versioned payload info")
		}
		return versionedPayloadInfo, nil
	}

	return &common.VersionedPayloadInfo{
		Slot:       uint64(slot),
		ParentHash: parentHash.String(),
		BlockHash:  blockHashString,
		Pubkey:     pubkeyStr,
	}, toErrorResp(http.StatusOK, "pre fetch payload not available in cache after retries")

}

func (s *Service) GetPayload(ctx context.Context, log *zerolog.Logger, in *PayloadRequestParams) (*common.VersionedPayloadInfo, error) {
	startTime := time.Now().UTC()
	id := uuid.NewString()

	parentSpan := trace.SpanFromContext(ctx)
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)

	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", s.authKey)

	ctx, span := s.tracer.Start(ctx, "getPayload-start")
	defer span.End()

	_, timeToRelayRequestSpan := s.tracer.Start(ctx, "getPayload-TimeToRelayRequest")

	var latency int64
	if in.GetPayloadStartTimeUnixMS != "" {
		getPayloadStartTime, err := strconv.ParseInt(in.GetPayloadStartTimeUnixMS, 10, 64)
		if err != nil {
			s.logger.Warn().Err(err).Msg("failed to parse getPayloadStartTimeUnixMS")
		} else {
			latency = in.ReceivedAt.Sub(time.UnixMilli(getPayloadStartTime)).Milliseconds()
		}
	}

	_, logTimingSpan := s.tracer.Start(ctx, "getPayload-logTimingSpan")

	*log = log.With().
		Str("method", getPayload).
		Str("receivedAt", in.ReceivedAt.String()).
		Str("reqID", id).
		Bool("isAuthHeaderProvided", in.AuthHeader != "").
		Logger()

	log.Info().Msg("received getPayload")
	parentSpan.SetAttributes(
		attribute.String("method", getPayload),
		attribute.String("reqID", id),
		attribute.Int64("receivedAt", in.ReceivedAt.Unix()),
	)
	logTimingSpan.End()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		errResp  ErrorRespWithPayload
		errChan  = make(chan ErrorRespWithPayload, len(s.clients)+1)
		respChan = make(chan *common.VersionedPayloadInfo, len(s.clients)+1)
		wg       sync.WaitGroup
	)

	// Prefetch goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		blindedBeaconBlock, errRes := s.prefetchPayloadToSignedBlindedBeaconBlock(ctx, in.Payload)
		if errRes != nil {
			log.Info().Err(errRes).Msg("validateAndFetchPayload failed")
			errChan <- ErrorRespWithPayload{err: errRes, resp: nil}
			return
		}

		slot, err := blindedBeaconBlock.Slot()
		if err != nil {
			log.Error().Err(err).Msg("validateAndFetchPayload: failed to decode slot")
			errChan <- ErrorRespWithPayload{err: toErrorResp(http.StatusBadRequest, "failed to get slot"), resp: nil}
			return
		}
		blockHash, err := blindedBeaconBlock.ExecutionBlockHash()
		if err != nil {
			log.Error().Err(err).Msg("validateAndFetchPayload: failed to decode block hash")
			errChan <- ErrorRespWithPayload{err: toErrorResp(http.StatusBadRequest, "failed to get block hash"), resp: nil}
			return
		}
		parentHash, err := blindedBeaconBlock.ExecutionParentHash()
		if err != nil {
			log.Error().Err(err).Msg("validateAndFetchPayload: failed to decode parent hash")
			errChan <- ErrorRespWithPayload{err: toErrorResp(http.StatusBadRequest, "failed to get parent hash"), resp: nil}
			return
		}
		slotInt := int64(slot)
		blockHashStr := blockHash.String()
		parentHashStr := parentHash.String()
		uKey := fmt.Sprintf("slot_%v_bHash_%v_pHash_%v", slotInt, blockHashStr, parentHashStr)

		parentSpan.SetAttributes(
			attribute.Int64("slot", slotInt),
			attribute.String("blockHash", blockHashStr),
			attribute.String("parentHash", parentHashStr),
			attribute.String("uniqueKey", uKey),
		)
		*log = log.With().
			Int64("slot", slotInt).
			Str("blockHash", blockHashStr).
			Str("parentHash", parentHashStr).
			Str("uniqueKey", uKey).
			Logger()

		payloadInfo, errRes := s.validateAndFetchPayload(ctx, blindedBeaconBlock)

		if errRes != nil {
			errChan <- ErrorRespWithPayload{err: errRes, resp: payloadInfo}
			log.Info().Err(errRes).Msg("validateAndFetchPayload failed")
			return
		}

		log.Info().Msg("validateAndFetchPayload success (prefetch)")
		respChan <- payloadInfo
	}()

	// Relay requests
	req := &relaygrpc.GetPayloadRequest{
		ReqId:       id,
		Payload:     in.Payload,
		ClientIp:    in.ClientIP,
		Version:     s.version,
		ReceivedAt:  timestamppb.New(in.ReceivedAt),
		SecretToken: s.secretToken,
	}

	timeToRelayRequestSpan.End()
	ctx, payloadResponseSpan := s.tracer.Start(ctx, "getPayload-payloadResponseFromRelay")

	for _, client := range s.clients {
		wg.Add(1)
		go func(c *common.ParentClient) {
			defer wg.Done()
			out, err := s.getPayloadWithRetry(ctx, c.SafeClient, span, req, maxGetPayloadRetry)
			if err != nil {
				log.Error().Err(err).Msg("getPayloadWithRetry")
				errChan <- ErrorRespWithPayload{err: err, resp: out}
				return
			}
			log.Info().Msg("getPayloadWithRetry success")
			respChan <- out
		}(client)
	}

	// Channel closer
	go func() {
		wg.Wait()
		close(errChan)
		close(respChan)
	}()

	expected := len(s.clients) + 1
	responses := 0

	for responses < expected {
		select {
		case <-ctx.Done():
			go s.sendPayloadStats(in.Payload, log, false, nil, in.ReceivedAt, startTime, time.Now(), 0, id, in.ClientIP, in.ValidatorID, in.AccountID, latency, in.Cluster, in.UserAgent, in.SlotUID)
			log.Error().Msg("failed to getPayload")
			payloadResponseSpan.End()
			return nil, toErrorResp(http.StatusInternalServerError, ctx.Err().Error())

		case resp := <-respChan:
			//cancel() // Cancel other goroutines on success
			slotStartTime := GetSlotStartTime(s.beaconGenesisTime, int64(resp.Slot), s.secondsPerSlot)
			msIntoSlot := in.ReceivedAt.Sub(slotStartTime).Milliseconds()
			duration := time.Since(startTime)

			go s.sendPayloadStats(in.Payload, log, true, resp, in.ReceivedAt, startTime, slotStartTime, msIntoSlot, id, in.ClientIP, in.ValidatorID, in.AccountID, latency, in.Cluster, in.UserAgent, in.SlotUID)

			uKey := fmt.Sprintf("slot_%v_bHash_%v_pHash_%v", resp.Slot, resp.BlockHash, resp.ParentHash)
			*log = log.With().
				Dur("duration", duration).
				Int64("slot", int64(resp.Slot)).
				Int64("slotStartTime", slotStartTime.UnixMilli()).
				Int64("msIntoSlot", msIntoSlot).
				Str("parentHash", resp.ParentHash).
				Str("blockHash", resp.BlockHash).
				Str("blockValue", resp.BlockValue).
				Str("uniqueKey", uKey).
				Logger()
			parentSpan.SetAttributes(
				attribute.String("duration", duration.String()),
				attribute.Int64("slot", int64(resp.Slot)),
				attribute.Int64("slotStartTime", slotStartTime.UnixMilli()),
				attribute.Int64("msIntoSlot", msIntoSlot),
				attribute.String("parentHash", resp.ParentHash),
				attribute.String("blockHash", resp.BlockHash),
				attribute.String("blockValue", resp.BlockValue),
				attribute.String("uniqueKey", uKey),
			)
			payloadResponseSpan.End()
			return resp, nil

		case errResp = <-errChan:
			// if multiple client return errors, first error gets replaced by the subsequent errors
			responses++
		}
	}

	// All responses failed
	go s.sendPayloadStats(in.Payload, log, false, errResp.resp, in.ReceivedAt, startTime, time.Now(), 0, id, in.ClientIP, in.ValidatorID, in.AccountID, latency, in.Cluster, in.UserAgent, in.SlotUID)
	payloadResponseSpan.End(trace.WithTimestamp(time.Now()))
	parentSpan.SetAttributes(
		attribute.String("getPayloadErr", errResp.err.Message),
	)
	return nil, errResp.err
}

func (s *Service) GetPayloadTrusted(ctx context.Context, log *zerolog.Logger, in *PayloadRequestParams) (*common.VersionedPayloadInfo, error) {
	startTime := time.Now().UTC()
	id := uuid.NewString()

	parentSpan := trace.SpanFromContext(ctx)
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)

	authKey := s.authKey
	if in.AuthHeader != "" {
		authKey = in.AuthHeader
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", authKey)

	ctx, span := s.tracer.Start(ctx, "getPayload-start")
	defer span.End()

	_, timeToRelayRequestSpan := s.tracer.Start(ctx, "getPayload-TimeToRelayRequest")

	var latency int64
	if in.GetPayloadStartTimeUnixMS != "" {
		if getPayloadStartTime, err := strconv.ParseInt(in.GetPayloadStartTimeUnixMS, 10, 64); err == nil {
			latency = in.ReceivedAt.Sub(time.UnixMilli(getPayloadStartTime)).Milliseconds()
		} else {
			log.Warn().Err(err).Msg("failed to parse getPayloadStartTimeUnixMS")
		}
	}

	_, logTimingSpan := s.tracer.Start(ctx, "getPayload-logTimingSpan")
	*log = log.With().
		Str("method", getPayloadTrusted).
		Time("receivedAt", in.ReceivedAt).
		Str("reqID", id).
		Bool("isAuthHeaderProvided", in.AuthHeader != "").
		Logger()
	log.Info().Msg("received getPayloadTrusted")
	parentSpan.SetAttributes(
		attribute.String("method", getPayload),
		attribute.String("reqID", id),
		attribute.Int64("receivedAt", in.ReceivedAt.Unix()),
	)
	log.Info().Msg("added spans getPayloadTrusted")
	logTimingSpan.End()

	req := &relaygrpc.GetPayloadRequest{
		ReqId:       id,
		Payload:     in.Payload,
		ClientIp:    in.ClientIP,
		Version:     s.version,
		ReceivedAt:  timestamppb.New(in.ReceivedAt),
		SecretToken: s.secretToken,
	}
	timeToRelayRequestSpan.End()

	blindedBeaconBlock, errRes := s.prefetchPayloadToSignedBlindedBeaconBlock(ctx, in.Payload)
	if errRes != nil {
		log.Error().Err(errRes).Msg("prefetchPayloadToSignedBlindedBeaconBlock failed")
		go s.sendPayloadStats(in.Payload, log, false, nil, in.ReceivedAt, startTime, time.Now(), 0, id, in.ClientIP, in.ValidatorID, in.AccountID, latency, in.Cluster, in.UserAgent, in.SlotUID)
		return nil, errRes
	}

	payloadInfoChan := make(chan *common.VersionedPayloadInfo, 1)

	// Start validateAndFetchPayload
	go func() {
		payloadInfo, err := s.validateAndFetchPayload(ctx, blindedBeaconBlock)
		if err == nil {
			select {
			case payloadInfoChan <- payloadInfo:
			default:
			}
		}
	}()

	// Send getPayloadWithRetry requests to all clients
	for _, client := range s.clients {
		go func(c *common.ParentClient) {
			resp, err := s.getPayloadWithRetry(ctx, c.SafeClient, span, req, maxGetPayloadRetry)
			if err == nil && resp != nil {
				select {
				case payloadInfoChan <- resp:
				default:
				}
			}
		}(client)
	}

	select {
	case payloadInfo := <-payloadInfoChan:
		slotStartTime := GetSlotStartTime(s.beaconGenesisTime, int64(payloadInfo.Slot), s.secondsPerSlot)
		msIntoSlot := in.ReceivedAt.Sub(slotStartTime).Milliseconds()
		duration := time.Since(startTime)
		go s.sendPayloadStats(in.Payload, log, true, payloadInfo, in.ReceivedAt, startTime, slotStartTime, msIntoSlot, id, in.ClientIP, in.ValidatorID, in.AccountID, latency, in.Cluster, in.UserAgent, in.SlotUID)
		*log = log.With().
			Dur("duration", duration).
			Int64("slotStartTime", slotStartTime.UnixMilli()).
			Int64("msIntoSlot", msIntoSlot).
			Str("blockValue", payloadInfo.BlockValue).
			Logger()
		parentSpan.SetAttributes(
			attribute.String("duration", duration.String()),
			attribute.Int64("slotStartTime", slotStartTime.UnixMilli()),
			attribute.Int64("msIntoSlot", msIntoSlot),
			attribute.String("blockValue", payloadInfo.BlockValue),
		)
		go func() {
			if s.blockPublishFunc != nil {
				s.blockPublishFunc(s.tracer, s.logger, payloadInfo, blindedBeaconBlock, s.blockPublishingGatewayClient, s.gatewayAuthKey)
			}
		}()
		return payloadInfo, nil
	case <-time.After(1 * time.Second):
	}
	log.Error().Msg("timeout waiting for payload response")
	go s.sendPayloadStats(in.Payload, log, false, nil, in.ReceivedAt, startTime, time.Now(), 0, id, in.ClientIP, in.ValidatorID, in.AccountID, latency, in.Cluster, in.UserAgent, in.SlotUID)
	return nil, toErrorResp(http.StatusOK, "pre fetch payload not available in cache after retries")
}

type ErrorRespWithPayload struct {
	err  *ErrorResp
	resp *common.VersionedPayloadInfo
}

func (s *Service) getPayloadWithRetry(ctx context.Context, c *common.Client, parentSpan trace.Span, req *relaygrpc.GetPayloadRequest, retryCount int) (*common.VersionedPayloadInfo, *ErrorResp) {
	for attempt := 0; attempt <= retryCount; attempt++ {
		_, clientGetPayloadSpan := s.tracer.Start(ctx, "getPayloadWithRetry-getPayloadForClient")
		clientCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		resp, err := c.GetPayload(clientCtx, req)
		cancel()
		clientGetPayloadSpan.End(trace.WithTimestamp(time.Now()))

		if err == nil && resp != nil {
			if resp.GetCode() == uint32(codes.OK) {
				return common.BuildVersionedPayloadInfoFromGrpcResponse(resp), nil
			}
			if resp.GetMessage() != "could not find requested payload" {
				parentSpan.SetStatus(otelcodes.Error, resp.Message)
				uKey := fmt.Sprintf("slot_%v_bHash_%v_pHash_%v", resp.GetSlot(), resp.GetBlockHash(), resp.GetParentHash())
				clientGetPayloadSpan.SetAttributes(
					attribute.String("relayError", resp.Message),
					attribute.String("url", c.URL),
					attribute.Int64("slot", int64(resp.GetSlot())),
					attribute.String("BlockHash", resp.GetBlockHash()),
					attribute.String("in.ParentHash", resp.GetParentHash()),
					attribute.String("BlockValue", resp.GetBlockValue()),
					attribute.String("uniqueKey", uKey),
				)
				return common.BuildVersionedPayloadInfoFromGrpcResponse(resp), toErrorResp(http.StatusBadRequest, resp.Message)
			}
		}

		if attempt < retryCount {
			time.Sleep(getPayloadInterval)
			continue
		}

		if err != nil {
			parentSpan.SetStatus(otelcodes.Error, err.Error())
			return nil, toErrorResp(http.StatusInternalServerError, err.Error())
		}
		if resp == nil {
			parentSpan.SetStatus(otelcodes.Error, "empty response from relay")
			return nil, toErrorResp(http.StatusInternalServerError, "empty response from relay")
		}

		parentSpan.SetStatus(otelcodes.Error, resp.Message)
		uKey := fmt.Sprintf("slot_%v_bHash_%v_pHash_%v", resp.GetSlot(), resp.GetBlockHash(), resp.GetParentHash())
		clientGetPayloadSpan.SetAttributes(
			attribute.String("relayError", resp.Message),
			attribute.String("url", c.URL),
			attribute.Int64("slot", int64(resp.GetSlot())),
			attribute.String("BlockHash", resp.GetBlockHash()),
			attribute.String("in.ParentHash", resp.GetParentHash()),
			attribute.String("BlockValue", resp.GetBlockValue()),
			attribute.String("uniqueKey", uKey),
		)
		return common.BuildVersionedPayloadInfoFromGrpcResponse(resp), toErrorResp(http.StatusBadRequest, resp.Message)
	}

	return nil, toErrorResp(http.StatusInternalServerError, "all relay retries failed")
}

func (s *Service) sendPayloadStats(payload []byte, log *zerolog.Logger, isSucceeded bool, resp *common.VersionedPayloadInfo, receivedAt, startTime, slotStartTime time.Time, msIntoSlot int64, id, clientIP, validatorID, accountID string, latency int64, cluster, userAgent, slotUID string) {
	// 3 different scenario calling sendPayload stats
	// case 1 : resp success
	// case 2: Err case with resp
	// case 2: Err case with no resp
	out := resp.Copy()
	if out.GetSlot() != 0 {
		slotStartTime = GetSlotStartTime(s.beaconGenesisTime, int64(out.GetSlot()), s.secondsPerSlot)
		msIntoSlot = receivedAt.Sub(slotStartTime).Milliseconds()
	}
	if out == nil {
		decodedPayload := new(common.VersionedSignedBlindedBeaconBlock)
		if err := json.NewDecoder(bytes.NewReader(payload)).Decode(decodedPayload); err != nil {
			log.Warn().Msg("failed to decode getPayload request")
			return
		} else {
			_slot, err := decodedPayload.Slot()
			if err != nil {
				log.Warn().Err(err).Msg("failed to decode getPayload slot")
				return
			} else {
				out = new(common.VersionedPayloadInfo)
				out.SetSlot(uint64(_slot))
				slotStartTime = GetSlotStartTime(s.beaconGenesisTime, int64(out.Slot), s.secondsPerSlot)
				msIntoSlot = receivedAt.Sub(slotStartTime).Milliseconds()
				_blockHash, err := decodedPayload.ExecutionBlockHash()
				if err != nil {
					log.Warn().Err(err).Msg("failed to decode getPayload BlockHash")
				} else {
					out.SetBlockHash(_blockHash.String())
					parentHash, err := decodedPayload.ExecutionParentHash()
					if err != nil {
						log.Warn().Err(err).Msg("failed to decode getPayload parentHash")
					} else {
						out.SetParentHash(parentHash.String())
					}
				}
			}
		}
	}

	statsUserAgent := userAgent
	if cluster != "" {
		statsUserAgent = fmt.Sprintf("%s/%s", statsUserAgent, cluster)
	}

	statsRecord := SlotStatsRecord{
		PayloadReqID:              id,
		PayloadReqReceivedAt:      receivedAt,
		PayloadReqDuration:        time.Since(startTime),
		PayloadReqDurationInMs:    time.Since(startTime).Milliseconds(),
		PayloadMsIntoSlot:         msIntoSlot,
		PayloadSucceeded:          isSucceeded,
		PayloadDeliveredBlockHash: out.GetBlockHash(),
		PayloadBlockValue:         out.GetBlockValue(),
		PayloadUserAgent:          statsUserAgent,
		Slot:                      out.GetSlot(),
		ParentHash:                out.GetParentHash(),
		PubKey:                    out.GetPubkey(),
		SlotStartTime:             slotStartTime,
		ClientIP:                  clientIP,
		NodeID:                    s.nodeID,
		AccountID:                 accountID,
		ValidatorID:               validatorID,
		GetPayloadLatency:         latency,
		PayloadSlotUID:            slotUID,
	}
	var (
		isRelayProxyWin bool
		//isSlotUIDMatch  bool
		fallback SlotStatsRecord
	)
	k := fmt.Sprintf("slot-%v-parentHash-%v", out.GetSlot(), out.GetParentHash())
	v, ok := s.slotStats.Get(k)
	if ok {
		if records, success := v.([]SlotStatsRecord); success {
			for i, record := range records {
				if i == len(records)-1 {
					fallback = record
				}
				if record.HeaderDeliveredBlockHash == out.GetBlockHash() {
					mergeSlotStats(&record, &statsRecord)
					isRelayProxyWin = true
					//isSlotUIDMatch = record.HeaderSlotUID == statsRecord.PayloadSlotUID
					break
				}
				if !isRelayProxyWin {
					mergeSlotStats(&fallback, &statsRecord)
				}
			}
		}
	} else {
		log.Warn().Str("slotKey", k).Msg("no previous slot stats found, creating new record")
	}
	s.slotStatsEvent.Set(k, statsRecord, cache.DefaultExpiration) // replace with updated slot stats

	if isRelayProxyWin {
		log.Info().Str("slotKey", k).Msg("emit slot won event")
		s.fluentD.LogToFluentD(fluentstats.Record{
			Type: TypeRelayProxySlotWon,
			Data: statsRecord,
		}, time.Now().UTC(), s.nodeID, StatsRelayProxySlotWon)
	}

	payloadStats := GetPayloadStatsRecord{
		RequestReceivedAt: receivedAt,
		Duration:          time.Since(startTime),
		SlotStartTime:     slotStartTime,
		MsIntoSlot:        msIntoSlot,
		Slot:              out.GetSlot(),
		ParentHash:        out.GetParentHash(),
		PubKey:            out.GetPubkey(),
		BlockHash:         out.GetBlockHash(),
		BlockValue:        out.GetBlockValue(),
		ReqID:             id,
		ClientIP:          clientIP,
		Succeeded:         true,
		NodeID:            s.nodeID,
		AccountID:         accountID,
		ValidatorID:       validatorID,
		Latency:           latency,
		UserAgent:         statsUserAgent,
	}

	s.fluentD.LogToFluentD(fluentstats.Record{
		Type: TypeRelayProxyGetPayload,
		Data: payloadStats,
	}, time.Now().UTC(), s.nodeID, StatsRelayProxyGetPayload)
}
func mergeSlotStats(record *SlotStatsRecord, statsRecord *SlotStatsRecord) {
	statsRecord.HeaderReqID = record.HeaderReqID
	statsRecord.HeaderReqReceivedAt = record.HeaderReqReceivedAt
	statsRecord.HeaderReqDuration = record.HeaderReqDuration
	statsRecord.HeaderReqDurationInMs = record.HeaderReqDurationInMs
	statsRecord.HeaderMsIntoSlot = record.HeaderMsIntoSlot
	statsRecord.HeaderMsIntoSlotWithDelay = record.HeaderMsIntoSlotWithDelay
	statsRecord.HeaderDelayInMs = record.HeaderDelayInMs
	statsRecord.HeaderMaxDelayInMs = record.HeaderMaxDelayInMs
	statsRecord.HeaderSucceeded = record.HeaderSucceeded
	statsRecord.HeaderDeliveredBlockHash = record.HeaderDeliveredBlockHash
	statsRecord.HeaderBlockValue = record.HeaderBlockValue
	statsRecord.HeaderUserAgent = record.HeaderUserAgent
	statsRecord.PubKey = record.PubKey
	statsRecord.GetHeaderLatency = record.GetHeaderLatency
	statsRecord.HeaderStartTimeUnixMs = record.HeaderStartTimeUnixMs
	statsRecord.HeaderSlotUID = record.HeaderSlotUID

	statsRecord.AccountID = record.AccountID
	statsRecord.ValidatorID = record.ValidatorID
	return
}

func (s *Service) keyForCachingBids(slot uint64, parentHash string, proposerPubkey string) string {
	return fmt.Sprintf("%d_%s_%s", slot, strings.ToLower(parentHash), strings.ToLower(proposerPubkey))
}

func (s *Service) GetTopBuilderBid(cacheKey string) (*common.Bid, error) {
	var builderBidsMap *SyncMap[string, *common.Bid]
	entry, bidsMapFound := s.builderBidsForProxySlot.Get(cacheKey)
	if bidsMapFound {
		builderBidsMap = entry.(*SyncMap[string, *common.Bid])
	}

	if !bidsMapFound || builderBidsMap == nil || builderBidsMap.Size() == 0 {
		return nil, fmt.Errorf("no builder bids found for cache key %s", cacheKey)
	}

	topBid := new(common.Bid)
	topBidValue := new(big.Int)

	// search for the highest builder bid
	builderBidsMap.Range(func(builderPubkey string, bid *common.Bid) bool {
		bidValue := new(big.Int).SetBytes(bid.Value)
		if bidValue.Cmp(topBidValue) > 0 {
			topBid = bid
			topBidValue.Set(bidValue)
		}
		return true
	})

	return topBid, nil
}

func (s *Service) setBuilderBidForProxySlot(cacheKey string, builderPubkey string, bid *common.Bid, slot uint64) {

	var builderBidsMap *SyncMap[string, *common.Bid]

	// if the cache key does not exist, create a new syncmap and store it in the cache
	if entry, bidsMapFound := s.builderBidsForProxySlot.Get(cacheKey); !bidsMapFound {
		builderBidsMap = NewStringMapOf[*common.Bid]()
		s.builderBidsForProxySlot.Set(cacheKey, builderBidsMap, cache.DefaultExpiration)
	} else {
		// otherwise use the existing syncmap
		builderBidsMap = entry.(*SyncMap[string, *common.Bid])
	}
	slotDuty, err := s.IDataService.GetSlotDuty(slot)
	replace := true
	if err != nil || slotDuty == nil {
		if err != common.ErrNoProposerSlotMap {
			s.logger.Warn().Err(err).Uint64("slot", slot).Msg("failed to get slot duty")
		}
	} else {
		replace = slotDuty.IsOptedIn
	}

	// disable bid replacement
	if !replace {
		if bidEntry, found := builderBidsMap.Load(builderPubkey); found {
			bidValue := new(big.Int).SetBytes(bid.Value)
			bidValueExist := new(big.Int).SetBytes(bidEntry.Value)
			if bidValueExist.Cmp(bidValue) > 0 {
				return
			}
		}
	}
	builderBidsMap.Store(builderPubkey, bid)
}

// This is only used for testing
func (s *Service) getBuilderBidForSlot(cacheKey string, builderPubkey string) (*common.Bid, bool) {
	if entry, bidsMapFound := s.builderBidsForProxySlot.Get(cacheKey); bidsMapFound {
		builderBidsMap := entry.(*SyncMap[string, *common.Bid])
		builderBid, found := builderBidsMap.Load(builderPubkey)
		return builderBid, found
	}
	return nil, false
}

func (s *Service) EmitSlotStats(ctx context.Context) {
	for {
		select {
		case event := <-s.slotStatsEventCh:
			go func() {
				now := time.Now().UTC()
				t := GetSlotStartTime(s.beaconGenesisTime, event.Slot, s.secondsPerSlot)

				//if t.Add(time.Second * 12).Before(now) {
				//	s.logger.Warn("omitting past slots event", zap.String("slotKey", event.SlotKey))
				//	return
				//}

				timer := time.NewTimer(t.Sub(now) + time.Second*12) // wait from slot start time and until slot completes
				defer timer.Stop()
				select {
				case <-timer.C:
					v, ok := s.slotStatsEvent.Get(event.SlotKey)
					if ok { //Populated when getPayloadOnly is called
						record, success := v.(SlotStatsRecord)
						if success {
							s.logRecord(record, event.SlotKey, event.UserAgent)
						} else {
							slotStats, found := s.slotStats.Get(event.SlotKey)
							if found {
								if records, slotStatsSuccess := slotStats.([]SlotStatsRecord); slotStatsSuccess {
									slotStatsRecord := records[len(records)-1]
									s.logRecord(slotStatsRecord, event.SlotKey, event.UserAgent)
								}
							}
						}
					} else {
						slotStats, found := s.slotStats.Get(event.SlotKey)
						if found {
							if records, slotStatsSuccess := slotStats.([]SlotStatsRecord); slotStatsSuccess {
								slotStatsRecord := records[len(records)-1]
								s.logRecord(slotStatsRecord, event.SlotKey, event.UserAgent)
							}
						}
					}
				case <-ctx.Done():
					return
				}
			}()

		case <-ctx.Done():
			s.logger.Info().Msg("closing slot stats events")
			return
		}
	}
}

func (s *Service) StartStreamBlocks(ctx context.Context, wg *sync.WaitGroup) {
	for _, client := range s.streamingBlockClients {
		wg.Add(1)
		go func(_ctx context.Context, c *common.ParentClient) {
			defer wg.Done()
			s.handleBlockStream(_ctx, c)
		}(ctx, client)
	}
	go s.handleForwardedBlockResponse()
	wg.Wait()
}

func (s *Service) handleBlockStream(ctx context.Context, client *common.ParentClient) {
	parentSpan := trace.SpanFromContext(ctx)
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)
	_, span := s.tracer.Start(ctx, "handleBlockStream-streamBlock")
	defer span.End(trace.WithTimestamp(time.Now().UTC()))

	traceID := parentSpan.SpanContext().TraceID().String()

	span.SetAttributes(
		attribute.String("method", "streamBlock"),
		attribute.String("url", client.SafeClient.URL),
		attribute.String("traceID", traceID),
	)

	var lastConnectTime time.Time

	for {
		select {
		case <-ctx.Done():
			s.logger.Warn().
				Str("traceID", traceID).
				Msg("stream block context cancelled")
			return
		default:
			active, safe := client.GetActiveClient(lastConnectTime)
			if safe {
				s.logger.Warn().Str("method", "streamBlock").Str("fastURL", client.FastClient.URL).Str("safeURL", client.SafeClient.URL).Msg("Fallback to safe IP used")
			}
			lastConnectTime = time.Now()
			if _, err := s.StreamBlock(ctx, active); err != nil {
				s.logger.Warn().
					Str("url", active.URL).
					Str("traceID", traceID).
					Err(err).
					Msg("failed to stream block. Sleeping and then reconnecting")

				span.SetAttributes(
					attribute.Int64("sleepingFor", reconnectTime),
					attribute.String("error", err.Error()),
				)
			} else {
				s.logger.Warn().
					Str("url", active.URL).
					Str("traceID", traceID).
					Msg("stream block stopped. Sleeping and then reconnecting")

				span.SetAttributes(
					attribute.Int64("sleepingFor", reconnectTime),
					attribute.String("error", "stream header stopped."),
				)
			}
			time.Sleep(reconnectTime * time.Millisecond)
		}
	}
}

func (s *Service) StreamBlock(ctx context.Context, client *common.Client) (*relaygrpc.StreamBlockResponse, error) {
	parentSpan := trace.SpanFromContext(ctx)
	method := "streamBlock"
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", s.authKey)
	_, port, err := net.SplitHostPort(s.listenAddress)
	if err != nil {
		s.logger.Warn().Err(err).Msg("failed to split host port")
		return nil, err
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "listenAddress", port)
	ctx = metadata.AppendToOutgoingContext(ctx, "grpcListenAddress", s.GrpcListenAddress)
	streamBlockCtx, span := s.tracer.Start(ctx, "streamBlock-start")
	defer span.End(trace.WithTimestamp(time.Now().UTC()))
	id := uuid.NewString()
	client.NodeID = fmt.Sprintf("%v-%v-%v-%v", s.nodeID, client.URL, id, time.Now().UTC().Format("15:04:05.999999999"))
	stream, err := client.StreamBlock(ctx, &relaygrpc.StreamBlockRequest{
		ReqId:       id,
		NodeId:      client.NodeID,
		Version:     s.version,
		SecretToken: s.secretToken,
	})
	logMetric := NewLogMetric(
		map[string]any{
			"method": method,
			"nodeID": client.NodeID,
			"reqID":  id,
			"url":    client.URL,
		},
	)
	span.SetAttributes(
		attribute.String("method", method),
		attribute.String("nodeID", client.NodeID),
		attribute.String("url", client.URL),
		attribute.String("reqID", id),
	)

	s.logger.Info().Fields(logMetric.GetFields()).Msg("streaming blocks")
	if err != nil {
		logMetric.Error(err)
		s.logger.Warn().Fields(logMetric.GetFields()).Msg("failed to stream block")
		span.SetStatus(otelcodes.Error, err.Error())
		return nil, err
	}
	done := make(chan struct{})
	var once sync.Once
	closeDone := func() {
		once.Do(func() {
			s.logger.Info().Msg("calling close done once")
			close(done)
		})
	}
	logMetricCopy := logMetric.Copy()
	go func(lm *LogMetric) {
		select {
		case <-stream.Context().Done():
			lm.Error(stream.Context().Err())
			s.logger.Warn().Fields(lm.GetFields()).Msg("stream context cancelled, closing connection")
			closeDone()
		case <-ctx.Done():
			logMetric.Error(ctx.Err())
			s.logger.Warn().Fields(lm.GetFields()).Msg("context cancelled, closing connection")
			closeDone()
		}
	}(logMetricCopy)

	_, streamReceiveSpan := s.tracer.Start(streamBlockCtx, "StreamBlock-streamReceive")
	clientIP := GetHost(client.URL)
	for {
		select {
		case <-done:
			return nil, nil
		default:
		}
		block, err := stream.Recv()
		receivedAt := time.Now().UTC()
		if err == io.EOF {
			s.logger.Warn().Err(err).Fields(logMetric.GetFields()).Msg("stream received EOF")
			streamReceiveSpan.SetStatus(otelcodes.Error, err.Error())
			closeDone()
			break
		}
		_s, ok := status.FromError(err)
		if !ok {
			s.logger.Warn().Err(err).Fields(logMetric.GetFields()).Msg("invalid grpc error status")
			streamReceiveSpan.SetStatus(otelcodes.Error, "invalid grpc error status")
			continue
		}

		if _s.Code() == codes.Canceled {
			logMetric.Error(err)
			s.logger.Warn().Err(err).Fields(logMetric.GetFields()).Msg("received cancellation signal, shutting down")
			// mark as canceled to stop the upstream retry loop
			streamReceiveSpan.SetStatus(otelcodes.Error, "received cancellation signal")
			closeDone()
			break
		}

		if _s.Code() != codes.OK {
			s.logger.Warn().Err(_s.Err()).Str("code", _s.Code().String()).Fields(logMetric.GetFields()).Msg("server unavailable,try reconnecting")
			streamReceiveSpan.SetStatus(otelcodes.Error, "server unavailable,try reconnecting")
			closeDone()
			break
		}
		if err != nil {
			s.logger.Warn().Err(err).Fields(logMetric.GetFields()).Msg("failed to receive stream, disconnecting the stream")
			streamReceiveSpan.SetStatus(otelcodes.Error, err.Error())
			closeDone()
			break
		}
		// Added empty streaming as a temporary workaround to maintain streaming alive
		// TODO: this need to be handled by adding settings for keep alive params on both server and client
		if block.GetBlockHash() == "" {
			s.logger.Warn().Fields(logMetric.GetFields()).Msg("received empty stream")
			continue
		}
		latency := receivedAt.Sub(block.GetSendTime().AsTime()).Milliseconds()
		processTime := time.Since(receivedAt).Milliseconds()
		go s.handleStreamBlockResponse(streamBlockCtx, block, logMetric, receivedAt, latency, parentSpan.SpanContext().TraceID().String(), method, clientIP, processTime)
	}
	<-done
	streamReceiveSpan.End(trace.WithTimestamp(time.Now()))

	s.logger.Warn().Fields(logMetric.GetFields()).Msg("closing connection")
	return nil, nil
}

func (s *Service) handleForwardedBlockResponse() {
	s.logger.Info().Msg("start handling forwarded block response")
	for forwardedBlockInfo := range *s.forwardedBlockCh {
		// s.logger.Info().Msg("received forwarded block from channel")

		lm := NewLogMetric(
			map[string]any{
				"method": forwardedBlockInfo.Method,
			},
		)
		if forwardedBlockInfo.Block == nil || forwardedBlockInfo.Block.GetBlockHash() == "" {
			s.logger.Warn().Fields(lm.GetFields()).Msg("received empty forwarded block")
			continue
		}
		go s.handleStreamBlockResponse(
			forwardedBlockInfo.Context,
			forwardedBlockInfo.Block,
			lm,
			forwardedBlockInfo.ReceivedAt,
			forwardedBlockInfo.Latency,
			forwardedBlockInfo.TraceID,
			forwardedBlockInfo.Method,
			forwardedBlockInfo.ClientIP,
			forwardedBlockInfo.ProcessTime,
		)
	}
	s.logger.Info().Msg("stop handling forwarded block response")
}

func (s *Service) handleStreamBlockResponse(
	ctx context.Context,
	block *relaygrpc.StreamBlockResponse,
	logMetric *LogMetric,
	receivedAt time.Time,
	latency int64,
	traceId string,
	method string,
	clientIP string,
	processTime int64,
) {
	// check if the block hash has already been received
	handleStart := time.Now().UTC()
	lm := logMetric.Copy()

	k := s.keyForCachingBids(block.GetSlot(), block.GetParentHash(), block.GetPubkey())
	uKey := fmt.Sprintf("slot_%v_bHash_%v_pHash_%v", block.GetSlot(), block.GetBlockHash(), block.GetParentHash())
	payloadSize := len(block.GetPayload())
	payloadType := ""
	extraData := block.GetBuilderExtraData()

	lm.Fields(map[string]any{
		"keyForCachingBids": k,
		"slot":              block.GetSlot(),
		"parentHash":        block.GetParentHash(),
		"blockHash":         block.GetBlockHash(),
		"pubKey":            block.GetPubkey(),
		"builderPubKey":     block.GetBuilderPubkey(),
		"extraData":         extraData,
		"traceID":           traceId,
		"uniqueKey":         uKey,
		"receivedAt":        receivedAt,
		"paidBlxr":          block.GetPaidBlxr(),
		"accountID":         block.GetAccountId(),
		"streamLatencyInMs": latency,
		"processLatency":    processTime,
		"httpPayloadSize":   int64(payloadSize),
	})

	spanCtx, span := s.tracer.Start(ctx, "handleStreamBlockResponse")
	diff := int64(0)
	defer func() {
		handleTime := time.Since(handleStart).Milliseconds()
		span.SetAttributes(
			attribute.String("keyForCachingBids", k),
			attribute.Int64("slot", int64(block.GetSlot())),
			attribute.String("parentHash", block.GetParentHash()),
			attribute.String("blockHash", block.GetBlockHash()),
			attribute.String("pubKey", block.GetPubkey()),
			attribute.String("builderPubKey", block.GetBuilderPubkey()),
			attribute.String("extraData", extraData),
			attribute.String("traceID", traceId),
			attribute.String("blockHash", block.GetBlockHash()),
		)
		span.End()
		go s.logBlockReceivedStream(
			block,
			receivedAt,
			latency,
			clientIP,
			method,
			payloadType,
			processTime,
			diff,
			handleTime,
			int64(payloadSize),
			extraData,
		)
	}()

	if val, exist := s.builderExistingBlockHash.Get(block.GetBlockHash()); exist {
		var addedAt int64
		var source string
		if v, ok := val.(common.DuplicateBlock); ok {
			addedAt = v.Time
			source = v.Source
		}
		duplicateReceiveTime := time.Now().UTC().UnixMilli()
		diff := duplicateReceiveTime - addedAt
		lm.Fields(map[string]any{
			"addedAt":              addedAt,
			"duplicateReceiveTime": duplicateReceiveTime,
			"diff":                 diff,
			"source":               source,
		})
		span.SetAttributes(
			attribute.Int64("diff", diff),
			attribute.Int64("addedAt", addedAt),
			attribute.String("source", source),
		)
		s.logger.Warn().Fields(lm.GetFields()).Msg("block hash already exist")
		return
	}

	grpcPayload := block.GetGrpcPayload()
	httpPayload := block.GetPayload()
	submitBlockRequest := new(common.VersionedSubmitBlockRequest)
	_, unmarshalSpan := s.tracer.Start(spanCtx, "handleStreamBlockResponse-unmarshal")
	if grpcPayload != nil {
		submission, err := relaygrpc.ProtoRequestToVersionedRequest(grpcPayload)
		if err != nil {
			s.logger.Error().Err(err).Msg("could not convert block to versioned block")
			unmarshalSpan.End()
			return
		}
		submitBlockRequest = &common.VersionedSubmitBlockRequest{VersionedSubmitBlockRequest: *submission}
		payloadType = "grpc"
	} else if httpPayload != nil {
		payloadType = "json"
		if err := submitBlockRequest.UnmarshalJSON(httpPayload); err != nil {
			if err := submitBlockRequest.UnmarshalSSZ(httpPayload); err != nil {
				s.logger.Error().Err(err).Msg("could not decode ssz http payload")
				unmarshalSpan.End()
				return
			}
			payloadType = "ssz"
		}
	} else {
		s.logger.Error().Msg("empty payload")
		return
	}
	unmarshalSpan.End()

	lm.Fields(map[string]any{
		"blockValue":     new(big.Int).SetBytes(block.GetValue()).String(),
		"relayReceiveAt": block.GetRelayReceiveTime().AsTime(),
		"streamSentAt":   block.GetSendTime().AsTime(),
		"payloadType":    payloadType,
	})
	span.SetAttributes(
		attribute.String("blockValue", new(big.Int).SetBytes(block.GetValue()).String()),
		attribute.String("relayReceiveAt", block.GetRelayReceiveTime().AsTime().String()),
		attribute.String("streamSentAt", block.GetSendTime().AsTime().String()),
		attribute.String("payloadType", payloadType),
	)

	_, signSpan := s.tracer.Start(spanCtx, "handleStreamBlockResponse-sign")
	headerSubmissionV3, err := common.BuildHeaderSubmissionV3(submitBlockRequest)
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to build header submission")
		signSpan.End()
		return
	}
	relayProxyGetHeaderResponse, err := common.BuildGetHeaderResponseAndSign(headerSubmissionV3, s.secretKey, &s.publicKey, s.builderSigningDomain)
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to sign header")
		signSpan.End()
		return
	}
	signSpan.End()

	wrapped := &common.VersionedSignedBuilderBid{VersionedSignedBuilderBid: *relayProxyGetHeaderResponse}
	_, marshalSpan := s.tracer.Start(spanCtx, "handleStreamBlockResponse-marshal")
	relayProxyBidBytes, err := json.Marshal(wrapped)
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to marshal header")
		marshalSpan.End()
		return
	}
	marshalSpan.End()

	if extraData == "" {
		extraDataBytes, err := wrapped.ExtraData()
		if err != nil {
			s.logger.Error().Err(err).Msg("failed to get extra data")
		} else {
			extraData = common.DecodeExtraData(extraDataBytes)
		}
	}

	bid := common.NewBid(
		block.GetValue(),
		relayProxyBidBytes,
		headerSubmissionV3,
		block.GetBlockHash(),
		block.GetBuilderPubkey(),
		extraData,
		block.GetAccountId(),
		nil,
		"",
	)

	// update block hash map if not seen already
	s.builderExistingBlockHash.Set(block.GetBlockHash(), common.DuplicateBlock{
		Time:   time.Now().UTC().UnixMilli(),
		Source: "proxy-block-" + clientIP,
	}, cache.DefaultExpiration)

	s.logger.Info().Fields(lm.GetFields()).Msg("received streamed block")

	_, storeBidsSpan := s.tracer.Start(spanCtx, "StreamHeader-storeBids")
	s.setBuilderBidForProxySlot(k, block.GetBuilderPubkey(), bid, block.GetSlot())
	storeBidsSpan.End(trace.WithTimestamp(time.Now()))

	go func() {
		headerStream := HeaderStreamReceivedRecord{
			RelayReceivedAt:   block.GetRelayReceiveTime().AsTime(),
			ReceivedAt:        receivedAt,
			SentAt:            block.GetSendTime().AsTime(),
			StreamLatencyInMS: latency,
			Slot:              int64(block.GetSlot()),
			ParentHash:        block.GetParentHash(),
			PubKey:            block.GetPubkey(),
			BlockHash:         block.GetBlockHash(),
			BlockValue:        weiToEther(new(big.Int).SetBytes(block.GetValue())),
			BuilderPubKey:     block.GetBuilderPubkey(),
			BuilderExtraData:  extraData,
			PaidBLXR:          block.GetPaidBlxr(),
			ClientIP:          clientIP,
			NodeID:            s.nodeID,
			AccountID:         block.GetAccountId(),
			Method:            method + "-" + payloadType,
			PayloadFetchUrl:   "",
		}
		s.fluentD.LogToFluentD(fluentstats.Record{
			//UniqueKey: "block_hash__node_id",
			Type: TypeRelayProxyHeaderStreamReceived,
			Data: headerStream,
		}, time.Now().UTC(), s.nodeID, StatsRelayProxyHeaderStreamReceived)
	}()
}

func (s *Service) logBlockReceivedStream(block *relaygrpc.StreamBlockResponse, receivedAt time.Time, latency int64, clientIP string, method string, payloadType string, processLatency int64, diff int64, handleLatency int64, payloadSize int64, extraData string) {
	// log block received stream
	blockStream := BlockStreamReceivedRecord{
		RelayReceivedAt:   block.GetRelayReceiveTime().AsTime(),
		ReceivedAt:        receivedAt,
		SentAt:            block.GetSendTime().AsTime(),
		StreamLatencyInMS: latency,
		Slot:              int64(block.GetSlot()),
		ParentHash:        block.GetParentHash(),
		PubKey:            block.GetPubkey(),
		BlockHash:         block.GetBlockHash(),
		BlockValue:        weiToEther(new(big.Int).SetBytes(block.GetValue())),
		BuilderPubKey:     block.GetBuilderPubkey(),
		BuilderExtraData:  extraData,
		PaidBLXR:          block.GetPaidBlxr(),
		ClientIP:          clientIP,
		NodeID:            s.nodeID,
		AccountID:         block.GetAccountId(),
		Method:            method + "-" + payloadType,
		ProcessLatency:    processLatency,
		Diff:              diff,
		HandleLatency:     handleLatency,
		PayloadSize:       payloadSize,
	}
	s.fluentD.LogToFluentD(fluentstats.Record{
		//UniqueKey: "block_hash__node_id",
		Type: TypeRelayProxyBlockStreamReceived,
		Data: blockStream,
	}, time.Now().UTC(), s.nodeID, StatsRelayProxyBlockStreamReceived)

}

func isVouch(userAgent string) bool {
	lower := strings.ToLower(userAgent)

	return strings.Contains(lower, "vouch")
}

func (s *Service) StartStreamBuilderInfo(ctx context.Context, wg *sync.WaitGroup) {
	for _, client := range s.streamingBlockClients {
		wg.Add(1)
		go func(_ctx context.Context, c *common.ParentClient) {
			defer wg.Done()
			s.handleBuilderInfoStream(_ctx, c)
		}(ctx, client)
	}
	wg.Wait()
}
func (s *Service) handleBuilderInfoStream(ctx context.Context, client *common.ParentClient) {
	parentSpan := trace.SpanFromContext(ctx)
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)
	traceID := parentSpan.SpanContext().TraceID().String()

	var lastConnectTime time.Time
	for {
		select {
		case <-ctx.Done():
			s.logger.Warn().
				Str("traceID", traceID).
				Msg("stream block context cancelled")
			return
		default:
			active, safe := client.GetActiveClient(lastConnectTime)
			if safe {
				s.logger.Warn().Str("method", "streamBuilderInfo").Str("fastURL", client.FastClient.URL).Str("safeURL", client.SafeClient.URL).Msg("Fallback to safe IP used")
			}
			lastConnectTime = time.Now()

			if _, err := s.StreamBuilderInfo(ctx, active); err != nil {
				s.logger.Warn().
					Str("url", active.URL).
					Str("traceID", traceID).
					Err(err).
					Msg("failed to stream builderInfo. Sleeping and then reconnecting")
			} else {
				s.logger.Warn().
					Str("url", active.URL).
					Str("traceID", traceID).
					Msg("stream builderInfo stopped. Sleeping and then reconnecting")
			}
			time.Sleep(reconnectTime * time.Millisecond)
		}
	}
}

func (s *Service) StreamBuilderInfo(ctx context.Context, client *common.Client) (*relaygrpc.StreamBuilderResponse, error) {
	parentSpan := trace.SpanFromContext(ctx)
	method := "streamBuilderInfo"
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", s.authKey)

	_, port, err := net.SplitHostPort(s.listenAddress)
	if err != nil {
		s.logger.Warn().Err(err).Msg("failed to split host port")
		return nil, err
	}

	ctx = metadata.AppendToOutgoingContext(ctx, "listenAddress", port)
	ctx = metadata.AppendToOutgoingContext(ctx, "grpcListenAddress", s.GrpcListenAddress)
	streamBuilderInfoCtx, span := s.tracer.Start(ctx, "streamBuilderInfo-start")
	defer span.End()

	id := uuid.NewString()
	client.NodeID = fmt.Sprintf("%v-%v-%v-%v", s.nodeID, client.URL, id, time.Now().UTC().Format("15:04:05.999999999"))

	stream, err := client.StreamBuilder(ctx, &relaygrpc.StreamBuilderRequest{
		ReqId:   id,
		NodeId:  client.NodeID,
		Version: s.version,
	})

	logMetric := NewLogMetric(
		map[string]any{
			"method": method,
			"nodeID": client.NodeID,
			"reqID":  id,
			"url":    client.URL,
		},
	)

	s.logger.Info().Fields(logMetric.GetFields()).Msg("streaming builder info")

	if err != nil {
		logMetric.Error(err)
		s.logger.Warn().Err(err).Fields(logMetric.GetFields()).Msg("failed to stream builderInfo")
		span.SetStatus(otelcodes.Error, err.Error())
		return nil, err
	}

	done := make(chan struct{})
	var once sync.Once
	closeDone := func() {
		once.Do(func() {
			s.logger.Info().Msg("calling close done once")
			close(done)
		})
	}

	logMetricCopy := logMetric.Copy()
	go func(lm *LogMetric) {
		select {
		case <-stream.Context().Done():
			lm.Error(stream.Context().Err())
			s.logger.Warn().Fields(lm.GetFields()).Msg("stream context cancelled, closing connection")
			closeDone()
		case <-ctx.Done():
			logMetric.Error(ctx.Err())
			s.logger.Warn().Fields(logMetric.GetFields()).Msg("context cancelled, closing connection")
			closeDone()
		}
	}(logMetricCopy)

	_, streamReceiveSpan := s.tracer.Start(streamBuilderInfoCtx, "StreamBuilderInfo-streamReceived")
	clientIP := GetHost(client.URL)

	for {
		select {
		case <-done:
			return nil, nil
		default:
		}

		builderInfoResponse, err := stream.Recv()
		receivedAt := time.Now().UTC()

		if err == io.EOF {
			s.logger.Warn().Err(err).Fields(logMetric.GetFields()).Msg("stream received EOF")
			streamReceiveSpan.SetStatus(otelcodes.Error, err.Error())
			closeDone()
			break
		}

		_s, ok := status.FromError(err)
		if !ok {
			s.logger.Warn().Err(err).Fields(logMetric.GetFields()).Msg("invalid grpc error status")
			streamReceiveSpan.SetStatus(otelcodes.Error, "invalid grpc error status")
			continue
		}

		if _s.Code() == codes.Canceled {
			logMetric.Error(err)
			s.logger.Warn().Err(err).Fields(logMetric.GetFields()).Msg("received cancellation signal, shutting down")
			streamReceiveSpan.SetStatus(otelcodes.Error, "received cancellation signal")
			closeDone()
			break
		}

		if _s.Code() != codes.OK {
			s.logger.Warn().
				Err(_s.Err()).
				Str("code", _s.Code().String()).
				Fields(logMetric.GetFields()).
				Msg("server unavailable, try reconnecting")
			streamReceiveSpan.SetStatus(otelcodes.Error, "server unavailable, try reconnecting")
			closeDone()
			break
		}

		if err != nil {
			s.logger.Warn().Err(err).Fields(logMetric.GetFields()).Msg("failed to receive stream, disconnecting the stream")
			streamReceiveSpan.SetStatus(otelcodes.Error, err.Error())
			closeDone()
			break
		}

		if len(builderInfoResponse.GetBuilderInfo()) == 0 {
			s.logger.Warn().Fields(logMetric.GetFields()).Msg("received empty stream")
			continue
		}

		processTime := time.Since(receivedAt).Milliseconds()
		go s.handleStreamBuilderInfoResponse(
			streamBuilderInfoCtx,
			builderInfoResponse,
			logMetric,
			receivedAt,
			parentSpan.SpanContext().TraceID().String(),
			method,
			clientIP,
			processTime,
		)
	}

	<-done
	streamReceiveSpan.End(trace.WithTimestamp(time.Now()))
	s.logger.Warn().Fields(logMetric.GetFields()).Msg("closing connection")
	return nil, nil
}

func (s *Service) handleStreamBuilderInfoResponse(
	ctx context.Context,
	builderInfoResponse *relaygrpc.StreamBuilderResponse,
	logMetric *LogMetric,
	receivedAt time.Time,
	traceId string,
	method string,
	clientIP string,
	processTime int64,
) {
	// check if the block hash has already been received
	_, span := s.tracer.Start(ctx, "handleStreamBuilderInfoResponse")
	span.SetAttributes(
		attribute.String("clientIPAddress", clientIP),
		attribute.String("method", method),
		attribute.String("traceID", traceId),
		attribute.Int64("processTime", processTime),
	)
	defer span.End()

	handleStart := time.Now().UTC()
	lm := logMetric.Copy()
	builderInfos := builderInfoResponse.GetBuilderInfo()
	if len(builderInfos) == 0 {
		s.logger.Warn().Fields(lm.GetFields()).Msg("received empty builderInfo stream")
		return
	}

	numBuilderInfos := len(builderInfos)
	builderInfoPubkeys := make([]string, numBuilderInfos)
	optimisticBuilders := make([]string, 0, numBuilderInfos)
	demotedBuilders := make([]string, 0, numBuilderInfos)

	for i := 0; i < numBuilderInfos; i++ {
		builderInfo := builderInfos[i]
		builderPubkey := phase0.BLSPubKey(builderInfo.BuilderPubkey)
		builderPubkeyStr := builderPubkey.String()
		builderInfoPubkeys[i] = builderPubkeyStr

		grpcWalletAccounts := builderInfo.GetWalletAccounts()
		walletAccounts := make([]common.WalletAccount, 0, len(grpcWalletAccounts))
		for _, grpcWalletAccount := range grpcWalletAccounts {
			walletAccounts = append(walletAccounts, common.WalletAccount{
				Pubkey:           gethcommon.Address(grpcWalletAccount.GetPubkey()),
				Balance:          new(big.Int).SetBytes(grpcWalletAccount.GetBalance()),
				Nonce:            new(big.Int).SetUint64(grpcWalletAccount.GetNonce()),
				LastUpdatedBlock: grpcWalletAccount.GetLastUpdatedBlock(),
			})
		}

		newBuilderInfo := &common.BuilderInfo{
			BuilderPubkey:                           builderPubkey,
			IsOptimistic:                            builderInfo.IsOptimistic,
			IsDemoted:                               builderInfo.IsDemoted,
			AccountID:                               builderInfo.ExternalBuilderAccountId,
			IsBuilderPubkeyHighPriority:             builderInfo.IsBuilderPubkeyHighPriority,
			BuilderPubkeySkipSimulationThreshold:    new(big.Int).SetBytes(builderInfo.BuilderPubkeySkipSimulationThreshold),
			IsBuilderAccountIDHighPriority:          builderInfo.IsBuilderAccountIdHighPriority,
			BuilderAccountIDSkipSimulationThreshold: new(big.Int).SetBytes(builderInfo.BuilderAccountIdSkipSimulationThreshold),
			TrustedExternalBuilder:                  builderInfo.TrustedExternalBuilder,
			IsOptedIn:                               builderInfo.IsOptedIn,
			WalletAccounts:                          walletAccounts,
		}

		if builderInfo.IsDemoted {
			demotedBuilders = append(demotedBuilders, builderPubkeyStr)
		}
		if builderInfo.IsOptimistic {
			optimisticBuilders = append(optimisticBuilders, builderPubkeyStr)
		}

		for _, wallet := range newBuilderInfo.WalletAccounts {
			curWallet, found := (*s.walletAccounts)[wallet.Pubkey.String()]
			if found && curWallet != nil && curWallet.LastUpdatedBlock < wallet.LastUpdatedBlock {
				s.logger.Debug().
					Str("pubkey", wallet.Pubkey.String()).
					Uint64("lastUpdatedBlock", wallet.LastUpdatedBlock).
					Uint64("balance", wallet.Balance.Uint64()).
					Uint64("nonce", wallet.Nonce.Uint64()).
					Str("accountID", builderInfo.ExternalBuilderAccountId).
					Msg("updating wallet account")

				curWallet.Balance = wallet.Balance
				curWallet.LastUpdatedBlock = wallet.LastUpdatedBlock
				curWallet.Nonce = wallet.Nonce
			}
		}

		s.builderInfo.Set(builderPubkeyStr, newBuilderInfo, cache.DefaultExpiration)
	}

	lm.Fields(map[string]any{
		"builderInfoPubkeys": builderInfoPubkeys,
		"demotedBuilders":    demotedBuilders,
		"optimisticBuilders": optimisticBuilders,
		"receivedAt":         receivedAt,
		"duration":           time.Since(handleStart),
	})

	s.logger.Debug().Fields(lm.GetFields()).Msg("received builderInfo")
}

func (s *Service) logRecord(record SlotStatsRecord, slotKey string, userAgent string) {
	s.slotStats.Get(slotKey)
	s.logger.Info().
		Str("slotKey", slotKey).
		Str("accountID", record.AccountID).
		Str("validatorID", record.ValidatorID).
		Str("userAgent", userAgent).
		Msg("emit slot stats event")
	s.fluentD.LogToFluentD(fluentstats.Record{
		Type: TypeRelayProxySlotStats,
		Data: record,
	}, time.Now().UTC(), s.nodeID, StatsRelayProxySlotStats)
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
func (s *Service) StartStreamSlotInfo(ctx context.Context, wg *sync.WaitGroup) {
	for _, client := range s.streamingBlockClients {
		wg.Add(1)
		go func(_ctx context.Context, c *common.ParentClient) {
			defer wg.Done()
			s.handleSlotInfoStream(_ctx, c)
		}(ctx, client)
	}
	wg.Wait()
}
func (s *Service) handleSlotInfoStream(ctx context.Context, client *common.ParentClient) {
	parentSpan := trace.SpanFromContext(ctx)
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)
	traceID := parentSpan.SpanContext().TraceID().String()

	var lastConnectTime time.Time
	for {
		select {
		case <-ctx.Done():
			s.logger.Warn().
				Str("traceID", traceID).
				Msg("stream block context cancelled")
			return
		default:
			active, safe := client.GetActiveClient(lastConnectTime)
			if safe {
				s.logger.Warn().Str("method", "streamSlotInfo").Str("fastURL", client.FastClient.URL).Str("safeURL", client.SafeClient.URL).Msg("Fallback to safe IP used")
			}
			lastConnectTime = time.Now()

			if _, err := s.StreamSlotInfo(ctx, active); err != nil {
				s.logger.Warn().
					Str("url", active.URL).
					Str("traceID", traceID).
					Err(err).
					Msg("failed to stream SlotInfo. Sleeping and then reconnecting")
			} else {
				s.logger.Warn().
					Str("url", active.URL).
					Str("traceID", traceID).
					Msg("stream SlotInfo stopped. Sleeping and then reconnecting")
			}
			time.Sleep(reconnectTime * time.Millisecond)
		}
	}
}

func (s *Service) StreamSlotInfo(ctx context.Context, client *common.Client) (*relaygrpc.StreamSlotResponse, error) {
	parentSpan := trace.SpanFromContext(ctx)
	method := "streamSlotInfo"
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", s.authKey)

	_, port, err := net.SplitHostPort(s.listenAddress)
	if err != nil {
		s.logger.Warn().Err(err).Msg("failed to split host port")
		return nil, err
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "listenAddress", port)
	ctx = metadata.AppendToOutgoingContext(ctx, "grpcListenAddress", s.GrpcListenAddress)

	streamSlotInfoCtx, span := s.tracer.Start(ctx, "streamSlotInfo-start")
	defer span.End(trace.WithTimestamp(time.Now().UTC()))

	id := uuid.NewString()
	client.NodeID = fmt.Sprintf("%v-%v-%v-%v", s.nodeID, client.URL, id, time.Now().UTC().Format("15:04:05.999999999"))

	stream, err := client.StreamSlotInfo(ctx, &relaygrpc.StreamSlotRequest{
		ReqId:   id,
		NodeId:  client.NodeID,
		Version: s.version,
	})

	logMetric := NewLogMetric(
		map[string]any{
			"method": method,
			"nodeID": client.NodeID,
			"reqID":  id,
			"url":    client.URL,
		},
	)

	s.logger.Debug().Fields(logMetric.GetFields()).Msg("streaming Validator info")

	if err != nil {
		logMetric.Error(err)
		s.logger.Warn().Err(err).Fields(logMetric.GetFields()).Msg("failed to stream SlotInfo")
		span.SetStatus(otelcodes.Error, err.Error())
		return nil, err
	}

	done := make(chan struct{})
	var once sync.Once
	closeDone := func() {
		once.Do(func() {
			s.logger.Info().Msg("calling close done once")
			close(done)
		})
	}

	logMetricCopy := logMetric.Copy()
	go func(lm *LogMetric) {
		select {
		case <-stream.Context().Done():
			lm.Error(stream.Context().Err())
			s.logger.Warn().Fields(lm.GetFields()).Msg("stream context cancelled, closing connection")
			closeDone()
		case <-ctx.Done():
			logMetric.Error(ctx.Err())
			s.logger.Warn().Fields(logMetric.GetFields()).Msg("context cancelled, closing connection")
			closeDone()
		}
	}(logMetricCopy)

	_, streamReceiveSpan := s.tracer.Start(streamSlotInfoCtx, "StreamSlotInfo-streamReceived")
	clientIP := GetHost(client.URL)

	for {
		select {
		case <-done:
			return nil, nil
		default:
		}

		SlotInfoResponse, err := stream.Recv()
		receivedAt := time.Now().UTC()

		if err == io.EOF {
			s.logger.Warn().Err(err).Fields(logMetric.GetFields()).Msg("stream received EOF")
			streamReceiveSpan.SetStatus(otelcodes.Error, err.Error())
			closeDone()
			break
		}

		_s, ok := status.FromError(err)
		if !ok {
			s.logger.Warn().Err(err).Fields(logMetric.GetFields()).Msg("invalid grpc error status")
			streamReceiveSpan.SetStatus(otelcodes.Error, "invalid grpc error status")
			continue
		}

		if _s.Code() == codes.Canceled {
			logMetric.Error(err)
			s.logger.Warn().Err(err).Fields(logMetric.GetFields()).Msg("received cancellation signal, shutting down")
			streamReceiveSpan.SetStatus(otelcodes.Error, "received cancellation signal")
			closeDone()
			break
		}

		if _s.Code() != codes.OK {
			s.logger.Warn().
				Err(_s.Err()).
				Str("code", _s.Code().String()).
				Fields(logMetric.GetFields()).
				Msg("server unavailable, try reconnecting")
			streamReceiveSpan.SetStatus(otelcodes.Error, "server unavailable, try reconnecting")
			closeDone()
			break
		}

		if err != nil {
			s.logger.Warn().Err(err).Fields(logMetric.GetFields()).Msg("failed to receive stream, disconnecting the stream")
			streamReceiveSpan.SetStatus(otelcodes.Error, err.Error())
			closeDone()
			break
		}

		if SlotInfoResponse == nil || SlotInfoResponse.LastUpdatedBlock == 0 {
			s.logger.Warn().Fields(logMetric.GetFields()).Msg("received empty stream")
			continue
		}

		processTime := time.Since(receivedAt).Milliseconds()
		go s.handleStreamSlotInfoResponse(streamSlotInfoCtx, SlotInfoResponse, logMetric, receivedAt, parentSpan.SpanContext().TraceID().String(), method, clientIP, processTime)
	}

	<-done
	streamReceiveSpan.End(trace.WithTimestamp(time.Now()))
	s.logger.Warn().Fields(logMetric.GetFields()).Msg("closing connection")

	return nil, nil
}

func (s *Service) handleStreamSlotInfoResponse(
	ctx context.Context,
	SlotInfoResponse *relaygrpc.StreamSlotResponse,
	logMetric *LogMetric,
	receivedAt time.Time,
	traceId string,
	method string,
	clientIP string,
	processTime int64,
) {
	_, span := s.tracer.Start(ctx, "handleStreamSlotInfoResponse")
	span.SetAttributes(
		attribute.String("clientIPAddress", clientIP),
		attribute.String("method", method),
		attribute.String("traceID", traceId),
		attribute.Int64("processTime", processTime),
	)
	defer span.End()
	lm := logMetric.Copy()

	proposerPubkey := phase0.BLSPubKey(SlotInfoResponse.GetProposerPubkey())
	proposerFeeRecipient := bellatrix.ExecutionAddress(SlotInfoResponse.GetProposerFeeRecipient())
	isEOA := SlotInfoResponse.IsEoa
	slot := SlotInfoResponse.GetSlot()
	lastUpdatedBlock := SlotInfoResponse.GetLastUpdatedBlock()
	parentBlockRoot := phase0.Root(SlotInfoResponse.GetParentBlockRoot())

	oldProposer, found := s.miniProposerSlotMap.Load(slot)

	lm.Fields(map[string]any{
		"proposerPubkey":   proposerPubkey.String(),
		"slot":             slot,
		"feeRecipient":     proposerFeeRecipient.String(),
		"lastUpdatedBlock": lastUpdatedBlock,
		"parentBlockRoot":  parentBlockRoot.String(),
		"isEOA":            isEOA,
	})

	lm.Attributes(
		attribute.String("proposerPubkey", proposerPubkey.String()),
		attribute.Int64("slot", int64(slot)),
		attribute.String("feeRecipient", proposerFeeRecipient.String()),
		attribute.Int64("lastUpdatedBlock", int64(lastUpdatedBlock)),
		attribute.String("parentBlockRoot", parentBlockRoot.String()),
		attribute.Bool("isEOA", isEOA),
	)

	if !found || oldProposer == nil {
		s.logger.Error().Fields(lm.GetFields()).Msg("slot not found in mini proposer slot map")
		return
	}

	lm.Fields(map[string]any{
		"oldProposerPubkey":           oldProposer.Registration.Message.Pubkey.String(),
		"oldProposerFeeRecipient":     oldProposer.Registration.Message.FeeRecipient.String(),
		"oldProposerLastUpdatedBlock": int64(oldProposer.LastUpdatedBlock),
		"oldProposerIsEOA":            strconv.FormatBool(oldProposer.IsEOA),
	})

	lm.Attributes(
		attribute.String("oldProposerPubkey", oldProposer.Registration.Message.Pubkey.String()),
		attribute.String("oldProposerFeeRecipient", oldProposer.Registration.Message.FeeRecipient.String()),
		attribute.Int64("oldProposerLastUpdatedBlock", int64(oldProposer.LastUpdatedBlock)),
		attribute.String("oldProposerIsEOA", strconv.FormatBool(oldProposer.IsEOA)),
	)

	switch {
	case oldProposer.Registration.Message.Pubkey != proposerPubkey:
		s.logger.Error().Fields(lm.GetFields()).Msg("slot pubkey mismatch")
	case oldProposer.Registration.Message.FeeRecipient != proposerFeeRecipient:
		s.logger.Error().Fields(lm.GetFields()).Msg("slot fee recipient mismatch")
	default:
		if oldProposer.LastUpdatedBlock < lastUpdatedBlock {
			oldProposer.IsEOA = isEOA
			oldProposer.LastUpdatedBlock = lastUpdatedBlock
			oldProposer.ExpectedParentBlockRoot = parentBlockRoot
			s.miniProposerSlotMap.Store(slot, oldProposer)
			s.logger.Debug().Fields(lm.GetFields()).Msg("updating mini proposer slot map")
		}
	}

	s.logger.Debug().Fields(lm.GetFields()).Msg("received slot")
}
