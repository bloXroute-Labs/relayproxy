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
	"time"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	relaygrpc "github.com/bloXroute-Labs/relay-grpc"
	"github.com/bloXroute-Labs/relayproxy/common"
	"github.com/bloXroute-Labs/relayproxy/fastjson"
	"github.com/bloXroute-Labs/relayproxy/fluentstats"
	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
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

	prefetchAttempts = 20
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
	RegisterValidator(ctx context.Context, outgoingCtx context.Context, in *RegistrationParams) (any, *LogMetric, error)
	GetHeader(ctx context.Context, in *HeaderRequestParams) (any, *LogMetric, error)
	GetPayload(ctx context.Context, in *PayloadRequestParams) (any, *LogMetric, error)
}
type Service struct {
	logger      *zap.Logger
	version     string // build version
	nodeID      string // UUID
	authKey     string
	secretToken string

	tracer                         trace.Tracer
	fluentD                        fluentstats.Stats
	builderBidsForProxySlot        *cache.Cache
	builderExistingBlockHash       *cache.Cache
	getPayloadResponseForProxySlot *cache.Cache
	pubKeysBySlots                 *cache.Cache
	preFetchPayloadChan            chan preFetcherFields

	beaconGenesisTime  int64
	secondsPerSlot     int64
	slotStats          *cache.Cache
	slotStatsEvent     *cache.Cache
	duplicateSlotCache *cache.Cache
	slotStatsEventCh   chan slotStatsEvent
	ethNetworkDetails  *common.EthNetworkDetails

	clients                       []*common.Client
	streamingClients              []*common.Client
	streamingBlockClients         []*common.Client
	registrationClients           []*common.Client
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
	// data service
	IDataService
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
	pubKey          string
	blockValue      string
	client          *common.Client
	payloadFetchUrl string
}

func NewService(opts ...ServiceOption) *Service {

	svc := &Service{
		pubKeysBySlots:                cache.New(ExecutionPayloadCleanupInterval, ExecutionPayloadCleanupInterval),
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

func (s *Service) RegisterValidator(ctx context.Context, outgoingCtx context.Context, in *RegistrationParams) (any, *LogMetric, error) {
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
	logMetric := NewLogMetric(
		[]zap.Field{
			zap.String("method", "registerValidator"),
			zap.String("in.ClientIP", in.ClientIP),
			zap.String("reqID", id),
			zap.String("traceID", parentSpan.SpanContext().TraceID().String()),
			zap.Time("receivedAt", in.ReceivedAt),
			zap.String("in.ValidatorID", in.ValidatorID),
			zap.String("accountID", in.AccountID),
			zap.String("secretToken", s.secretToken),
			zap.String("authHeader", in.AuthHeader),
			zap.Bool("proposerMevProtect", in.ProposerMevProtect),
		},
		[]attribute.KeyValue{
			attribute.String("method", "registerValidator"),
			attribute.String("in.ClientIP", in.ClientIP),
			attribute.String("reqID", id),
			attribute.String("in.ValidatorID", in.ValidatorID),
			attribute.String("traceID", parentSpan.SpanContext().TraceID().String()),
			attribute.Int64("receivedAt", in.ReceivedAt.Unix()),
			attribute.String("authHeader", in.AuthHeader),
			attribute.Bool("proposerMevProtect", in.ProposerMevProtect),
		},
	)
	s.logger.Info("received registration", logMetric.GetFields()...)

	span.SetAttributes(logMetric.GetAttributes()...)
	//TODO: For now using relay proxy auth-header to allow every validator to connect  But this needs to be updated in the future to  use validator auth header.
	ctx, spanWaitForResponse := s.tracer.Start(ctx, "RegisterValidator-waitForResponse")

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
	go func(_ctx context.Context, req *relaygrpc.RegisterValidatorRequest) {
		out, err := s.registerValidatorForClient(ctx, req)
		if err != nil {
			errChan <- err
			return
		}
		respChan <- out
	}(ctx, req)
	spanWaitForResponse.End(trace.WithTimestamp(time.Now()))

	ctx, spanWaitForSuccessfulResponse := s.tracer.Start(ctx, "RegisterValidator-waitForSuccessfulResponse")
	// Wait for the first successful response or until all responses are processed
	select {
	case <-ctx.Done():
		logMetric.Error(ctx.Err())
		logMetric.String("relayError", "failed to register")
		return nil, logMetric, toErrorResp(http.StatusInternalServerError, ctx.Err().Error(), logMetric.GetFields()...)
	case _err = <-errChan:
		// if multiple client return errors, first error gets replaced by the subsequent errors
	case <-respChan:
		return struct{}{}, logMetric, nil
	case <-timer.C:
		s.logger.Error("timer hit: relay request timeout", logMetric.GetFields()...)
		return struct{}{}, logMetric, nil
	}
	spanWaitForSuccessfulResponse.End(trace.WithTimestamp(time.Now()))

	if _err != nil {
		logMetric.Error(errors.New(_err.Message))
		logMetric.Fields(_err.fields...)
		if _err.Code == http.StatusRequestTimeout {
			s.logger.Info("relay request timeout", logMetric.GetFields()...)
			return struct{}{}, logMetric, nil
		}
	}

	return nil, logMetric, _err
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

		out, err = selectedRelay.RegisterValidator(_ctx, req)
		url := selectedRelay.URL
		if err != nil || out == nil || out.Code != uint32(codes.OK) {
			s.logger.Warn("failed to register validator", zap.String("url", url), zap.Error(err))
			continue
		}

		regSpan.SetStatus(otelcodes.Ok, "relay returned success response code")
		regSpan.End()
		return out, nil
	}
	if err != nil {
		regSpan.SetStatus(otelcodes.Error, err.Error())
		regSpan.End()
		if strings.Contains(err.Error(), errContextDeadlineString) {
			return nil, toErrorResp(http.StatusRequestTimeout, "relay requests timeout")
		}
		return nil, toErrorResp(http.StatusInternalServerError, "relays returned error", zap.String("relayError", err.Error()))
	}
	if out == nil {
		regSpan.SetStatus(otelcodes.Error, errors.New("empty response from relay").Error())
		regSpan.End()
		return nil, toErrorResp(http.StatusInternalServerError, "empty response from relay")
	}
	if out.Code != uint32(codes.OK) {
		regSpan.SetStatus(otelcodes.Error, errors.New("relay returned failure response code").Error())
		regSpan.End()
		return nil, toErrorResp(http.StatusBadRequest, "relay returned failure response code", zap.String("relayError", out.Message))
	}
	return nil, toErrorResp(http.StatusInternalServerError, "no relay client available")
}

func (s *Service) StartStreamHeaders(ctx context.Context, wg *sync.WaitGroup) {

	for _, client := range s.streamingClients {
		wg.Add(1)
		go func(_ctx context.Context, c *common.Client) {
			defer wg.Done()
			s.handleStream(_ctx, c)
		}(ctx, client)
	}
	wg.Wait()
}

func (s *Service) handleStream(ctx context.Context, client *common.Client) {
	parentSpan := trace.SpanFromContext(ctx)
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)
	_, span := s.tracer.Start(ctx, "handleStream-streamHeader")
	defer span.End(trace.WithTimestamp(time.Now().UTC()))

	span.SetAttributes(
		attribute.String("method", "streamHeader"),
		attribute.String("url", client.URL),
		attribute.String("traceID", parentSpan.SpanContext().TraceID().String()),
	)

	for {
		select {
		case <-ctx.Done():
			s.logger.Warn("stream header context cancelled",
				zap.String("traceID", parentSpan.SpanContext().TraceID().String()),
			)
			return
		default:
			if _, err := s.StreamHeader(ctx, client); err != nil {
				s.logger.Warn("failed to stream header. Sleeping and then reconnecting",
					zap.String("url", client.URL),
					zap.String("traceID", parentSpan.SpanContext().TraceID().String()),
					zap.Error(err))
				span.SetAttributes(attribute.KeyValue{Key: "sleepingFor", Value: attribute.Int64Value(reconnectTime)}, attribute.KeyValue{Key: "error", Value: attribute.StringValue(err.Error())})
			} else {
				s.logger.Warn("stream header stopped.  Sleeping and then reconnecting",
					zap.String("url", client.URL),
					zap.String("traceID", parentSpan.SpanContext().TraceID().String()),
				)
				span.SetAttributes(attribute.KeyValue{Key: "sleepingFor", Value: attribute.Int64Value(reconnectTime)}, attribute.KeyValue{Key: "error", Value: attribute.StringValue("stream header stopped.")})
			}
			time.Sleep(reconnectTime * time.Millisecond)
		}
	}
}

func (s *Service) StreamHeader(ctx context.Context, client *common.Client) (*relaygrpc.StreamHeaderResponse, error) {
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
		[]zap.Field{
			zap.String("method", method),
			zap.String("nodeID", client.NodeID),
			zap.String("reqID", id),
			zap.String("url", client.URL),
		},
		[]attribute.KeyValue{
			attribute.String("method", method),
			attribute.String("nodeID", client.NodeID),
			attribute.String("url", client.URL),
			attribute.String("reqID", id),
		},
	)
	span.SetAttributes(logMetric.GetAttributes()...)

	s.logger.Info("streaming headers", logMetric.GetFields()...)
	if err != nil {
		logMetric.Error(err)
		s.logger.Warn("failed to stream header", logMetric.GetFields()...)
		span.SetStatus(otelcodes.Error, err.Error())
		return nil, err
	}
	done := make(chan struct{})
	var once sync.Once
	closeDone := func() {
		once.Do(func() {
			s.logger.Info("calling close done once")
			close(done)
		})
	}
	logMetricCopy := logMetric.Copy()
	go func(lm *LogMetric) {
		select {
		case <-stream.Context().Done():
			lm.Error(stream.Context().Err())
			s.logger.Warn("stream context cancelled, closing connection", lm.GetFields()...)
			closeDone()
		case <-ctx.Done():
			logMetric.Error(ctx.Err())
			s.logger.Warn("context cancelled, closing connection", lm.GetFields()...)
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
			s.logger.With(zap.Error(err)).Warn("stream received EOF", logMetric.GetFields()...)
			streamReceiveSpan.SetStatus(otelcodes.Error, err.Error())
			closeDone()
			break
		}
		_s, ok := status.FromError(err)
		if !ok {
			s.logger.With(zap.Error(err)).Warn("invalid grpc error status", logMetric.GetFields()...)
			streamReceiveSpan.SetStatus(otelcodes.Error, "invalid grpc error status")
			continue
		}

		if _s.Code() == codes.Canceled {
			logMetric.Error(err)
			s.logger.With(zap.Error(err)).Warn("received cancellation signal, shutting down", logMetric.GetFields()...)
			// mark as canceled to stop the upstream retry loop
			streamReceiveSpan.SetStatus(otelcodes.Error, "received cancellation signal")
			closeDone()
			break
		}

		if _s.Code() != codes.OK {
			s.logger.With(zap.Error(_s.Err())).With(zap.String("code", _s.Code().String())).Warn("server unavailable,try reconnecting", logMetric.GetFields()...)
			streamReceiveSpan.SetStatus(otelcodes.Error, "server unavailable,try reconnecting")
			closeDone()
			break
		}
		if err != nil {
			s.logger.With(zap.Error(err)).Warn("failed to receive stream, disconnecting the stream", logMetric.GetFields()...)
			streamReceiveSpan.SetStatus(otelcodes.Error, err.Error())
			closeDone()
			break
		}
		// Added empty streaming as a temporary workaround to maintain streaming alive
		// TODO: this need to be handled by adding settings for keep alive params on both server and client
		if header.GetBlockHash() == "" {
			s.logger.Warn("received empty stream", logMetric.GetFields()...)
			continue
		}

		// check if the block hash has already been received
		lm := logMetric.Copy()

		k := s.keyForCachingBids(header.GetSlot(), header.GetParentHash(), header.GetPubkey())
		uKey := fmt.Sprintf("slot_%v_bHash_%v_pHash_%v", header.GetSlot(), header.GetBlockHash(), header.GetParentHash())
		lm.Fields(
			zap.String("keyForCachingBids", k),
			zap.Uint64("slot", header.GetSlot()),
			zap.String("in.ParentHash", header.GetParentHash()),
			zap.String("blockHash", header.GetBlockHash()),
			zap.String("pubKey", header.GetPubkey()),
			zap.String("builderPubKey", header.GetBuilderPubkey()),
			zap.String("extraData", header.GetBuilderExtraData()),
			zap.String("traceID", parentSpan.SpanContext().TraceID().String()),
			zap.String("uniqueKey", uKey),
			zap.Time("receivedAt", receivedAt),
			zap.Bool("paidBlxr", header.GetPaidBlxr()),
			zap.String("accountID", header.GetAccountId()),
			zap.String("payloadFetchUrl", header.GetPayloadFetchUrl()),
		)
		lm.Attributes(
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

		if val, exist := s.builderExistingBlockHash.Get(header.GetBlockHash()); exist {
			var addedAt int64
			var source string
			if v, ok := val.(common.DuplicateBlock); ok {
				addedAt = v.Time
				source = v.Source
			}
			duplicateReceiveTime := time.Now().UTC().UnixMilli()
			lm.Fields(
				zap.Int64("receivedAt", duplicateReceiveTime),
				zap.Int64("addedAt", addedAt),
				zap.Int64("diff", duplicateReceiveTime-addedAt),
				zap.String("source", source))
			lm.Attributes(attribute.String("blockHash", header.GetBlockHash()),
				attribute.Int64("receivedAt", duplicateReceiveTime),
				attribute.Int64("addedAt", addedAt),
				attribute.Int64("diff", duplicateReceiveTime-addedAt),
				attribute.String("source", source))

			s.logger.Warn("block hash already exist", lm.GetFields()...)
			streamReceiveSpan.AddEvent("blockHashAlreadyExist", trace.WithAttributes(lm.GetAttributes()...))
			continue
		}
		// update block hash map if not seen already
		s.builderExistingBlockHash.Set(header.GetBlockHash(), common.DuplicateBlock{
			Time:   time.Now().UTC().UnixMilli(),
			Source: "proxy-header-" + GetHost(client.URL),
		}, cache.DefaultExpiration)
		lm.Fields(
			zap.String("blockValue", new(big.Int).SetBytes(header.GetValue()).String()),
			zap.Time("relayReceiveAt", header.GetRelayReceiveTime().AsTime()),
			zap.Time("streamSentAt", header.GetSendTime().AsTime()),
			zap.Int64("streamLatencyInMs", time.Since(header.GetSendTime().AsTime()).Milliseconds()),
		)
		lm.Attributes(
			attribute.String("blockValue", new(big.Int).SetBytes(header.GetValue()).String()),
			attribute.String("relayReceiveAt", header.GetRelayReceiveTime().AsTime().String()),
			attribute.String("streamSentAt", header.GetSendTime().AsTime().String()),
			attribute.Int64("streamLatencyInMs", latency),
		)

		s.logger.Info("received header", lm.GetFields()...)

		go func() {
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
			s.fluentD.LogToFluentD(fluentstats.Record{
				//UniqueKey: "block_hash__node_id",
				Type: TypeRelayProxyHeaderStreamReceived,
				Data: headerStream,
			}, time.Now().UTC(), s.nodeID, StatsRelayProxyHeaderStreamReceived)
		}()
		_, storeBidsSpan := s.tracer.Start(streamReceiveCtx, "StreamHeader-storeBids")
		// store the bid for builder pubkey
		payloadURL := "grpc;" + client.URL
		headerSubmissionV3, err := common.RelayGrpcHeaderSubmissionToVersioned(header, []byte(payloadURL))
		if err != nil && header.GetPayload() == nil {
			s.logger.Error("failed to convert to versioned header submission", logMetric.GetFields()...)
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
			client,
			header.GetPayloadFetchUrl(),
		)
		s.setBuilderBidForProxySlot(k, header.GetBuilderPubkey(), bid, header.GetSlot()) // run it in goroutine ?
		storeBidsSpan.SetAttributes(lm.GetAttributes()...)
		storeBidsSpan.End(trace.WithTimestamp(time.Now()))
	}
	<-done
	streamReceiveSpan.SetAttributes(logMetric.GetAttributes()...)
	streamReceiveSpan.End(trace.WithTimestamp(time.Now()))

	s.logger.Warn("closing connection", logMetric.GetFields()...)
	return nil, nil
}

func (s *Service) GetHeader(ctx context.Context, in *HeaderRequestParams) (any, *LogMetric, error) {
	id := uuid.NewString()
	parentSpan := trace.SpanFromContext(ctx)
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)
	ctx, span := s.tracer.Start(ctx, "getHeader-start")
	defer span.End(trace.WithTimestamp(time.Now()))

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

	logMetric := NewLogMetric(
		[]zap.Field{
			zap.String("method", getHeader),
			zap.Time("receivedAt", in.ReceivedAt),
			zap.String("clientIP", in.ClientIP),
			zap.String("reqID", id),
			zap.String("validatorID", in.ValidatorID),
			zap.String("accountID", in.AccountID),
			zap.String("key", k),
			zap.String("traceID", parentSpan.SpanContext().TraceID().String()),
			zap.String("slot", in.Slot),
			zap.Int64("slotStartTimeUnix", slotStartTime.Unix()),
			zap.String("slotStartTime", slotStartTime.UTC().String()),
			zap.Int64("sleep", sleep),
			zap.Int64("maxSleep", maxSleep),
			zap.Int64("latency", latency),
			zap.String("authHeader", in.AuthHeader),
		},
		[]attribute.KeyValue{
			attribute.String("method", getHeader),
			attribute.String("clientIP", in.ClientIP),
			attribute.String("req", id),
			attribute.String("validatorID", in.ValidatorID),
			attribute.String("accountID", in.AccountID),
			attribute.Int64("receivedAt", in.ReceivedAt.Unix()),
			attribute.String("key", k),
			attribute.String("traceID", parentSpan.SpanContext().TraceID().String()),
			attribute.String("slot", in.Slot),
			attribute.Int64("slotStartTimeUnix", slotStartTime.Unix()),
			attribute.String("slotStartTime", slotStartTime.UTC().String()),
			attribute.Int64("sleep", sleep),
			attribute.Int64("maxSleep", maxSleep),
			attribute.Int64("latency", latency),
			attribute.String("authHeader", in.AuthHeader),
		},
	)
	s.logger.Info("received getHeader", logMetric.GetFields()...)
	if err != nil {
		preStoringHeaderSpan.End(trace.WithTimestamp(time.Now()))
		logMetric.String("proxyError", err.Error())
		return nil, logMetric, toErrorResp(http.StatusNoContent, err.Error())
	}
	_, parseUintHeaderSpan := s.tracer.Start(ctx, "getHeader-parseUint")
	_slot, err := fastParseUint(in.Slot)
	if err != nil {
		logMetric.String("proxyError", "invalid slot "+in.Slot)
		parseUintHeaderSpan.End(trace.WithTimestamp(time.Now()))
		preStoringHeaderSpan.End(trace.WithTimestamp(time.Now()))
		return nil, logMetric, toErrorResp(http.StatusNoContent, errInvalidSlot.Error())
	}
	parseUintHeaderSpan.End(trace.WithTimestamp(time.Now()))

	_, slotTimeMeasureSpan := s.tracer.Start(ctx, "getHeader-slotTimeMeasure")
	msIntoSlotIncludingDelay := time.Since(slotStartTime).Milliseconds()
	msIntoSlot := in.ReceivedAt.Sub(slotStartTime).Milliseconds() // without sleep and using received at
	logMetric.Time("slotStartTime", slotStartTime)
	logMetric.Int64("msTntoSlot", msIntoSlot)
	logMetric.Int64("msIntoSlotIncludingDelay", msIntoSlotIncludingDelay)
	slotTimeMeasureSpan.End(trace.WithTimestamp(time.Now()))

	span.SetAttributes(logMetric.GetAttributes()...)
	preStoringHeaderSpan.End(trace.WithTimestamp(time.Now()))

	_, storingHeaderSpan := s.tracer.Start(ctx, "getHeader-storingHeader")
	//TODO: send fluentd stats for StatusNoContent error cases

	if len(in.PubKey) != 98 {
		storingHeaderSpan.End(trace.WithTimestamp(time.Now()))
		logMetric.String("proxyError", fmt.Sprintf("pub key should be %d long", 98))
		return nil, logMetric, toErrorResp(http.StatusNoContent, errInvalidPubkey.Error())
	}

	if len(in.ParentHash) != 66 {
		storingHeaderSpan.End(trace.WithTimestamp(time.Now()))
		logMetric.String("proxyError", fmt.Sprintf("parent hash should be %d long", 66))
		return nil, logMetric, toErrorResp(http.StatusNoContent, errInvalidHash.Error())
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
		logMetric.String("proxyError", msg)
		return nil, logMetric, toErrorResp(http.StatusNoContent, "Header value is not present")
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
	logMetric.String("blockHash", slotBestHeader.BlockHash)
	logMetric.String("blockValue", blockValue.String())
	logMetric.String("uniqueKey", uKey)
	storingHeaderSpan.SetAttributes(logMetric.GetAttributes()...)
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

			Slot:             _slot,
			SlotStartTime:    slotStartTime,
			ParentHash:       in.ParentHash,
			PubKey:           in.PubKey,
			ClientIP:         in.ClientIP,
			NodeID:           s.nodeID,
			AccountID:        in.AccountID,
			ValidatorID:      in.ValidatorID,
			GetHeaderLatency: latency,
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
		pubKey:          in.PubKey,
		blockValue:      weiToEther(blockValue),
		client:          slotBestHeader.Client,
		payloadFetchUrl: slotBestHeader.PayloadFetchUrl,
	}

	signedHeaderResponse, prevSigned, err := slotBestHeader.GetSignedHeaderResponse(s.secretKey, &s.publicKey, s.builderSigningDomain)
	if err != nil {
		logMetric.Error(err)
		s.logger.Info("failed to get signed header", logMetric.GetFields()...)
	}
	if prevSigned {
		s.logger.Info("previously signed header", logMetric.GetFields()...)
	} else {
		s.logger.Info("newly signed header", logMetric.GetFields()...)
	}
	return json.RawMessage(signedHeaderResponse), logMetric, nil
}

func (s *Service) StartPreFetcher(ctx context.Context) {
	for fields := range s.preFetchPayloadChan {
		go func(fields preFetcherFields) {
			_ctx, cancel := context.WithTimeout(ctx, preFetcherRequestTimeout)
			defer cancel()
			//s.PreFetchGetPayload(_ctx, f.clientIP, f.authHeader, f.slot, f.parentHash, f.blockHash, f.pubKey, f.blockValue, f.client, f.payloadFetchUrl)
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
	_, span := s.tracer.Start(ctx, "preFetchGetPayload-start")
	defer span.End(trace.WithTimestamp(time.Now()))

	if fields.client != nil {
		clientURL = fields.client.URL
	}

	logMetric := NewLogMetric(
		[]zap.Field{
			zap.String("method", preFetchPayload),
			zap.Time("receivedAt", time.Now().UTC()),
			zap.String("in.ClientIP", fields.clientIP),
			zap.String("clientURL", clientURL),
			zap.String("reqID", id),
			zap.String("traceID", parentSpan.SpanContext().TraceID().String()),
			zap.String("secretToken", s.secretToken),
			zap.String("authHeader", fields.authHeader),
			zap.String("uKey", fmt.Sprintf("slot_%v_bHash_%v_pHash_%v", fields.slot, fields.blockHash, fields.parentHash)),
			zap.Int64("slot", int64(fields.slot)),
			zap.String("blockHash", fields.blockHash),
		},
		[]attribute.KeyValue{
			attribute.String("method", preFetchPayload),
			attribute.String("in.ClientIP", fields.clientIP),
			attribute.String("clientURL", clientURL),
			attribute.String("reqID", id),
			attribute.Int64("receivedAt", time.Now().UTC().Unix()),
			attribute.String("traceID", parentSpan.SpanContext().TraceID().String()),
			attribute.String("authHeader", fields.authHeader),
			attribute.String("secretToken", s.secretToken),
			attribute.String("uKey", fmt.Sprintf("slot_%v_bHash_%v_pHash_%v", fields.slot, fields.blockHash, fields.parentHash)),
			attribute.Int64("slot", int64(fields.slot)),
			attribute.String("blockHash", fields.blockHash),
		},
	)
	s.logger.Info("received preFetchGetPayload", logMetric.GetFields()...)
	span.SetAttributes(logMetric.GetAttributes()...)

	req := &relaygrpc.PreFetchGetPayloadRequest{
		ReqId:       id,
		Version:     s.version,
		SecretToken: s.secretToken,
		Slot:        fields.slot,
		ParentHash:  fields.parentHash,
		BlockHash:   fields.blockHash,
		Pubkey:      fields.pubKey,
		ClientIp:    fields.clientIP,
		ReceivedAt:  timestamppb.New(startTime),
	}

	var (
		errChan            = make(chan *ErrorResp, len(s.clients)+2)
		respChan           = make(chan *relaygrpc.PreFetchGetPayloadResponse, len(s.clients)+2)
		payloadCacheKey    = common.GetKeyForCachingPayload(fields.slot, fields.parentHash, fields.blockHash, fields.pubKey)
		wg                 sync.WaitGroup
		prefetchedRequests = 0
		succeeds           = false
	)

	// Goroutine to handle cache
	prefetchedRequests += 1
	if s.getPayloadResponseForProxySlot == nil {
		s.logger.Error("PreFetchGetPayload :: cache is nil")
		errChan <- toErrorResp(http.StatusInternalServerError, "cache is nil", logMetric.GetFields()...)
	}

	if cachedValue, exists := s.getPayloadResponseForProxySlot.Get(payloadCacheKey); exists && cachedValue != nil {
		payloadResponseForProxy, ok := cachedValue.(*common.PayloadResponseForProxy)
		if !ok {
			s.logger.Error("failed to cast cached value to GetPayloadResponseForProxy", logMetric.GetFields()...)
			errChan <- toErrorResp(http.StatusInternalServerError, "failed to cast cached value", logMetric.GetFields()...)
		}
		marshaledVal, err := payloadResponseForProxy.GetMarshalledResponse()
		if err != nil {
			s.logger.Error("failed to marshal cached value to GetPayloadResponseForProxy", logMetric.GetFields()...)
			errChan <- toErrorResp(http.StatusInternalServerError, "failed to marshal cached value", logMetric.GetFields()...)
		}

		resp := &relaygrpc.PreFetchGetPayloadResponse{
			Code:                      uint32(codes.OK),
			Message:                   "Pre fetch getPayload succeeded",
			VersionedExecutionPayload: marshaledVal,
		}

		s.logger.Info("PreFetchGetPayload-cache hit", logMetric.GetFields()...)

		respChan <- resp
		succeeds = true
		return
	} else {
		errChan <- toErrorResp(http.StatusBadRequest, "local payload not found", logMetric.GetFields()...)
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
			go func(client *common.Client) {
				defer wg.Done()
				prefetchLogger := s.logger.With(logMetric.GetFields()...)
				s.prefetchPayload(ctx, client, req, span, errChan, respChan, prefetchLogger)
			}(client)
		}
	}
	// Wait for all goroutines to finish
	defer func() {
		go func() {
			wg.Wait()
			close(respChan) // Safe to close after all goroutines finish
			close(errChan)
		}()
	}()

	// Process responses
	for i := 0; i < prefetchedRequests; i++ {
		select {
		case <-ctx.Done():
			s.logger.Warn("PreFetchGetPayload :: Context canceled", logMetric.GetFields()...)
		case _err := <-errChan:
			s.logger.With(zap.Any("error", _err)).Error("PreFetchGetPayload :: Received error", logMetric.GetFields()...)
		case out := <-respChan:
			proxyCacheKey := common.GetKeyForCachingPayload(fields.slot, fields.parentHash, fields.blockHash, fields.pubKey)
			s.pubKeysBySlots.Set(fmt.Sprintf("%d", fields.slot), fields.pubKey, cache.DefaultExpiration)

			payloadResponse := &common.PayloadResponseForProxy{
				MarshalledPayloadResponse: out.VersionedExecutionPayload,
				BlockValue:                fields.blockValue,
			}

			if err := s.getPayloadResponseForProxySlot.Add(proxyCacheKey, payloadResponse, cache.DefaultExpiration); err != nil {
				s.logger.With(zap.Error(err)).Warn("PreFetchGetPayload :: respChan :: cache execution payload failed", logMetric.GetFields()...)
				return
			}
			s.logger.Info("PreFetchGetPayload :: respChan :: preFetchGetPayload succeeded", logMetric.GetFields()...)
			return
		}
	}
}

func (s *Service) prefetchPayloadToSignedBlindedBeaconBlock(ctx context.Context, logMetric *LogMetric, payload []byte) (*common.VersionedSignedBlindedBeaconBlock, *ErrorResp) {
	_, readPayload := s.tracer.Start(ctx, "validateAndFetchPayload-readPayload")

	bodyString := string(payload)
	blockHashIndex := strings.LastIndex(bodyString, "\"block_hash\"")

	if blockHashIndex == -1 {
		logMetric.String("proxyError", "block_hash not present")
		return nil, toErrorResp(http.StatusBadRequest, "invalid input", logMetric.GetFields()...)
	}
	readPayload.End(trace.WithTimestamp(time.Now()))

	_, decodeJSONSpan := s.tracer.Start(ctx, "validateAndFetchPayload-decodeJSON")
	signedBlindedBeaconBlock, err := fastjson.UnmarshalToSignedBlindedBeaconBlock(bodyString)
	if err != nil {
		decodeJSONSpan.End(trace.WithTimestamp(time.Now()))
		logMetric.String("proxyError", "failed to decode request payload")
		return nil, toErrorResp(http.StatusBadRequest, err.Error(), logMetric.GetFields()...)
	}
	decodeJSONSpan.End(trace.WithTimestamp(time.Now()))
	return signedBlindedBeaconBlock, nil
}

func (s *Service) validateAndFetchPayload(ctx context.Context, logMetric *LogMetric, signedBlindedBeaconBlock *common.VersionedSignedBlindedBeaconBlock) (*common.VersionedPayloadInfo, *ErrorResp) {
	logMetric.String("blockVersion", signedBlindedBeaconBlock.Version.String())
	slot, err := signedBlindedBeaconBlock.Slot()
	if err != nil {
		logMetric.String("proxyError", "failed to decode slot")
		return nil, toErrorResp(http.StatusBadRequest, "failed to get slot", logMetric.GetFields()...)
	}

	blockHash, err := signedBlindedBeaconBlock.ExecutionBlockHash()
	if err != nil {
		logMetric.String("proxyError", "failed to decode block hash")
		return nil, toErrorResp(http.StatusBadRequest, "failed to get block hash", logMetric.GetFields()...)
	}
	blockHashString := blockHash.String()

	parentHash, err := signedBlindedBeaconBlock.ExecutionParentHash()
	if err != nil {
		logMetric.String("proxyError", "failed to decode parent hash")
		return nil, toErrorResp(http.StatusBadRequest, "failed to get parent hash", logMetric.GetFields()...)
	}

	_, checkRequestTimingSpan := s.tracer.Start(ctx, "validateAndFetchPayload-checkRequestTiming")

	slotStartTime := GetSlotStartTime(s.beaconGenesisTime, int64(slot), s.secondsPerSlot)
	msIntoSlot := time.Since(slotStartTime).Milliseconds()
	logMetric.Attributes(
		attribute.String("slot", fmt.Sprintf("%+v", slot)),
		attribute.String("BlockHash", blockHashString),
	)

	logMetric.Fields(
		zap.Uint64("slot", uint64(slot)),
		zap.String("BlockHash", blockHashString),
		zap.String("parentHash", parentHash.String()),
		zap.Time("slotStartTime", slotStartTime),
		zap.Int64("slotStartTimeUnix", slotStartTime.Unix()),
		zap.Int64("msIntoSlot", msIntoSlot))
	if msIntoSlot < 0 {
		// Wait until slot start (t=0) if still in the future
		_msSinceSlotStart := time.Now().UTC().UnixMilli() - slotStartTime.UnixMilli()
		if _msSinceSlotStart < 0 {
			delayMillis := (_msSinceSlotStart * -1) + int64(rand.Intn(50)) //nolint:gosec
			logMetric.Int64("delayMillis", delayMillis)
			time.Sleep(time.Duration(delayMillis) * time.Millisecond)
			logMetric.Attributes(attribute.KeyValue{Key: "sleepingFor", Value: attribute.Int64Value(delayMillis)})
		}
	} else if msIntoSlot > int64(getPayloadRequestCutoffMs) {
		checkRequestTimingSpan.End(trace.WithTimestamp(time.Now()))
		return nil, toErrorResp(http.StatusBadRequest, "timestamp too late", logMetric.GetFields()...)
	}
	checkRequestTimingSpan.End(trace.WithTimestamp(time.Now()))

	_, fetchProposerForSlotSpan := s.tracer.Start(ctx, "validateAndFetchPayload-fetchProposerForSlot")
	proposerKey, ok := s.pubKeysBySlots.Get(fmt.Sprintf("%d", uint64(slot)))
	if !ok {
		logMetric.String("proxyError", fmt.Sprintf("slot %v not found in memory", slot))
		return nil, toErrorResp(http.StatusBadRequest, fmt.Sprintf("slot %v not found in memory", slot), logMetric.GetFields()...)
	}
	pubKey, ok := proposerKey.(string)
	if !ok {
		s.logger.With(logMetric.GetFields()...).Error("ERROR::validateAndFetchPayload: pubKeysBySlots error")
		return nil, toErrorResp(http.StatusBadRequest, fmt.Sprintf("invalid pubkey %v stored in slot %v ", proposerKey, slot), logMetric.GetFields()...)
	}
	pub, err := utils.HexToPubkey(pubKey)
	if err != nil {
		s.logger.With(logMetric.GetFields()...).Error("ERROR::validateAndFetchPayload: HexToPubkey(pubKey) error")
		fetchProposerForSlotSpan.End(trace.WithTimestamp(time.Now()))
		logMetric.String("proxyError", "invalid public key")
		return nil, toErrorResp(http.StatusBadRequest, "invalid public key", logMetric.GetFields()...)
	}

	fetchProposerForSlotSpan.End(trace.WithTimestamp(time.Now()))
	logMetric.String("pubKey", pub.String())

	_, verifySignatureSpan := s.tracer.Start(ctx, "validateAndFetchPayload-verifySignature")
	// verify the signature
	ok, err = fastjson.CheckProposerSignature(s.ethNetworkDetails, signedBlindedBeaconBlock, pub[:])
	if !ok || err != nil {
		verifySignatureSpan.End(trace.WithTimestamp(time.Now()))
		if err != nil {
			logMetric.Error(err)
		}
		logMetric.String("proxyError", "invalid signature")
		return nil, toErrorResp(http.StatusBadRequest, "invalid signature", logMetric.GetFields()...)
	}
	verifySignatureSpan.End(trace.WithTimestamp(time.Now()))

	_, fetchPayloadFromCacheSpan := s.tracer.Start(ctx, "validateAndFetchPayload-fetchPayloadFromCache")
	// fetch payload from cache
	proxyCacheKey := common.GetKeyForCachingPayload(uint64(slot), parentHash.String(), blockHashString, pubKey)
	v, ok := s.getPayloadResponseForProxySlot.Get(proxyCacheKey)
	fetchPayloadFromCacheSpan.End(trace.WithTimestamp(time.Now()))
	if ok {
		payloadResponse := v.(*common.PayloadResponseForProxy)
		versionePayloadInfo, err := payloadResponse.BuildVersionedPayloadInfo(uint64(slot), parentHash.String(), blockHashString, pubKey)
		if err != nil {
			logMetric.Error(err)
			s.logger.Error("failed to build versioned payload info", logMetric.GetFields()...)
			return nil, toErrorResp(http.StatusOK, "failed to build versioned payload info", logMetric.GetFields()...)
		}
		s.logger.Info("SUCCESS-validateAndFetchPayload-payloadResponse", logMetric.GetFields()...)
		return versionePayloadInfo, nil
	}

	s.logger.Warn("ERROR-validateAndFetchPayload", logMetric.GetFields()...)
	return &common.VersionedPayloadInfo{
		Slot:       uint64(slot),
		ParentHash: parentHash.String(),
		BlockHash:  blockHashString,
		Pubkey:     pubKey,
	}, toErrorResp(http.StatusOK, "pre fetch payload not available in cache")
}

func (s *Service) GetPayload(ctx context.Context, in *PayloadRequestParams) (any, *LogMetric, error) {
	startTime := time.Now().UTC()
	id := uuid.NewString()
	parentSpan := trace.SpanFromContext(ctx)
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)
	// use internal auth header if auth header is not provided
	aKey := s.authKey
	isAuthHeaderProvided := in.AuthHeader != ""
	if isAuthHeaderProvided {
		aKey = in.AuthHeader
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", s.authKey)
	ctx, span := s.tracer.Start(ctx, "getPayload-start")
	defer span.End(trace.WithTimestamp(time.Now()))
	var (
		latency int64
	)
	if in.GetPayloadStartTimeUnixMS != "" {
		getPayloadStartTime, err := strconv.ParseInt(in.GetPayloadStartTimeUnixMS, 10, 64)
		if err != nil {
			s.logger.Warn("failed to parse getPayloadStartTimeUnixMS", zap.Error(err))
		} else {
			latency = in.ReceivedAt.Sub(time.UnixMilli(getPayloadStartTime)).Milliseconds()
		}
	}

	logMetric := NewLogMetric(
		[]zap.Field{
			zap.String("method", getPayload),
			zap.Time("receivedAt", in.ReceivedAt),
			zap.String("in.ClientIP", in.ClientIP),
			zap.String("reqID", id),
			zap.String("in.ValidatorID", in.ValidatorID),
			zap.String("accountID", in.AccountID),
			zap.Int64("latency", latency),
			zap.String("traceID", parentSpan.SpanContext().TraceID().String()),
			zap.String("authHeader", aKey),
			zap.Bool("isAuthHeaderProvided", isAuthHeaderProvided),
			zap.String("cluster", in.Cluster),
			zap.String("userAgent", in.UserAgent),
		},
		[]attribute.KeyValue{
			attribute.String("method", getPayload),
			attribute.String("in.ClientIP", in.ClientIP),
			attribute.String("reqID", id),
			attribute.String("in.ValidatorID", in.ValidatorID),
			attribute.String("accountID", in.AccountID),
			attribute.Int64("receivedAt", in.ReceivedAt.Unix()),
			attribute.Int64("latency", latency),
			attribute.String("traceID", parentSpan.SpanContext().TraceID().String()),
			attribute.String("authHeader", aKey),
			attribute.String("cluster", in.Cluster),
			attribute.String("userAgent", in.UserAgent),
		},
	)
	s.logger.Info("received getPayload", logMetric.GetFields()...)
	span.SetAttributes(logMetric.GetAttributes()...)

	var errResp ErrorRespWithPayload
	errChan := make(chan ErrorRespWithPayload, len(s.clients)+prefetchAttempts)
	respChan := make(chan *common.VersionedPayloadInfo, len(s.clients)+prefetchAttempts)
	attempts := make([]struct{}, prefetchAttempts)
	metricCopy := logMetric.Copy()
	var wg sync.WaitGroup
	wg.Add(1)
	totalPrefetchResponses := 1
	go func(l *LogMetric) {
		defer wg.Done()
		// fetch payload from cache
		blindedBeaconBlock, errRes := s.prefetchPayloadToSignedBlindedBeaconBlock(ctx, l, in.Payload)
		if errRes != nil {
			s.logger.Info("validateAndFetchPayload failed", logMetric.GetFields()...)
			errChan <- ErrorRespWithPayload{err: errRes, resp: nil}
			return
		}
		s.logger.With(zap.String("version", blindedBeaconBlock.Version.String())).Info("validateAndFetchPayload prefetching payload", logMetric.GetFields()...)
		firstAttempt := true
		for range attempts {
			payloadInfo, errRes := s.validateAndFetchPayload(ctx, l, blindedBeaconBlock)

			if !firstAttempt {
				totalPrefetchResponses += 1
			} else {
				firstAttempt = false
			}

			if errRes != nil {
				errChan <- ErrorRespWithPayload{err: errRes, resp: payloadInfo}
				time.Sleep(100 * time.Millisecond)
				s.logger.With(zap.String("error", errRes.Error())).Info("validateAndFetchPayload sleeping", logMetric.GetFields()...)
				continue
			}
			s.logger.Info("validateAndFetchPayload success", logMetric.GetFields()...)
			respChan <- payloadInfo
			return
		}
	}(metricCopy)

	req := &relaygrpc.GetPayloadRequest{
		ReqId:       id,
		Payload:     in.Payload,
		ClientIp:    in.ClientIP,
		Version:     s.version,
		ReceivedAt:  timestamppb.New(in.ReceivedAt),
		SecretToken: s.secretToken,
	}

	ctx, payloadResponseSpan := s.tracer.Start(ctx, "getPayload-payloadResponseFromRelay")
	for _, client := range s.clients {
		wg.Add(1)
		go func(c *common.Client) {
			defer wg.Done()
			out, err := s.getPayloadWithRetry(ctx, c, span, req, maxGetPayloadRetry)
			if err != nil {
				s.logger.Error("getPayloadWithRetry", zap.Error(err))
				errChan <- ErrorRespWithPayload{err: err, resp: out}
				return
			}
			s.logger.Info("getPayloadWithRetry success", logMetric.GetFields()...)
			respChan <- out
		}(client)
	}

	go func() {
		wg.Wait()
		close(errChan)
		close(respChan)
	}()

	for i := 0; i < len(s.clients)+totalPrefetchResponses; i++ {
		select {
		case <-ctx.Done():
			logMetricCopy := logMetric.Copy()
			go s.sendPayloadStats(in.Payload, logMetricCopy, false, nil, in.ReceivedAt, startTime, time.Now(), 0, id, in.ClientIP, in.ValidatorID, in.AccountID, latency, in.Cluster, in.UserAgent)
			logMetric.Error(ctx.Err())
			logMetric.String("relayError", "failed to getPayload")
			return nil, logMetric, toErrorResp(http.StatusInternalServerError, ctx.Err().Error(), zap.String("relayError", "failed to getPayload"))
		case resp := <-respChan:
			logMetricCopy := logMetric.Copy()
			slotStartTime := GetSlotStartTime(s.beaconGenesisTime, int64(resp.Slot), s.secondsPerSlot)
			msIntoSlot := in.ReceivedAt.Sub(slotStartTime).Milliseconds()
			duration := time.Since(startTime)
			go s.sendPayloadStats(in.Payload, logMetricCopy, true, resp, in.ReceivedAt, startTime, slotStartTime, msIntoSlot, id, in.ClientIP, in.ValidatorID, in.AccountID, latency, in.Cluster, in.UserAgent)
			uKey := fmt.Sprintf("slot_%v_bHash_%v_pHash_%v", resp.Slot, resp.BlockHash, resp.ParentHash) // TODO:add pubkey
			logMetric.Fields([]zap.Field{
				zap.Duration("duration", duration),
				zap.String("slot", fmt.Sprintf("%v", resp.Slot)),
				zap.Time("slotStartTime", slotStartTime),
				zap.Int64("msIntoSlot", msIntoSlot),
				zap.String("in.ParentHash", resp.ParentHash),
				zap.String("blockHash", resp.BlockHash),
				zap.String("blockValue", resp.BlockValue),
				zap.String("uniqueKey", uKey),
			}...)
			logMetric.Attributes([]attribute.KeyValue{
				attribute.String("duration", duration.String()),
				attribute.String("slot", fmt.Sprintf("%v", resp.Slot)),
				attribute.Int64("slotStartTime", slotStartTime.UnixMilli()),
				attribute.Int64("msIntoSlot", msIntoSlot),
				attribute.String("in.ParentHash", resp.ParentHash),
				attribute.String("blockHash", resp.BlockHash),
				attribute.String("blockValue", resp.BlockValue),
				attribute.String("uniqueKey", uKey),
			}...)
			return json.RawMessage(resp.Response), logMetric, nil
		case errResp = <-errChan:
			// if multiple client return errors, first error gets replaced by the subsequent errors
		}
	}
	logMetricCopy := logMetric.Copy()
	go s.sendPayloadStats(in.Payload, logMetricCopy, false, errResp.resp, in.ReceivedAt, startTime, time.Now(), 0, id, in.ClientIP, in.ValidatorID, in.AccountID, latency, in.Cluster, in.UserAgent)
	payloadResponseSpan.End(trace.WithTimestamp(time.Now()))
	logMetric.Error(errors.New(errResp.err.Message))
	logMetric.Fields(errResp.err.fields...)
	return nil, logMetric, errResp.err

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
				uKey := fmt.Sprintf("slot_%v_bHash_%v_pHash_%v", resp.GetSlot(), resp.GetBlockHash(), resp.GetParentHash()) // TODO:add pubkey
				att := []attribute.KeyValue{
					attribute.String("relayError", resp.Message),
					attribute.String("url", c.URL),
					attribute.Int64("slot", int64(resp.GetSlot())),
					attribute.String("BlockHash", resp.GetBlockHash()),
					attribute.String("in.ParentHash", resp.GetParentHash()),
					attribute.String("BlockValue", resp.GetBlockValue()),
					attribute.String("uniqueKey", uKey),
				}
				clientGetPayloadSpan.SetAttributes(att...)
				clientGetPayloadSpan.End()

				return common.BuildVersionedPayloadInfoFromGrpcResponse(resp), toErrorResp(http.StatusBadRequest, "relay returned error",
					zap.String("relayError", resp.Message),
					zap.String("url", c.URL),
					zap.Uint64("slot", resp.GetSlot()),
					zap.String("BlockHash", resp.GetBlockHash()),
					zap.String("in.ParentHash", resp.GetParentHash()),
					zap.String("BlockValue", resp.GetBlockValue()),
					zap.String("uniqueKey", uKey))
			}
		}

		if attempt < retryCount {
			clientGetPayloadSpan.End()
			time.Sleep(getPayloadInterval) // Wait before retrying
			continue
		}
		if err != nil {
			parentSpan.SetStatus(otelcodes.Error, err.Error())
			clientGetPayloadSpan.End()
			return nil, toErrorResp(http.StatusInternalServerError, "relay returned error", zap.String("relayError", err.Error()), zap.String("url", c.URL))
		}
		if resp == nil {
			parentSpan.SetStatus(otelcodes.Error, "empty response from relay")
			clientGetPayloadSpan.End()
			return nil, toErrorResp(http.StatusInternalServerError, "empty response from relay", zap.String("url", c.URL))
		}
		parentSpan.SetStatus(otelcodes.Error, resp.Message)
		uKey := fmt.Sprintf("slot_%v_bHash_%v_pHash_%v", resp.GetSlot(), resp.GetBlockHash(), resp.GetParentHash()) // TODO:add pubkey
		att := []attribute.KeyValue{
			attribute.String("relayError", resp.Message),
			attribute.String("url", c.URL),
			attribute.Int64("slot", int64(resp.GetSlot())),
			attribute.String("BlockHash", resp.GetBlockHash()),
			attribute.String("in.ParentHash", resp.GetParentHash()),
			attribute.String("BlockValue", resp.GetBlockValue()),
			attribute.String("uniqueKey", uKey),
		}
		clientGetPayloadSpan.SetAttributes(att...)
		clientGetPayloadSpan.End()
		return common.BuildVersionedPayloadInfoFromGrpcResponse(resp), toErrorResp(http.StatusBadRequest, "relay returned failure response code",
			zap.String("relayError", resp.Message),
			zap.String("url", c.URL),
			zap.Uint64("slot", resp.GetSlot()),
			zap.String("BlockHash", resp.GetBlockHash()),
			zap.String("in.ParentHash", resp.GetParentHash()),
			zap.String("BlockValue", resp.GetBlockValue()),
			zap.String("uniqueKey", uKey))
	}

	return nil, toErrorResp(http.StatusInternalServerError, "relay returned error", zap.String("relayError", "all retry failed"), zap.String("url", c.URL))
}

func (s *Service) sendPayloadStats(payload []byte, logMetric *LogMetric, isSucceeded bool, resp *common.VersionedPayloadInfo, receivedAt, startTime, slotStartTime time.Time, msIntoSlot int64, id, clientIP, validatorID, accountID string, latency int64, cluster string, userAgent string) {
	// 3 different scenario calling sendPayload stats
	// case 1 : resp success
	// case 2: Err case with resp
	// case 2: Err case with no resp
	out := resp.Copy()
	if out.GetSlot() != 0 { // case 2
		slotStartTime = GetSlotStartTime(s.beaconGenesisTime, int64(out.GetSlot()), s.secondsPerSlot)
		msIntoSlot = receivedAt.Sub(slotStartTime).Milliseconds()
	}
	if out == nil { // case 3
		// Decode payload
		decodedPayload := new(common.VersionedSignedBlindedBeaconBlock)
		if err := json.NewDecoder(bytes.NewReader(payload)).Decode(decodedPayload); err != nil {
			s.logger.With(logMetric.GetFields()...).Warn("failed to decode getPayload request")
			return
		} else {
			_slot, err := decodedPayload.Slot()
			if err != nil {
				s.logger.With(logMetric.GetFields()...).Warn("failed to decode getPayload slot")
				return
			} else {
				out = new(common.VersionedPayloadInfo)
				out.SetSlot(uint64(_slot))
				slotStartTime = GetSlotStartTime(s.beaconGenesisTime, int64(out.Slot), s.secondsPerSlot)
				msIntoSlot = receivedAt.Sub(slotStartTime).Milliseconds()
				_blockHash, err := decodedPayload.ExecutionBlockHash()
				if err != nil {
					s.logger.With(logMetric.GetFields()...).Warn("failed to decode getPayload BlockHash")
				} else {
					out.SetBlockHash(_blockHash.String())
					parentHash, err := decodedPayload.ExecutionParentHash()
					if err != nil {
						s.logger.With(logMetric.GetFields()...).Warn("failed to decode getPayload parentHash")
					} else {
						// block value will be empty as it's not available as part of VersionedSignedBlindedBeaconBlock
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
	}
	var (
		isRelayProxyWin bool
	)
	k := fmt.Sprintf("slot-%v-parentHash-%v", out.GetSlot(), out.GetParentHash())
	v, ok := s.slotStats.Get(k)
	if ok {
		if records, success := v.([]SlotStatsRecord); success {
			for i, record := range records {
				isRelayProxyWin = record.HeaderDeliveredBlockHash == out.GetBlockHash()
				// emit slot stats event either when proxy win the slot or last record of getHeader list
				if isRelayProxyWin || i == len(records)-1 {
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

					// needed for stakely
					statsRecord.AccountID = record.AccountID
					accountID = record.AccountID
					statsRecord.ValidatorID = record.ValidatorID
					validatorID = record.ValidatorID

					break
				}
			}
		}
	}
	s.slotStatsEvent.Set(k, statsRecord, cache.DefaultExpiration) // replace with updated slot stats

	if isRelayProxyWin {
		s.logger.Info("emit slot won event", zap.Any("slotKey", k))
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
			s.logger.Error("failed to get slot duty", zap.Uint64("slot", slot), zap.Error(err))
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
			s.logger.Info("closing slot stats events")
			return
		}
	}
}

func (s *Service) StartStreamBlocks(ctx context.Context, wg *sync.WaitGroup) {
	for _, client := range s.streamingBlockClients {
		wg.Add(1)
		go func(_ctx context.Context, c *common.Client) {
			defer wg.Done()
			s.handleBlockStream(_ctx, c)
		}(ctx, client)
	}
	go s.handleForwardedBlockResponse()
	wg.Wait()
}

func (s *Service) handleBlockStream(ctx context.Context, client *common.Client) {
	parentSpan := trace.SpanFromContext(ctx)
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)
	_, span := s.tracer.Start(ctx, "handleBlockStream-streamBlock")
	defer span.End(trace.WithTimestamp(time.Now().UTC()))

	span.SetAttributes(
		attribute.String("method", "streamBlock"),
		attribute.String("url", client.URL),
		attribute.String("traceID", parentSpan.SpanContext().TraceID().String()),
	)

	for {
		select {
		case <-ctx.Done():
			s.logger.Warn("stream block context cancelled",
				zap.String("traceID", parentSpan.SpanContext().TraceID().String()),
			)
			return
		default:
			if _, err := s.StreamBlock(ctx, client); err != nil {
				s.logger.Warn("failed to stream block. Sleeping and then reconnecting",
					zap.String("url", client.URL),
					zap.String("traceID", parentSpan.SpanContext().TraceID().String()),
					zap.Error(err))
				span.SetAttributes(attribute.KeyValue{Key: "sleepingFor", Value: attribute.Int64Value(reconnectTime)}, attribute.KeyValue{Key: "error", Value: attribute.StringValue(err.Error())})
			} else {
				s.logger.Warn("stream block stopped.  Sleeping and then reconnecting",
					zap.String("url", client.URL),
					zap.String("traceID", parentSpan.SpanContext().TraceID().String()),
				)
				span.SetAttributes(attribute.KeyValue{Key: "sleepingFor", Value: attribute.Int64Value(reconnectTime)}, attribute.KeyValue{Key: "error", Value: attribute.StringValue("stream header stopped.")})
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
		s.logger.Warn("failed to split host port", zap.Error(err))
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
		[]zap.Field{
			zap.String("method", method),
			zap.String("nodeID", client.NodeID),
			zap.String("reqID", id),
			zap.String("url", client.URL),
		},
		[]attribute.KeyValue{
			attribute.String("method", method),
			attribute.String("nodeID", client.NodeID),
			attribute.String("url", client.URL),
			attribute.String("reqID", id),
		},
	)
	span.SetAttributes(logMetric.GetAttributes()...)

	s.logger.Info("streaming blocks", logMetric.GetFields()...)
	if err != nil {
		logMetric.Error(err)
		s.logger.Warn("failed to stream block", logMetric.GetFields()...)
		span.SetStatus(otelcodes.Error, err.Error())
		return nil, err
	}
	done := make(chan struct{})
	var once sync.Once
	closeDone := func() {
		once.Do(func() {
			s.logger.Info("calling close done once")
			close(done)
		})
	}
	logMetricCopy := logMetric.Copy()
	go func(lm *LogMetric) {
		select {
		case <-stream.Context().Done():
			lm.Error(stream.Context().Err())
			s.logger.Warn("stream context cancelled, closing connection", lm.GetFields()...)
			closeDone()
		case <-ctx.Done():
			logMetric.Error(ctx.Err())
			s.logger.Warn("context cancelled, closing connection", lm.GetFields()...)
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
			s.logger.With(zap.Error(err)).Warn("stream received EOF", logMetric.GetFields()...)
			streamReceiveSpan.SetStatus(otelcodes.Error, err.Error())
			closeDone()
			break
		}
		_s, ok := status.FromError(err)
		if !ok {
			s.logger.With(zap.Error(err)).Warn("invalid grpc error status", logMetric.GetFields()...)
			streamReceiveSpan.SetStatus(otelcodes.Error, "invalid grpc error status")
			continue
		}

		if _s.Code() == codes.Canceled {
			logMetric.Error(err)
			s.logger.With(zap.Error(err)).Warn("received cancellation signal, shutting down", logMetric.GetFields()...)
			// mark as canceled to stop the upstream retry loop
			streamReceiveSpan.SetStatus(otelcodes.Error, "received cancellation signal")
			closeDone()
			break
		}

		if _s.Code() != codes.OK {
			s.logger.With(zap.Error(_s.Err())).With(zap.String("code", _s.Code().String())).Warn("server unavailable,try reconnecting", logMetric.GetFields()...)
			streamReceiveSpan.SetStatus(otelcodes.Error, "server unavailable,try reconnecting")
			closeDone()
			break
		}
		if err != nil {
			s.logger.With(zap.Error(err)).Warn("failed to receive stream, disconnecting the stream", logMetric.GetFields()...)
			streamReceiveSpan.SetStatus(otelcodes.Error, err.Error())
			closeDone()
			break
		}
		// Added empty streaming as a temporary workaround to maintain streaming alive
		// TODO: this need to be handled by adding settings for keep alive params on both server and client
		if block.GetBlockHash() == "" {
			s.logger.Warn("received empty stream", logMetric.GetFields()...)
			continue
		}
		latency := receivedAt.Sub(block.GetSendTime().AsTime()).Milliseconds()
		processTime := time.Since(receivedAt).Milliseconds()
		go s.handleStreamBlockResponse(streamBlockCtx, block, logMetric, receivedAt, latency, parentSpan.SpanContext().TraceID().String(), method, clientIP, processTime)
	}
	<-done
	streamReceiveSpan.SetAttributes(logMetric.GetAttributes()...)
	streamReceiveSpan.End(trace.WithTimestamp(time.Now()))

	s.logger.Warn("closing connection", logMetric.GetFields()...)
	return nil, nil
}

func (s *Service) handleForwardedBlockResponse() {
	s.logger.Info("start handling forwarded block response")
	for forwardedBlockInfo := range *s.forwardedBlockCh {
		s.logger.Info("received forwarded block from channel")
		lm := NewLogMetric([]zap.Field{
			zap.String("method", forwardedBlockInfo.Method),
		}, []attribute.KeyValue{
			attribute.String("method", forwardedBlockInfo.Method),
		})
		if forwardedBlockInfo.Block == nil || forwardedBlockInfo.Block.GetBlockHash() == "" {
			s.logger.Warn("received empty forwarded block", lm.GetFields()...)
			continue
		}
		go s.handleStreamBlockResponse(forwardedBlockInfo.Context, forwardedBlockInfo.Block, lm, forwardedBlockInfo.ReceivedAt, forwardedBlockInfo.Latency, forwardedBlockInfo.TraceID, forwardedBlockInfo.Method, forwardedBlockInfo.ClientIP, forwardedBlockInfo.ProcessTime)
	}
	s.logger.Info("stop handling forwarded block response")
}

func (s *Service) handleStreamBlockResponse(ctx context.Context, block *relaygrpc.StreamBlockResponse, logMetric *LogMetric, receivedAt time.Time, latency int64, traceId string, method string, clientIP string, processTime int64) {
	// check if the block hash has already been received
	handleStart := time.Now().UTC()
	lm := logMetric.Copy()

	k := s.keyForCachingBids(block.GetSlot(), block.GetParentHash(), block.GetPubkey())

	payloadSize := len(block.GetPayload())
	payloadType := ""
	extraData := block.GetBuilderExtraData()

	uKey := "slot_" + strconv.FormatUint(block.GetSlot(), 10) + "_bHash_" + block.GetBlockHash() + "_pHash_" + block.GetParentHash()
	lm.Fields(
		zap.String("keyForCachingBids", k),
		zap.Uint64("slot", block.GetSlot()),
		zap.String("parentHash", block.GetParentHash()),
		zap.String("blockHash", block.GetBlockHash()),
		zap.String("pubKey", block.GetPubkey()),
		zap.String("builderPubKey", block.GetBuilderPubkey()),
		zap.String("extraData", extraData),
		zap.String("traceID", traceId),
		zap.String("uniqueKey", uKey),
		zap.Time("receivedAt", receivedAt),
		zap.Bool("paidBlxr", block.GetPaidBlxr()),
		zap.String("accountID", block.GetAccountId()),
		zap.Int64("streamLatencyInMs", latency),
		zap.Int64("processLatency", processTime),
		zap.Int64("httpPayloadSize", int64(payloadSize)),
	)
	lm.Attributes(
		attribute.String("keyForCachingBids", k),
		attribute.Int64("slot", int64(block.GetSlot())),
		attribute.String("parentHash", block.GetParentHash()),
		attribute.String("blockHash", block.GetBlockHash()),
		attribute.String("pubKey", block.GetPubkey()),
		attribute.String("builderPubKey", block.GetBuilderPubkey()),
		attribute.String("extraData", extraData),
		attribute.String("traceID", traceId),
		attribute.String("uniqueKey", uKey),
		attribute.String("receivedAt", receivedAt.String()),
		attribute.Bool("paidBlxr", block.GetPaidBlxr()),
		attribute.String("accountID", block.GetAccountId()),
		attribute.Int64("streamLatencyInMs", latency),
		attribute.Int64("processLatency", processTime),
		attribute.Int64("httpPayloadSize", int64(payloadSize)),
	)
	spanCtx, span := s.tracer.Start(ctx, "handleStreamBlockResponse")
	diff := int64(0)
	defer func() {
		handleTime := time.Since(handleStart).Milliseconds()
		span.End()
		span.SetAttributes(lm.GetAttributes()...)
		go s.logBlockReceivedStream(block, receivedAt, latency, clientIP, method, payloadType, processTime, diff, handleTime, int64(payloadSize), extraData)
	}()
	if val, exist := s.builderExistingBlockHash.Get(block.GetBlockHash()); exist {
		var addedAt int64
		var source string
		if v, ok := val.(common.DuplicateBlock); ok {
			addedAt = v.Time
			source = v.Source
		}
		duplicateReceiveTime := time.Now().UTC().UnixMilli()
		diff = duplicateReceiveTime - addedAt
		lm.Fields(
			zap.String("blockHash", block.GetBlockHash()),
			zap.Int64("addedAt", addedAt),
			zap.Int64("duplicateReceiveTime", duplicateReceiveTime),
			zap.Int64("diff", diff),
			zap.String("source", source))
		lm.Attributes(attribute.String("blockHash", block.GetBlockHash()),
			attribute.Int64("addedAt", addedAt),
			attribute.Int64("duplicateReceiveTime", duplicateReceiveTime),
			attribute.Int64("diff", diff),
			attribute.String("source", source))
		s.logger.Warn("block hash already exist", lm.GetFields()...)
		return
	}

	grpcPayload := block.GetGrpcPayload()
	httpPayload := block.GetPayload()

	submitBlockRequest := new(common.VersionedSubmitBlockRequest)
	_, unmarshalSpan := s.tracer.Start(spanCtx, "handleStreamBlockResponse-unmarshal")
	if grpcPayload != nil {
		submission, err := relaygrpc.ProtoRequestToVersionedRequest(grpcPayload)
		if err != nil {
			s.logger.Error("could not convert block to versioned block", zap.Error(err))
			unmarshalSpan.End()
			return
		}
		submitBlockRequest = &common.VersionedSubmitBlockRequest{VersionedSubmitBlockRequest: *submission}
		payloadType = "grpc"
	} else if httpPayload != nil {
		payloadType = "json"
		if err := submitBlockRequest.UnmarshalJSON(httpPayload); err != nil {
			if err := submitBlockRequest.UnmarshalSSZ(httpPayload); err != nil {
				s.logger.Error("could not decode ssz http payload", zap.Error(err))
				unmarshalSpan.End()
				return
			}
			payloadType = "ssz"
		}
	} else {
		s.logger.Error("empty payload")
		return
	}
	unmarshalSpan.End()
	lm.Fields(
		zap.String("blockValue", new(big.Int).SetBytes(block.GetValue()).String()),
		zap.Time("relayReceiveAt", block.GetRelayReceiveTime().AsTime()),
		zap.Time("streamSentAt", block.GetSendTime().AsTime()),
		zap.String("payloadType", payloadType),
	)
	lm.Attributes(
		attribute.String("blockValue", new(big.Int).SetBytes(block.GetValue()).String()),
		attribute.String("relayReceiveAt", block.GetRelayReceiveTime().AsTime().String()),
		attribute.String("streamSentAt", block.GetSendTime().AsTime().String()),
		attribute.String("payloadType", payloadType),
	)
	_, signSpan := s.tracer.Start(spanCtx, "handleStreamBlockResponse-sign")

	headerSubmissionV3, err := common.BuildHeaderSubmissionV3(submitBlockRequest)
	if err != nil {
		s.logger.Error("failed to build header submission", zap.Error(err))
		signSpan.End()
		return
	}
	relayProxyGetHeaderResponse, err := common.BuildGetHeaderResponseAndSign(headerSubmissionV3, s.secretKey, &s.publicKey, s.builderSigningDomain)

	if err != nil {
		s.logger.Error("failed to sign header", zap.Error(err))
		signSpan.End()
		return
	}
	signSpan.End()
	wrappedRelayProxyGetHeaderResponse := &common.VersionedSignedBuilderBid{}
	wrappedRelayProxyGetHeaderResponse.VersionedSignedBuilderBid = *relayProxyGetHeaderResponse
	_, marshalSpan := s.tracer.Start(spanCtx, "handleStreamBlockResponse-marshal")
	relayProxyBidBytes, err := json.Marshal(wrappedRelayProxyGetHeaderResponse)
	if err != nil {
		s.logger.Error("failed to marshal header", zap.Error(err))
		marshalSpan.End()
		return
	}
	marshalSpan.End()

	if extraData == "" {
		extraDataBytes, err := wrappedRelayProxyGetHeaderResponse.ExtraData()
		if err != nil {
			s.logger.Error("failed to get extra data", zap.Error(err))
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

	s.logger.Info("received block", lm.GetFields()...)

	_, storeBidsSpan := s.tracer.Start(spanCtx, "StreamHeader-storeBids")
	// store the bid for builder pubkey
	s.setBuilderBidForProxySlot(k, block.GetBuilderPubkey(), bid, block.GetSlot()) // run it in goroutine ?
	storeBidsSpan.SetAttributes(lm.GetAttributes()...)
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
		go func(_ctx context.Context, c *common.Client) {
			defer wg.Done()
			s.handleBuilderInfoStream(_ctx, c)
		}(ctx, client)
	}
	wg.Wait()
}
func (s *Service) handleBuilderInfoStream(ctx context.Context, client *common.Client) {
	parentSpan := trace.SpanFromContext(ctx)
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)

	for {
		select {
		case <-ctx.Done():
			s.logger.Warn("stream block context cancelled",
				zap.String("traceID", parentSpan.SpanContext().TraceID().String()),
			)
			return
		default:
			if _, err := s.StreamBuilderInfo(ctx, client); err != nil {
				s.logger.Warn("failed to stream builderInfo. Sleeping and then reconnecting",
					zap.String("url", client.URL),
					zap.String("traceID", parentSpan.SpanContext().TraceID().String()),
					zap.Error(err))
			} else {
				s.logger.Warn("stream builderInfo stopped.  Sleeping and then reconnecting",
					zap.String("url", client.URL),
					zap.String("traceID", parentSpan.SpanContext().TraceID().String()),
				)
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
		s.logger.Warn("failed to split host port", zap.Error(err))
		return nil, err
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "listenAddress", port)
	ctx = metadata.AppendToOutgoingContext(ctx, "grpcListenAddress", s.GrpcListenAddress)
	streamBuilderInfoCtx, span := s.tracer.Start(ctx, "streamBuilderInfo-start")
	defer span.End(trace.WithTimestamp(time.Now().UTC()))
	id := uuid.NewString()
	client.NodeID = fmt.Sprintf("%v-%v-%v-%v", s.nodeID, client.URL, id, time.Now().UTC().Format("15:04:05.999999999"))
	stream, err := client.StreamBuilder(ctx, &relaygrpc.StreamBuilderRequest{
		ReqId:   id,
		NodeId:  client.NodeID,
		Version: s.version,
	})
	logMetric := NewLogMetric(
		[]zap.Field{
			zap.String("method", method),
			zap.String("nodeID", client.NodeID),
			zap.String("reqID", id),
			zap.String("url", client.URL),
		},
		[]attribute.KeyValue{
			attribute.String("method", method),
			attribute.String("nodeID", client.NodeID),
			attribute.String("url", client.URL),
			attribute.String("reqID", id),
		},
	)
	span.SetAttributes(logMetric.GetAttributes()...)

	s.logger.Info("streaming builder info", logMetric.GetFields()...)
	if err != nil {
		logMetric.Error(err)
		s.logger.Warn("failed to stream builderInfo", logMetric.GetFields()...)
		span.SetStatus(otelcodes.Error, err.Error())
		return nil, err
	}
	done := make(chan struct{})
	var once sync.Once
	closeDone := func() {
		once.Do(func() {
			s.logger.Info("calling close done once")
			close(done)
		})
	}
	logMetricCopy := logMetric.Copy()
	go func(lm *LogMetric) {
		select {
		case <-stream.Context().Done():
			lm.Error(stream.Context().Err())
			s.logger.Warn("stream context cancelled, closing connection", lm.GetFields()...)
			closeDone()
		case <-ctx.Done():
			logMetric.Error(ctx.Err())
			s.logger.Warn("context cancelled, closing connection", lm.GetFields()...)
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
			s.logger.With(zap.Error(err)).Warn("stream received EOF", logMetric.GetFields()...)
			streamReceiveSpan.SetStatus(otelcodes.Error, err.Error())
			closeDone()
			break
		}
		_s, ok := status.FromError(err)
		if !ok {
			s.logger.With(zap.Error(err)).Warn("invalid grpc error status", logMetric.GetFields()...)
			streamReceiveSpan.SetStatus(otelcodes.Error, "invalid grpc error status")
			continue
		}

		if _s.Code() == codes.Canceled {
			logMetric.Error(err)
			s.logger.With(zap.Error(err)).Warn("received cancellation signal, shutting down", logMetric.GetFields()...)
			// mark as canceled to stop the upstream retry loop
			streamReceiveSpan.SetStatus(otelcodes.Error, "received cancellation signal")
			closeDone()
			break
		}

		if _s.Code() != codes.OK {
			s.logger.With(zap.Error(_s.Err())).With(zap.String("code", _s.Code().String())).Warn("server unavailable,try reconnecting", logMetric.GetFields()...)
			streamReceiveSpan.SetStatus(otelcodes.Error, "server unavailable,try reconnecting")
			closeDone()
			break
		}
		if err != nil {
			s.logger.With(zap.Error(err)).Warn("failed to receive stream, disconnecting the stream", logMetric.GetFields()...)
			streamReceiveSpan.SetStatus(otelcodes.Error, err.Error())
			closeDone()
			break
		}
		// Added empty streaming as a temporary workaround to maintain streaming alive
		// TODO: this need to be handled by adding settings for keep alive params on both server and client
		if len(builderInfoResponse.GetBuilderInfo()) == 0 {
			s.logger.Warn("received empty stream", logMetric.GetFields()...)
			continue
		}
		processTime := time.Since(receivedAt).Milliseconds()
		go s.handleStreamBuilderInfoResponse(streamBuilderInfoCtx, builderInfoResponse, logMetric, receivedAt, parentSpan.SpanContext().TraceID().String(), method, clientIP, processTime)
	}
	<-done
	streamReceiveSpan.SetAttributes(logMetric.GetAttributes()...)
	streamReceiveSpan.End(trace.WithTimestamp(time.Now()))

	s.logger.Warn("closing connection", logMetric.GetFields()...)
	return nil, nil
}

func (s *Service) handleStreamBuilderInfoResponse(ctx context.Context, builderInfoResponse *relaygrpc.StreamBuilderResponse, logMetric *LogMetric, receivedAt time.Time, traceId string, method string, clientIP string, processTime int64) {
	// check if the block hash has already been received
	handleStart := time.Now().UTC()
	lm := logMetric.Copy()
	builderInfos := builderInfoResponse.GetBuilderInfo()
	if len(builderInfos) == 0 {
		s.logger.Warn("received empty builderInfo stream", lm.GetFields()...)
		return
	}
	numBuilderInfos := len(builderInfos)
	builderInfoPubkeys := make([]string, numBuilderInfos)
	optimisticBuilders := make([]string, 0, numBuilderInfos)
	demotedBuilders := make([]string, 0, numBuilderInfos)
	for i := 0; i < numBuilderInfos; i++ {
		builderInfo := builderInfos[i]
		builderPubkey := phase0.BLSPubKey(builderInfos[i].BuilderPubkey)
		builderPubkeyStr := builderPubkey.String()
		builderInfoPubkeys[i] = builderPubkeyStr
		grpcWalletAccounts := builderInfo.GetWalletAccounts()
		walletAccounts := []common.WalletAccount{}
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
				s.logger.Info("updating wallet account", zap.String("pubkey", wallet.Pubkey.String()), zap.Uint64("lastUpdatedBlock", wallet.LastUpdatedBlock), zap.Uint64("balance", wallet.Balance.Uint64()), zap.Uint64("nonce", wallet.Nonce.Uint64()), zap.String("accountID", builderInfo.ExternalBuilderAccountId))
				(*s.walletAccounts)[wallet.Pubkey.String()].Balance = wallet.Balance
				(*s.walletAccounts)[wallet.Pubkey.String()].LastUpdatedBlock = wallet.LastUpdatedBlock
				(*s.walletAccounts)[wallet.Pubkey.String()].Nonce = wallet.Nonce
			}
		}
		s.builderInfo.Set(builderPubkeyStr, newBuilderInfo, cache.DefaultExpiration)
	}
	lm.Fields(
		zap.Strings("builderInfoPubkeys", builderInfoPubkeys),
		zap.Strings("demotedBuilders", demotedBuilders),
		zap.Strings("optimisticBuilders", optimisticBuilders),
		zap.Time("receivedAt", receivedAt),
		zap.Duration("duration", time.Since(handleStart)),
	)
	s.logger.Info("received builderInfo", lm.GetFields()...)
}

func (s *Service) logRecord(record SlotStatsRecord, slotKey string, userAgent string) {
	s.slotStats.Get(slotKey)
	s.logger.Info("emit slot stats event", zap.String("slotKey", slotKey), zap.String("validatorID", record.ValidatorID), zap.String("accountID", record.AccountID), zap.String("userAgent", userAgent))
	s.fluentD.LogToFluentD(fluentstats.Record{
		Type: TypeRelayProxySlotStats,
		Data: record,
	}, time.Now().UTC(), s.nodeID, StatsRelayProxySlotStats)
}

func (s *Service) prefetchPayload(ctx context.Context, client *common.Client, req *relaygrpc.PreFetchGetPayloadRequest, span trace.Span, errChan chan *ErrorResp, respChan chan *relaygrpc.PreFetchGetPayloadResponse, logger *zap.Logger) {
	clientCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	exitSignal := false
	wg := &sync.WaitGroup{}
	mu := &sync.Mutex{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5 && !exitSignal; i++ {
			out, err := client.PreFetchGetPayload(clientCtx, req)
			if exitSignal {
				return
			}
			if err != nil {
				logger.Error("prefetchPayload :: error fetching payload", zap.Error(err))
				span.SetStatus(otelcodes.Error, err.Error())
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if out == nil {
				logger.Error("prefetchPayload :: received nil payload from relay", zap.String("url", client.URL))
				span.SetStatus(otelcodes.Error, "nil payload")
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if out.Code != uint32(codes.OK) {
				logger.With(zap.Uint32("code", out.Code), zap.String("Message", out.Message)).Error("prefetchPayload :: invalid payload or failure response code", zap.String("url", client.URL))
				span.SetStatus(otelcodes.Error, out.Message)
				time.Sleep(100 * time.Millisecond)
				continue
			}

			logger.Info("prefetchPayload :: preFetchGetPayload succeeded", zap.String("url", client.URL))
			mu.Lock()
			if !exitSignal {
				exitSignal = true
				respChan <- out
				cancel()
			}
			mu.Unlock()
			return
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5 && !exitSignal; i++ {
			out, err := s.PreFetchGetPayloadPlaceHTTPRequest(clientCtx, req, client.URL, client.NodeID)
			if exitSignal {
				return
			}
			if err != nil {
				logger.Error("prefetchPayload :: error fetching payload", zap.Error(err))
				span.SetStatus(otelcodes.Error, err.Error())
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if out == nil {
				logger.Error("prefetchPayload :: received nil payload from relay", zap.String("url", client.URL))
				span.SetStatus(otelcodes.Error, "nil payload")
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if out.Code != uint32(codes.OK) {
				logger.With(zap.Uint32("code", out.Code), zap.String("Message", out.Message)).Error("prefetchPayload :: invalid payload or failure response code", zap.String("url", client.URL))
				span.SetStatus(otelcodes.Error, out.Message)
				time.Sleep(100 * time.Millisecond)
				continue
			}

			logger.Info("prefetchPayload :: preFetchGetPayload succeeded", zap.String("url", client.URL))
			mu.Lock()
			if !exitSignal {
				exitSignal = true
				respChan <- out
				cancel()
			}
			mu.Unlock()
			return
		}
	}()

	wg.Wait()
	if exitSignal {
		return
	}
	errChan <- toErrorResp(http.StatusInternalServerError, "relay failed all attempt", zap.String("url", client.URL))

}

func (s *Service) PreFetchGetPayloadPlaceHTTPRequest(ctx context.Context, origReq *relaygrpc.PreFetchGetPayloadRequest, url string, nodeID string) (*relaygrpc.PreFetchGetPayloadResponse, error) {
	reqData := common.PreFetchGetPayloadRequestHTTP{
		Slot:       origReq.GetSlot(),
		ParentHash: origReq.GetParentHash(),
		BlockHash:  origReq.GetBlockHash(),
		Pubkey:     origReq.GetPubkey(),
		ClientIp:   origReq.GetClientIp(),
		ReceivedAt: origReq.GetReceivedAt(),
	}
	reqJSON, err := json.Marshal(reqData)
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
	s.logger.Info("making prefetch request", zap.String("nodeID", nodeID), zap.String("url", finalURL), zap.String("originalURL", originalURL))
	req, err := http.NewRequest("GET", finalURL, bytes.NewReader(reqJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var respData common.PreFetchGetPayloadResponseHTTP
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil && err != io.EOF {
		return nil, err
	}
	return &relaygrpc.PreFetchGetPayloadResponse{
		Code:                      respData.Code,
		Message:                   respData.Message,
		VersionedExecutionPayload: respData.VersionedExecutionPayload,
	}, nil
}
func (s *Service) StartStreamSlotInfo(ctx context.Context, wg *sync.WaitGroup) {
	for _, client := range s.streamingBlockClients {
		wg.Add(1)
		go func(_ctx context.Context, c *common.Client) {
			defer wg.Done()
			s.handleSlotInfoStream(_ctx, c)
		}(ctx, client)
	}
	wg.Wait()
}
func (s *Service) handleSlotInfoStream(ctx context.Context, client *common.Client) {
	parentSpan := trace.SpanFromContext(ctx)
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)

	for {
		select {
		case <-ctx.Done():
			s.logger.Warn("stream block context cancelled",
				zap.String("traceID", parentSpan.SpanContext().TraceID().String()),
			)
			return
		default:
			if _, err := s.StreamSlotInfo(ctx, client); err != nil {
				s.logger.Warn("failed to stream SlotInfo. Sleeping and then reconnecting",
					zap.String("url", client.URL),
					zap.String("traceID", parentSpan.SpanContext().TraceID().String()),
					zap.Error(err))
			} else {
				s.logger.Warn("stream SlotInfo stopped.  Sleeping and then reconnecting",
					zap.String("url", client.URL),
					zap.String("traceID", parentSpan.SpanContext().TraceID().String()),
				)
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
		s.logger.Warn("failed to split host port", zap.Error(err))
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
		[]zap.Field{
			zap.String("method", method),
			zap.String("nodeID", client.NodeID),
			zap.String("reqID", id),
			zap.String("url", client.URL),
		},
		[]attribute.KeyValue{
			attribute.String("method", method),
			attribute.String("nodeID", client.NodeID),
			attribute.String("url", client.URL),
			attribute.String("reqID", id),
		},
	)
	span.SetAttributes(logMetric.GetAttributes()...)

	s.logger.Info("streaming Validator info", logMetric.GetFields()...)
	if err != nil {
		logMetric.Error(err)
		s.logger.Warn("failed to stream SlotInfo", logMetric.GetFields()...)
		span.SetStatus(otelcodes.Error, err.Error())
		return nil, err
	}
	done := make(chan struct{})
	var once sync.Once
	closeDone := func() {
		once.Do(func() {
			s.logger.Info("calling close done once")
			close(done)
		})
	}
	logMetricCopy := logMetric.Copy()
	go func(lm *LogMetric) {
		select {
		case <-stream.Context().Done():
			lm.Error(stream.Context().Err())
			s.logger.Warn("stream context cancelled, closing connection", lm.GetFields()...)
			closeDone()
		case <-ctx.Done():
			logMetric.Error(ctx.Err())
			s.logger.Warn("context cancelled, closing connection", lm.GetFields()...)
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
			s.logger.With(zap.Error(err)).Warn("stream received EOF", logMetric.GetFields()...)
			streamReceiveSpan.SetStatus(otelcodes.Error, err.Error())
			closeDone()
			break
		}
		_s, ok := status.FromError(err)
		if !ok {
			s.logger.With(zap.Error(err)).Warn("invalid grpc error status", logMetric.GetFields()...)
			streamReceiveSpan.SetStatus(otelcodes.Error, "invalid grpc error status")
			continue
		}

		if _s.Code() == codes.Canceled {
			logMetric.Error(err)
			s.logger.With(zap.Error(err)).Warn("received cancellation signal, shutting down", logMetric.GetFields()...)
			// mark as canceled to stop the upstream retry loop
			streamReceiveSpan.SetStatus(otelcodes.Error, "received cancellation signal")
			closeDone()
			break
		}

		if _s.Code() != codes.OK {
			s.logger.With(zap.Error(_s.Err())).With(zap.String("code", _s.Code().String())).Warn("server unavailable,try reconnecting", logMetric.GetFields()...)
			streamReceiveSpan.SetStatus(otelcodes.Error, "server unavailable,try reconnecting")
			closeDone()
			break
		}
		if err != nil {
			s.logger.With(zap.Error(err)).Warn("failed to receive stream, disconnecting the stream", logMetric.GetFields()...)
			streamReceiveSpan.SetStatus(otelcodes.Error, err.Error())
			closeDone()
			break
		}
		// Added empty streaming as a temporary workaround to maintain streaming alive
		// TODO: this need to be handled by adding settings for keep alive params on both server and client
		if SlotInfoResponse == nil || SlotInfoResponse.LastUpdatedBlock == 0 {
			s.logger.Warn("received empty stream", logMetric.GetFields()...)
			continue
		}
		processTime := time.Since(receivedAt).Milliseconds()
		go s.handleStreamSlotInfoResponse(streamSlotInfoCtx, SlotInfoResponse, logMetric, receivedAt, parentSpan.SpanContext().TraceID().String(), method, clientIP, processTime)
	}
	<-done
	streamReceiveSpan.SetAttributes(logMetric.GetAttributes()...)
	streamReceiveSpan.End(trace.WithTimestamp(time.Now()))

	s.logger.Warn("closing connection", logMetric.GetFields()...)
	return nil, nil
}

func (s *Service) handleStreamSlotInfoResponse(ctx context.Context, SlotInfoResponse *relaygrpc.StreamSlotResponse, logMetric *LogMetric, receivedAt time.Time, traceId string, method string, clientIP string, processTime int64) {
	// check if the block hash has already been received
	lm := logMetric.Copy()
	proposerPubkey := phase0.BLSPubKey(SlotInfoResponse.GetProposerPubkey())
	proposerFeeRecipient := bellatrix.ExecutionAddress(SlotInfoResponse.GetProposerFeeRecipient())
	isEOA := SlotInfoResponse.IsEoa
	slot := SlotInfoResponse.GetSlot()
	lastUpdatedBlock := SlotInfoResponse.GetLastUpdatedBlock()
	parentBlockRoot := phase0.Root(SlotInfoResponse.GetParentBlockRoot())
	oldProposer, found := s.miniProposerSlotMap.Load(slot)

	lm.Fields(
		zap.String("proposerPubkey", proposerPubkey.String()),
		zap.Uint64("slot", slot),
		zap.String("feeRecipient", proposerFeeRecipient.String()),
		zap.Uint64("lastUpdatedBlock", lastUpdatedBlock),
		zap.String("parentBlockRoot", parentBlockRoot.String()),
		zap.Bool("isEOA", isEOA),
	)
	lm.Attributes(
		attribute.String("proposerPubkey", proposerPubkey.String()),
		attribute.Int64("slot", int64(slot)),
		attribute.String("feeRecipient", proposerFeeRecipient.String()),
		attribute.Int64("lastUpdatedBlock", int64(lastUpdatedBlock)),
		attribute.String("parentBlockRoot", parentBlockRoot.String()),
		attribute.Bool("isEOA", isEOA),
	)

	if !found || oldProposer == nil {
		s.logger.Error("slot not found in mini proposer slot map", lm.GetFields()...)
		return
	}

	lm.Fields(
		zap.String("oldProposerPubkey", oldProposer.Registration.Message.Pubkey.String()),
		zap.String("oldProposerFeeRecipient", oldProposer.Registration.Message.FeeRecipient.String()),
		zap.Int64("oldProposerLastUpdatedBlock", int64(oldProposer.LastUpdatedBlock)),
		zap.String("oldProposerIsEOA", strconv.FormatBool(oldProposer.IsEOA)),
	)
	lm.Attributes(
		attribute.String("oldProposerPubkey", oldProposer.Registration.Message.Pubkey.String()),
		attribute.String("oldProposerFeeRecipient", oldProposer.Registration.Message.FeeRecipient.String()),
		attribute.Int64("oldProposerLastUpdatedBlock", int64(oldProposer.LastUpdatedBlock)),
		attribute.String("oldProposerIsEOA", strconv.FormatBool(oldProposer.IsEOA)),
	)

	if oldProposer.Registration.Message.Pubkey != proposerPubkey {
		s.logger.Error("slot pubkey mismatch", lm.GetFields()...)
	} else if oldProposer.Registration.Message.FeeRecipient != proposerFeeRecipient {
		s.logger.Error("slot fee recipient mismatch", lm.GetFields()...)
	} else {
		if oldProposer.LastUpdatedBlock < lastUpdatedBlock {
			oldProposer.IsEOA = isEOA
			oldProposer.LastUpdatedBlock = lastUpdatedBlock
			oldProposer.ExpectedParentBlockRoot = parentBlockRoot
			s.miniProposerSlotMap.Store(slot, oldProposer)
			s.logger.Info("updating mini proposer slot map", lm.GetFields()...)
		}
	}
	s.logger.Info("received slot", lm.GetFields()...)
}
