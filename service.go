package relayproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	eth2Api "github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	relaygrpc "github.com/bloXroute-Labs/relay-grpc"
	"github.com/bloXroute-Labs/relay-grpc/optimisticv3"
	"github.com/bloXroute-Labs/relay-grpc/stat"
	"github.com/bloXroute-Labs/relayproxy/common"
	"github.com/bloXroute-Labs/relayproxy/fluentstats"
	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	regRequestTimeout        = 7 * time.Second // Corresponds to the recent stats where p90 was 1.3s and p99 6.68s
	preFetcherRequestTimeout = 3 * time.Second

	// cache
	BuilderBidsCleanupInterval      = 36 * time.Second // 3 slots
	ExecutionPayloadCleanupInterval = 36 * time.Second // 3 slots
	slotStatsCleanupInterval        = 36 * time.Second // 3 slots
	cacheKeySeparator               = "_"

	maxGetPayloadRetry                = 3
	getPayloadInterval                = 150 * time.Millisecond
	preFetchPayloadChanBufSize        = 1000
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
	GetHeader(parentSpan trace.Span, ctx context.Context, log *zerolog.Logger, in *HeaderRequestParams) (json.RawMessage, *common.OnHeaderDeliveredParams, error)
	GetPayload(ctx context.Context, log *zerolog.Logger, in *PayloadRequestParams) (*common.VersionedPayloadInfo, error)
	GetPayloadV2(ctx context.Context, log *zerolog.Logger, in *PayloadRequestParams) error
}

type Service struct {
	// data service
	IDataService

	logger      zerolog.Logger
	version     string // build version
	nodeID      string // UUID
	authKey     string
	secretToken string

	tracer                          trace.Tracer
	fluentD                         fluentstats.Stats
	builderBidsForProxySlot         *cache.Cache
	allBidsLock                     sync.RWMutex
	allBidsMetadataForProxySlot     *cache.Cache
	builderExistingBlockHash        *cache.Cache
	getPayloadResponseForProxySlot  *cache.Cache
	preFetchPayloadChan             chan preFetcherFields
	optimisticV3FetchedPayloadsChan chan *common.VersionedSubmitBlockRequest
	performancestats                *stat.PerformanceStats

	beaconGenesisTime     int64
	secondsPerSlot        int64
	slotStatsHeaderEvents *cache.Cache
	slotStatsPayloadEvent *cache.Cache
	duplicateSlotCache    *cache.Cache
	slotStatsEventCh      chan slotStatsEvent
	ethNetworkDetails     *common.EthNetworkDetails

	clients                       []*common.ParentClient
	streamingClients              []*common.ParentClient
	uniqueStreamingClients        []*common.ParentClient
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
	BlockPublishFunc             func(tracer trace.Tracer, logger zerolog.Logger, payloadInfo *common.VersionedPayloadInfo, signedBeaconBlock *common.VersionedSignedBlindedBeaconBlock, blockPublishingGatewayClient interface{}, authKey string)
	OnPayloadRequested           func(slot uint64, blockHash string, parentHash string, proposerPubkey string, getPayloadRequestClientIP string, receivedAt time.Time, signedBlindedBeaconBlock *eth2Api.VersionedSignedBlindedBeaconBlock, ProposerRequestStartTimeUnixMS int64, validatorID string) error
	OnHeaderBidRetrieved         func(ctx context.Context, topBid *common.Bid, lookbackTopBid *common.BidMetadata, log zerolog.Logger, slot uint64, parentHash string, accountID string, replacemendDelayMs int64, clients []*common.ParentClient) (*common.Bid, bool, error)
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

	slotStartTime                     time.Time
	msIntoSlotGetHeaderIncludingDelay int64 // when getHeader was called + include delay
	getHeaderReqID                    string
}

func NewService(opts ...ServiceOption) *Service {

	svc := &Service{
		preFetchPayloadChan:           make(chan preFetcherFields, preFetchPayloadChanBufSize),
		slotStatsHeaderEvents:         cache.New(slotStatsCleanupInterval, slotStatsCleanupInterval),
		slotStatsPayloadEvent:         cache.New(slotStatsCleanupInterval, slotStatsCleanupInterval),
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

		var blockSequenceNumber *uint64
		headerBlockSequenceNumber := header.GetBlockSequenceNumber()
		if headerBlockSequenceNumber != 0 {
			blockSequenceNumber = &headerBlockSequenceNumber
		}

		// Process header
		lm := logMetric.Copy()

		keyForCachingBids := s.keyForCachingBids(header.GetSlot(), header.GetParentHash(), header.GetPubkey())
		uniqueKey := fmt.Sprintf("slot_%v_bHash_%v_pHash_%v", header.GetSlot(), header.GetBlockHash(), header.GetParentHash())

		lm.Fields(map[string]any{
			"keyForCachingBids":   keyForCachingBids,
			"slot":                header.GetSlot(),
			"in.ParentHash":       header.GetParentHash(),
			"blockHash":           header.GetBlockHash(),
			"pubKey":              header.GetPubkey(),
			"builderPubKey":       header.GetBuilderPubkey(),
			"extraData":           header.GetBuilderExtraData(),
			"traceID":             parentSpan.SpanContext().TraceID().String(),
			"uniqueKey":           uniqueKey,
			"receivedAt":          receivedAt,
			"paidBlxr":            header.GetPaidBlxr(),
			"accountID":           header.GetAccountId(),
			"payloadFetchUrl":     header.GetPayloadFetchUrl(),
			"blockSequenceNumber": header.GetBlockSequenceNumber(),
			"hidden":              header.GetHidden(),
		})

		if s.skipBidForOldBlockSequenceNumber(keyForCachingBids, header.GetBuilderPubkey(), blockSequenceNumber) {
			continue
		}

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

			s.logger.Debug().Fields(lm.GetFields()).Msg("block hash already exists")
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

		s.logger.Debug().Fields(lm.GetFields()).Msg("received header")

		//_ = HeaderStreamReceivedRecord{
		//	RelayReceivedAt:   header.GetRelayReceiveTime().AsTime(),
		//	ReceivedAt:        receivedAt,
		//	SentAt:            header.GetSendTime().AsTime(),
		//	StreamLatencyInMS: latency,
		//	Slot:              int64(header.GetSlot()),
		//	ParentHash:        header.GetParentHash(),
		//	PubKey:            header.GetPubkey(),
		//	BlockHash:         header.GetBlockHash(),
		//	BlockValue:        weiToEther(new(big.Int).SetBytes(header.GetValue())),
		//	BuilderPubKey:     header.GetBuilderPubkey(),
		//	BuilderExtraData:  header.GetBuilderExtraData(),
		//	PaidBLXR:          header.GetPaidBlxr(),
		//	ClientIP:          GetHost(client.URL),
		//	NodeID:            s.nodeID,
		//	AccountID:         header.GetAccountId(),
		//	Method:            method,
		//	PayloadFetchUrl:   header.GetPayloadFetchUrl(),
		//}

		//go func(streamCopy HeaderStreamReceivedRecord) {
		//	s.fluentD.LogToFluentD(fluentstats.Record{
		//		Type: TypeRelayProxyHeaderStreamReceived,
		//		Data: streamCopy,
		//	}, time.Now().UTC(), s.nodeID, StatsRelayProxyHeaderStreamReceived)
		//}(headerStream)

		// Store the bid for builder pubkey
		_, storeBidsSpan := s.tracer.Start(streamReceiveCtx, "StreamHeader-storeBids")
		payloadURL := "grpc;" + client.URL
		forkVersion := common.GetCurrentForkVersion()
		headerSubmissionV3, err := optimisticv3.RelayGrpcHeaderSubmissionToVersioned(header, []byte(payloadURL), forkVersion)
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
			header.GetRelayReceiveTime().AsTime(),
			"",
			blockSequenceNumber,
			header.GetHidden(),
		)

		s.setBuilderBidForProxySlot(keyForCachingBids, header.GetBuilderPubkey(), bid, header.GetSlot())
		s.setBidMetadataForProxySlot(keyForCachingBids, common.NewBidMetadata(bid))

		storeBidsSpan.SetAttributes(
			attribute.String("method", method),
			attribute.String("nodeID", client.NodeID),
			attribute.String("url", client.URL),
			attribute.String("reqID", id),
			attribute.String("blockValue", new(big.Int).SetBytes(header.GetValue()).String()),
			attribute.String("relayReceiveAt", header.GetRelayReceiveTime().AsTime().String()),
			attribute.String("streamSentAt", header.GetSendTime().AsTime().String()),
			attribute.Int64("streamLatencyInMs", latency),

			attribute.String("keyForCachingBids", keyForCachingBids),
			attribute.Int64("slot", int64(header.GetSlot())),
			attribute.String("in.ParentHash", header.GetParentHash()),
			attribute.String("blockHash", header.GetBlockHash()),
			attribute.String("pubKey", header.GetPubkey()),
			attribute.String("builderPubKey", header.GetBuilderPubkey()),
			attribute.String("extraData", header.GetBuilderExtraData()),
			attribute.String("traceID", parentSpan.SpanContext().TraceID().String()),
			attribute.String("uniqueKey", uniqueKey),
			attribute.String("receivedAt", receivedAt.String()),
			attribute.Bool("paidBlxr", header.GetPaidBlxr()),
			attribute.String("accountID", header.GetAccountId()),
			attribute.String("payloadFetchUrl", header.GetPayloadFetchUrl()),
			attribute.Bool("hidden", header.GetHidden()),
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

func (s *Service) keyForCachingBids(slot uint64, parentHash string, proposerPubkey string) string {
	return fmt.Sprintf("%d_%s_%s", slot, strings.ToLower(parentHash), strings.ToLower(proposerPubkey))
}

func (s *Service) GetTopBuilderBid(cacheKey string) (*common.Bid, *common.Bid, *common.BidMetadata, error) {
	var builderBidsMap *SyncMap[string, *common.Bid]
	entry, bidsMapFound := s.builderBidsForProxySlot.Get(cacheKey)
	if bidsMapFound {
		builderBidsMap = entry.(*SyncMap[string, *common.Bid])
	}

	if !bidsMapFound || builderBidsMap == nil || builderBidsMap.Size() == 0 {
		return nil, nil, nil, fmt.Errorf("no builder bids found for cache key %s", cacheKey)
	}

	topBid := new(common.Bid)
	topBidValue := new(big.Int)
	secondBid := new(common.Bid)
	secondBidValue := new(big.Int)

	// search for the highest builder bid
	builderBidsMap.Range(func(builderPubkey string, bid *common.Bid) bool {
		bidValue := new(big.Int).SetBytes(bid.Value)
		if bidValue.Cmp(topBidValue) > 0 {
			secondBid = topBid
			secondBidValue.Set(topBidValue)
			topBid = bid
			topBidValue.Set(bidValue)
		}
		return true
	})

	topLookbackbid := s.getTopLookBackBid(cacheKey, 200*time.Millisecond)

	return topBid, secondBid, topLookbackbid, nil
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
			if !common.ReplaceBid(bid, bidEntry) {
				return
			}
		}
	}
	builderBidsMap.Store(builderPubkey, bid)
}

func (s *Service) setBidMetadataForProxySlot(cacheKey string, bidMetadata *common.BidMetadata) {
	s.allBidsLock.Lock()
	defer s.allBidsLock.Unlock()

	var allBidsForSlot []*common.BidMetadata

	// If the cache key does not exist, create a new slice and store it in the cache
	if entry, bidsFound := s.allBidsMetadataForProxySlot.Get(cacheKey); !bidsFound {
		allBidsForSlot = make([]*common.BidMetadata, 0, 1000)
	} else {
		// Otherwise use the existing slice
		var ok bool
		allBidsForSlot, ok = entry.([]*common.BidMetadata)
		if !ok {
			s.logger.Warn().Str("cacheKey", cacheKey).Msg("Bid adjustment test - failed to cast allBidsForSlot slice in Service 'setBidMetadataForProxySlot'")
			return
		}
	}

	allBidsForSlot = append(allBidsForSlot, bidMetadata)

	s.allBidsMetadataForProxySlot.Set(cacheKey, allBidsForSlot, cache.DefaultExpiration)
}

func (s *Service) getTopLookBackBid(cacheKey string, lookbackTime time.Duration) *common.BidMetadata {
	start := time.Now().UTC()

	s.allBidsLock.RLock()
	defer s.allBidsLock.RUnlock()

	entry, bidsMapFound := s.builderBidsForProxySlot.Get(cacheKey)
	if !bidsMapFound {
		s.logger.Warn().Str("cacheKey", cacheKey).Msg("Bid adjustment test - no top lookback bid found for cache key in Service 'getTopLookBackBid'")
		return nil
	}

	allBidsForSlot, ok := entry.([]*common.BidMetadata)
	if !ok {
		s.logger.Warn().Str("cacheKey", cacheKey).Msg("Bid adjustment test - failed to cast allBidsForSlot slice in Service 'getTopLookBackBid'")
		return nil
	}

	now := time.Now().UTC()
	maxBidAdjustmentTargetTimestamp := now.Add(lookbackTime)

	// Get best bid in time range by for each builder pubkey
	bestBuilderBidByPubkey := make(map[string]*common.BidMetadata)
	for _, bid := range allBidsForSlot {
		// Skip bids after max target timestamp
		// TODO: is "ReceivedAt" ok to use here?
		if bid.ReceivedAt.After(maxBidAdjustmentTargetTimestamp) {
			continue
		}

		existingBid, found := bestBuilderBidByPubkey[bid.BuilderPubkey]

		// If there is no bid in the map for this pubkey, add the bid and continue
		if !found {
			bestBuilderBidByPubkey[bid.BuilderPubkey] = bid
			continue
		}

		// Otherwise compare to bid sequence numbers
		if bid.BlockSequenceNumber != nil &&
			existingBid.BlockSequenceNumber != nil &&
			*bid.BlockSequenceNumber > *existingBid.BlockSequenceNumber {
			bestBuilderBidByPubkey[bid.BuilderPubkey] = bid
			continue
		}

		// Then compare bid receive times if necessary
		if bid.ReceivedAt.After(existingBid.ReceivedAt) {
			bestBuilderBidByPubkey[bid.BuilderPubkey] = bid
		}
	}

	// Get the overall top lookback bid from top builder bids
	var topLookBackBid *common.BidMetadata
	topLookBackBidValue := big.NewInt(0)

	for _, bid := range bestBuilderBidByPubkey {
		bidValue := new(big.Int).SetBytes(bid.Value)
		if bidValue.Cmp(topLookBackBidValue) > 0 {
			topLookBackBid = bid
		}
	}

	// Get info for log if non-nil
	lookbackTopBidBlockHash := ""
	lookbackTopBidBuilderPubkey := ""
	lookbackTopBidBuilderExtraData := ""
	var lookbackTopBidTimestamp time.Time

	if topLookBackBid != nil {
		lookbackTopBidBlockHash = topLookBackBid.BlockHash
		lookbackTopBidBuilderPubkey = topLookBackBid.BuilderPubkey
		lookbackTopBidBuilderExtraData = topLookBackBid.BuilderExtraData
		lookbackTopBidTimestamp = topLookBackBid.ReceivedAt
	}

	s.logger.Info().
		Int64("durationMs", time.Since(start).Milliseconds()).
		Str("now", now.Format(time.RFC3339Nano)).
		Str("maxBidAdjustmentTargetTimestamp", maxBidAdjustmentTargetTimestamp.Format(time.RFC3339Nano)).
		Str("lookbackTopBidTimestamp", lookbackTopBidTimestamp.Format(time.RFC3339Nano)).
		Str("lookbackTopBidBlockHash", lookbackTopBidBlockHash).
		Str("lookbackTopBidValue", topLookBackBidValue.String()).
		Str("lookbackTopBidBuilderPubkey", lookbackTopBidBuilderPubkey).
		Str("lookbackTopBidBuilderExtraData", lookbackTopBidBuilderExtraData).
		Bool("lookbackTopBidFound", topLookBackBid != nil).
		Msg("Bid adjustment test - Service 'getTopLookBackBid' completed")

	return topLookBackBid
}

func (s *Service) getBuilderBidForSlot(cacheKey string, builderPubkey string) (*common.Bid, bool) {
	if entry, bidsMapFound := s.builderBidsForProxySlot.Get(cacheKey); bidsMapFound {
		builderBidsMap := entry.(*SyncMap[string, *common.Bid])
		builderBid, found := builderBidsMap.Load(builderPubkey)
		return builderBid, found
	}
	return nil, false
}

func (s *Service) skipBidForOldBlockSequenceNumber(cacheKey string, builderPubkey string, blockSequenceNumber *uint64) bool {
	existingBid, found := s.getBuilderBidForSlot(cacheKey, builderPubkey)
	if !found || existingBid.BlockSequenceNumber == nil || blockSequenceNumber == nil {
		return false
	}

	skipBid := *blockSequenceNumber <= *existingBid.BlockSequenceNumber
	if skipBid {
		s.logger.Warn().
			Uint64("existingBlockSequenceNumber", *existingBid.BlockSequenceNumber).
			Uint64("blockSequenceNumber", *blockSequenceNumber).
			Str("cacheKey", cacheKey).
			Str("builderPubkey", builderPubkey).
			Msg("skipping bid for old block sequence number")
	}

	return skipBid
}

func (s *Service) EmitSlotStats(ctx context.Context) {
	for {
		select {
		case event := <-s.slotStatsEventCh: // On getheader
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
					v, ok := s.slotStatsPayloadEvent.Get(event.SlotKey)
					if ok { //Populated when getPayloadOnly is called
						record, success := v.(SlotStatsRecord)
						if success {
							s.logRecord(record, event.SlotKey, event.UserAgent)
						} else {
							// For now this condition should not happen
							slotStats, found := s.slotStatsHeaderEvents.Get(event.SlotKey)
							if found {
								if records, slotStatsSuccess := slotStats.([]SlotStatsRecord); slotStatsSuccess {
									slotStatsRecord := records[len(records)-1]
									s.logRecord(slotStatsRecord, event.SlotKey, event.UserAgent)
								}
							}
						}
					} else {
						slotStats, found := s.slotStatsHeaderEvents.Get(event.SlotKey)
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
	s.slotStatsHeaderEvents.Get(slotKey)
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
