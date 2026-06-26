package relayproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/bloXroute-Labs/relayproxy/common"
	"github.com/bloXroute-Labs/relayproxy/fastjson"
	"github.com/bloXroute-Labs/relayproxy/fluentstats"
)

type GetHeaderSleepData struct {
	MsIntoSlotIncludingDelay int64
	SleepMs                  int64
	MaxSleepMs               int64
	UsedRepick               bool
}

func (s *Service) GetHeader(parentSpan trace.Span, parentCtx context.Context, log *zerolog.Logger, in *HeaderRequestParams) (json.RawMessage, *common.OnHeaderDeliveredParams, error) {
	id := uuid.NewString()
	ctx, span := s.tracer.Start(parentCtx, "getHeader-start")
	defer span.End()

	slotKey := "slot-" + in.Slot + "-parentHash-" + in.ParentHash
	var (
		err           error
		isValidatorIP bool
	)

	_slot, err := fastParseUint(in.Slot)
	if err != nil {
		return nil, nil, toErrorResp(http.StatusBadRequest, errInvalidSlot.Error())
	}

	validatorInfo, found := s.miniProposerSlotMap.Load(_slot)
	if found && validatorInfo != nil && IsValidatorIP(validatorInfo.IPAddresses, validatorInfo.IPAddress, in.ClientIP) {
		isValidatorIP = true
	}

	slotStartTime := GetSlotStartTime(s.beaconGenesisTime, int64(_slot), s.secondsPerSlot)
	latency := in.Latency
	startTime := time.Now().UTC()

	*log = log.With().
		Str("slotKey", slotKey).
		Str("reqID", id).
		Int64("slotStartTimeUnix", slotStartTime.Unix()).
		Str("slotStartTime", slotStartTime.UTC().String()).
		Uint64("headerTimeoutMS", in.HeaderTimeoutMs).
		Logger()

	log.Info().Msg("received getHeader")

	msIntoSlot := in.ReceivedAt.Sub(slotStartTime).Milliseconds() // without sleep and using received at
	*log = log.With().
		Int64("receivedAtMsIntoSlot", msIntoSlot).
		Logger()

	_, storingHeaderSpan := s.tracer.Start(ctx, "getHeader-storingHeader")

	//TODO: send fluentd stats for StatusBadRequest error cases

	if msIntoSlot > GetHeaderRequestCutoffMs {
		return nil, nil, toErrorResp(http.StatusBadRequest, common.ErrLateHeader.Error())
	}

	if len(in.PubKey) != 98 {
		storingHeaderSpan.End(trace.WithTimestamp(time.Now()))
		return nil, nil, toErrorResp(http.StatusBadRequest, errInvalidPubkey.Error())
	}

	if len(in.ParentHash) != 66 {
		storingHeaderSpan.End(trace.WithTimestamp(time.Now()))
		return nil, nil, toErrorResp(http.StatusBadRequest, errInvalidHash.Error())
	}

	fetchGetHeaderStartTime := time.Now().UTC()

	blockValue := new(big.Int)

	fetchGetHeaderDurationMS := time.Since(fetchGetHeaderStartTime).Milliseconds()
	headerReqDuration := time.Since(in.ReceivedAt)

	statsUserAgent := in.UserAgent
	if in.Cluster != "" {
		statsUserAgent += "/" + in.Cluster
	}
	storingHeaderSpan.End()

	slotBestHeader, _, getHeaderSleepData, err := s.GetHeaderFunc(
		parentCtx,
		parentSpan,
		log,
		in,
		in.HttpRequest,
		isValidatorIP,
		validatorInfo,
		id,
		s.preFetchPayloadChan,
	)

	*log = log.With().
		Bool("slotBestHeaderFound", slotBestHeader != nil).
		Int64("sleep", getHeaderSleepData.SleepMs).
		Int64("maxSleep", getHeaderSleepData.MaxSleepMs).
		Int64("msIntoSlotIncludingDelay", getHeaderSleepData.MsIntoSlotIncludingDelay).
		Bool("usedRepick", getHeaderSleepData.UsedRepick).
		Uint64("headerTimeoutMS", in.HeaderTimeoutMs).
		Logger()

	if slotBestHeader == nil || err != nil {
		keyForCachingBids := s.keyForCachingBids(_slot, in.ParentHash, in.PubKey)
		msg := fmt.Sprintf("header value is not present for the requested key %v", keyForCachingBids)
		span.AddEvent("Header value is not present", trace.WithAttributes(attribute.String("msg", msg)))

		log.Error().Err(err).Bool("slotBestHeaderIsNil", slotBestHeader == nil).Msg("Header value is not present")

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

	_, signAndFinishSpan := s.tracer.Start(ctx, "getHeader-finalize")
	defer signAndFinishSpan.End()

	*log = log.With().
		Str("blockHash", slotBestHeader.BlockHash).
		Str("blockValue", blockValue.String()).

		// overall timing
		Int64("headerReqDurationMs", headerReqDuration.Milliseconds()).
		Int64("fetchGetHeaderDurationMs", fetchGetHeaderDurationMS).
		Logger()

	go func() {
		slotStats := SlotStatsRecord{
			HeaderReqID:               id,
			HeaderReqReceivedAt:       in.ReceivedAt,
			HeaderReqDuration:         headerReqDuration, // this is not used
			HeaderReqDurationInMs:     headerReqDuration.Milliseconds(),
			HeaderDelayInMs:           getHeaderSleepData.SleepMs,
			HeaderMaxDelayInMs:        getHeaderSleepData.MaxSleepMs,
			HeaderMsIntoSlot:          msIntoSlot,
			HeaderMsIntoSlotWithDelay: getHeaderSleepData.MsIntoSlotIncludingDelay,
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

		if v, ok := s.slotStatsHeaderEvents.Get(slotKey); !ok {
			slotStatsSlice := make([]SlotStatsRecord, 0, 5)
			slotStatsSlice = append(slotStatsSlice, slotStats)
			s.slotStatsHeaderEvents.Set(slotKey, slotStatsSlice, cache.DefaultExpiration)

			s.slotStatsEventCh <- slotStatsEvent{
				Slot:      int64(_slot),
				SlotKey:   slotKey,
				UserAgent: in.UserAgent,
			}
		} else {
			slotStatsSlice := v.([]SlotStatsRecord)
			slotStatsSlice = append(slotStatsSlice, slotStats)
			s.slotStatsHeaderEvents.Set(slotKey, slotStatsSlice, cache.DefaultExpiration)
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
		Sleep:                    getHeaderSleepData.SleepMs,
		MaxSleep:                 getHeaderSleepData.MaxSleepMs,
		MsIntoSlot:               msIntoSlot,
		MsIntoSlotWithDelay:      getHeaderSleepData.MsIntoSlotIncludingDelay,
		BlockHash:                slotBestHeader.BlockHash,
		PayloadFetchUrl:          slotBestHeader.PayloadFetchUrl,
	}
	relayURL := ""
	if slotBestHeader.Client != nil {
		relayURL = slotBestHeader.Client.String()
	}
	go s.IDataService.GetFlowService().RecordHeaderFlow(_slot, in.ParentHash, slotBestHeader.BlockHash, weiToEther(blockValue), in.PubKey, s.nodeID, HeaderFlowEvent{
		FlowEventSentAt:      time.Now().UTC(),
		ServedByThisNode:     true,
		SlotStartTime:        slotStartTime,
		MsIntoSlot:           msIntoSlot,
		MsIntoSlotWithDelay:  getHeaderSleepData.MsIntoSlotIncludingDelay,
		AccountID:            in.AccountID,
		ValidatorID:          in.ValidatorID,
		Source:               FlowSourceLocalBidCache, // adjust if needed
		GetHeaderReqID:       id,
		GetHeaderStartUnixMs: in.GetHeaderStartTimeUnixMS,
		BlockValue:           weiToEther(blockValue),
		BuilderPubkey:        slotBestHeader.BuilderPubkey,
		BuilderExtraData:     slotBestHeader.BuilderExtraData,
		BlockHashReceivedAt:  slotBestHeader.ReceivedAt,
		RelayURL:             relayURL,
		BlockSequenceNumber:  slotBestHeader.BlockSequenceNumber,
		Latency:              latency,
		Sleep:                getHeaderSleepData.SleepMs,
		MaxSleep:             getHeaderSleepData.MaxSleepMs,
		ClientIP:             in.ClientIP,
		NodeID:               s.nodeID,
		SlotUID:              in.SlotUID,
		HeaderUserAgent:      statsUserAgent,
		RepickedBlock:        getHeaderSleepData.UsedRepick,
	})

	return signedHeaderResponse, onHeaderDeliveredParams, nil
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

func IsValidatorIP(ipAddresses map[string]struct{}, ipAddress string, ip string) bool {
	if ipAddresses != nil {
		if _, found := ipAddresses[ip]; found {
			return true
		}
	}
	if ipAddress == ip {
		return true
	}
	return ip == "127.0.0.1"
}
