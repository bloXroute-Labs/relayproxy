package relayproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
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

func (s *Service) GetHeader(parentSpan trace.Span, parentCtx context.Context, log *zerolog.Logger, in *HeaderRequestParams) (json.RawMessage, *common.OnHeaderDeliveredParams, error) {
	id := uuid.NewString()
	ctx, span := s.tracer.Start(parentCtx, "getHeader-start")
	defer span.End()

	k := "slot-" + in.Slot + "-parentHash-" + in.ParentHash
	var (
		err                    error
		delayGetHeaderResponse DelayGetHeaderResponse
	)
	delayCtx, delayGetHeaderSpan := s.tracer.Start(ctx, "getHeader-delayGetHeader")
	delayGetHeaderResponse, err = s.delayer.DelayGetHeader(
		delayCtx,
		DelayGetHeaderParams{
			ReceivedAt:                in.ReceivedAt,
			Slot:                      in.Slot,
			AccountID:                 in.AccountID,
			Cluster:                   in.Cluster,
			UserAgent:                 in.UserAgent,
			ClientIP:                  in.ClientIP,
			SlotWithParentHash:        k,
			BoostSendTimeUnixMS:       in.GetHeaderStartTimeUnixMS,
			Latency:                   in.Latency,
			HeaderTimeoutMS:           in.HeaderTimeoutMs, // client timeout
			BidAdjustmentBufferTimeMs: s.bidAdjustmentBufferTimeMs,
		},
	)
	resp := delayGetHeaderResponse

	*log = log.With().
		// top-level response fields
		Int64("sleep", resp.Sleep).
		Int64("maxSleep", resp.MaxSleep).
		Int64("replacementDelayMs", resp.ReplacementDelayMs).
		Int64("latency", resp.Latency).
		Time("slotStartTime", resp.SlotStartTime).

		// DelayInfo fields (exported)
		Int64("slept", resp.DelayInfo.SleptMsActual).
		Int64("sleepMsBefore", resp.DelayInfo.SleepMsBefore).
		Int64("sleepMsAfter", resp.DelayInfo.SleepMsAfter).
		Bool("isSleepUpdated", resp.DelayInfo.IsSleepUpdated).
		Int64("oneWayMs", resp.DelayInfo.OneWayMs).
		Int64("requestInitiatedAt", resp.DelayInfo.RequestInitiatedAt).
		Int64("requestTimeout", resp.DelayInfo.RequestTimeout).
		Time("requestDeadline", resp.DelayInfo.RequestDeadline).
		Time("getHeaderDeadline", resp.DelayInfo.GetHeaderDeadline).
		Time("effectiveDeadline", resp.DelayInfo.EffectiveDeadline).
		Time("defaultWakeupAt", resp.DelayInfo.DefaultWakeupAt).
		Time("updatedWakeupAt", resp.DelayInfo.UpdatedWakeupAt).
		Logger()
	delayGetHeaderSpan.End(trace.WithTimestamp(time.Now()))

	_, preStoringHeaderSpan := s.tracer.Start(ctx, "getHeader-preStoringHeaderSpan")
	sleep := delayGetHeaderResponse.Sleep // TODO: refactor for the error handling
	maxSleep := delayGetHeaderResponse.MaxSleep
	slotStartTime := delayGetHeaderResponse.SlotStartTime
	latency := delayGetHeaderResponse.Latency

	startTime := time.Now().UTC()

	*log = log.With().
		Str("reqID", id).
		Int64("slotStartTimeUnix", slotStartTime.Unix()).
		Str("slotStartTime", slotStartTime.UTC().String()).
		Int64("sleep", sleep).
		Int64("maxSleep", maxSleep).
		Uint64("headerTimeoutMS", in.HeaderTimeoutMs).
		Logger()

	log.Info().Msg("received getHeader")
	if err != nil {
		preStoringHeaderSpan.End(trace.WithTimestamp(time.Now()))
		return nil, nil, toErrorResp(http.StatusNoContent, err.Error())
	}

	_slot, err := fastParseUint(in.Slot)
	if err != nil {
		preStoringHeaderSpan.End(trace.WithTimestamp(time.Now()))
		return nil, nil, toErrorResp(http.StatusNoContent, errInvalidSlot.Error())
	}

	msIntoSlotIncludingDelay := time.Since(slotStartTime).Milliseconds()
	msIntoSlot := in.ReceivedAt.Sub(slotStartTime).Milliseconds() // without sleep and using received at
	*log = log.With().
		Int64("msIntoSlotIncludingDelay", msIntoSlotIncludingDelay).
		Int64("receivedAtMsIntoSlot", msIntoSlot).
		Logger()

	preStoringHeaderSpan.End()

	storingHeaderCtx, storingHeaderSpan := s.tracer.Start(ctx, "getHeader-storingHeader")
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

	initialBidFetchStart := time.Now().UTC()
	slotBestHeader, secondBestHeader, bidAdjustmentTargetBid, getErr := s.GetTopBuilderBid(keyForCachingBids)
	blockValue := new(big.Int)
	initialFetchBidUsed := true
	initialBidFetchDurationMs := time.Since(initialBidFetchStart).Milliseconds()

	usedRepick := false
	repickDataExist := false
	repickDataSuccess := true
	repickErr := ""
	originalValue := big.NewInt(0)
	originalBlockHash := ""

	// Repick algorithm (high level):
	//  1) Initial fetch: GetTopBuilderBid(key) -> (best, second). This is the baseline header/value we would return.
	//     - If best has a PayloadFetchUrl, we best-effort enqueue a prefetch.
	//
	//  2) Repick window: If ReplacementDelayMs > 0 and OnHeaderBidRetrieved is set,
	//     we open a bounded "repick window" of length ReplacementDelayMs.
	//     - Spawn a goroutine that calls OnHeaderBidRetrieved(repickCtx, currentBest, ...).
	//     - repickCtx is capped by repickDeadline (hard deadline).
	//     - Result is sent on a buffered channel (size 1) best-effort (never block).
	//
	//  3) Decide outcome (whichever happens first):
	//     a) Receive repick result within window:
	//        - If err: repick failed (record error), keep current best.
	//        - If bid != nil: accept replacement bid (usedRepick=true), update best/value.
	//        - If bid == nil: treat as failure, keep current best.
	//     b) repickCtx deadline hits: timeout, keep current best.
	//     c) request ctx canceled: abort repick, keep current best.
	//
	//  4) Final fetch (only if repick did NOT replace):
	//     After the repick window closes, fetch GetTopBuilderBid(key) again.
	//     If the newly fetched best has higher value than our current best, upgrade to it.
	//     This might affect bid replacement.
	//     (This is a final "catch-up" fetch; it does not wait beyond the repick deadline.)
	//

	if getErr == nil && slotBestHeader != nil {
		originalValue = new(big.Int).SetBytes(slotBestHeader.Value)
		blockValue = new(big.Int).Set(originalValue)
		originalBlockHash = slotBestHeader.BlockHash
	} else {
		log.Error().Err(getErr).Msg("error getting top builder bid")
	}

	// Send in an early prefetch payload request for Optimistic V3 block payloads
	if slotBestHeader != nil && slotBestHeader.PayloadFetchUrl != "" {
		select {
		case s.preFetchPayloadChan <- preFetcherFields{
			clientIP:                          in.ClientIP,
			authHeader:                        in.AuthHeader,
			slot:                              _slot,
			parentHash:                        in.ParentHash,
			blockHash:                         slotBestHeader.BlockHash,
			proposerPubKey:                    in.PubKey,
			builderPubKey:                     slotBestHeader.BuilderPubkey,
			blockValue:                        weiToEther(new(big.Int).SetBytes(slotBestHeader.Value)),
			client:                            slotBestHeader.Client,
			payloadFetchUrl:                   slotBestHeader.PayloadFetchUrl,
			slotStartTime:                     slotStartTime,
			msIntoSlotGetHeaderIncludingDelay: msIntoSlotIncludingDelay,
			getHeaderReqID:                    id,
		}:
		default:
			log.Warn().Msg("prefetch channel full; skipping prefetch")
		}
	}

	var (
		repickStartTime time.Time
		repickDeadline  time.Time
		repickEndTime   time.Time
		repickElapsedMs int64
		repickOutcome   string // "replaced" | "nil" | "timeout" | "ctx_canceled" | "skipped"

		finalFetchAttempted   bool
		finalFetchBidUsed     bool
		finalFetchRemainingMs int64
		finalFetchDurationMs  int64
		repickDurationMs      int64 // duration of OnHeaderBidRetrieved
	)

	repickDelayMs := delayGetHeaderResponse.ReplacementDelayMs
	bidAdjustmentStartAt := time.Now().UTC()

	type repickResult struct {
		bid         *common.Bid
		replaceable bool
		err         error
		durationMs  int64
	}

	if repickDelayMs > 0 && getErr == nil && s.OnHeaderBidRetrieved != nil && slotBestHeader != nil {
		repickStartTime = time.Now().UTC()
		repickDeadline = repickStartTime.Add(time.Duration(repickDelayMs) * time.Millisecond)

		// ctx that caps OnHeaderBidRetrieved to the repick window
		repickCtx, cancel := context.WithDeadline(storingHeaderCtx, repickDeadline)
		defer cancel()

		resCh := make(chan repickResult, 1)

		go func() {
			start := time.Now()
			onHeaderRetrievedCtx, span := s.tracer.Start(repickCtx, "getHeader-onHeaderBidRetrieved")
			defer span.End()

			newBestHeader, replaceable, err := s.OnHeaderBidRetrieved(
				onHeaderRetrievedCtx,
				slotBestHeader,
				bidAdjustmentTargetBid,
				*log,
				_slot,
				in.ParentHash,
				in.AccountID,
				repickDelayMs,
				s.uniqueStreamingClients,
			)

			r := repickResult{
				bid:         newBestHeader,
				replaceable: replaceable,
				err:         err,
				durationMs:  time.Since(start).Milliseconds(),
			}

			select {
			case resCh <- r:
			default:
				// best-effort; should not block
				log.Warn().Msg("resCh full, dropping result (non-blocking send)")
			}
		}()

		select {
		case r := <-resCh:
			repickDurationMs = r.durationMs
			repickDataExist = r.replaceable

			if r.err != nil {
				repickErr = r.err.Error()
				repickDataSuccess = false
				repickOutcome = r.err.Error()
				log.Debug().Err(r.err).Msg("OnHeaderBidRetrieved error")
			} else if r.bid != nil {
				usedRepick = true
				initialFetchBidUsed = false
				blockValue = new(big.Int).SetBytes(r.bid.Value)
				slotBestHeader = r.bid
				getErr = nil
				repickOutcome = "replaced"
				log.Debug().Msg("got replacement bid within ReplacementDelayMs")
			} else {
				repickDataSuccess = false
				repickErr = "OnHeaderBidRetrieved returned nil"
				repickOutcome = "nil"
				log.Debug().Msg("repick returned nil bid")
			}

		case <-repickCtx.Done():
			repickDataSuccess = false
			repickErr = "timeout waiting for OnHeaderBidRetrieved"
			repickOutcome = "timeout"
			log.Debug().
				Time("deadline", repickDeadline).
				Int64("replacementDelayMs", repickDelayMs).
				Msg("repick hard deadline reached")

		case <-ctx.Done():
			repickDataSuccess = false
			repickErr = ctx.Err().Error()
			repickOutcome = "ctx_canceled"
			log.Debug().Err(ctx.Err()).Msg("request ctx canceled during repick")
		}

		if !usedRepick {
			remaining := time.Until(repickDeadline)
			finalFetchRemainingMs = remaining.Milliseconds()

			finalFetchAttempted = true
			fetchStart := time.Now().UTC()

			newBestHeader, secondBidHeader, _, err := s.GetTopBuilderBid(keyForCachingBids)

			if err != nil || newBestHeader == nil {
				log.Error().Err(err).Msg("error getting top builder bid after repick window")
			} else {
				newblockValue := new(big.Int).SetBytes(newBestHeader.Value)
				if newblockValue.Cmp(blockValue) > 0 {
					slotBestHeader = newBestHeader
					secondBestHeader = secondBidHeader
					getErr = err
					blockValue = newblockValue
					initialFetchBidUsed = false
					finalFetchBidUsed = true
				}
			}
			finalFetchDurationMs = time.Since(fetchStart).Milliseconds()
		}

		repickEndTime = time.Now().UTC()
		repickElapsedMs = repickEndTime.Sub(repickStartTime).Milliseconds()

	} else {
		repickOutcome = "skipped"
		repickDataSuccess = false
	}

	bidAdjustmentDurationMs := time.Since(bidAdjustmentStartAt).Milliseconds()
	fetchGetHeaderDurationMS := time.Since(fetchGetHeaderStartTime).Milliseconds()
	headerReqDuration := time.Since(in.ReceivedAt)

	statsUserAgent := in.UserAgent
	if in.Cluster != "" {
		statsUserAgent += "/" + in.Cluster
	}
	storingHeaderSpan.End()

	if slotBestHeader == nil || getErr != nil {
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
	_, signAndFinishSpan := s.tracer.Start(ctx, "getHeader-finalize")
	defer signAndFinishSpan.End()

	*log = log.With().
		Str("blockHash", slotBestHeader.BlockHash).
		Str("blockValue", blockValue.String()).

		// overall timing
		Int64("headerReqDurationMs", headerReqDuration.Milliseconds()).
		Int64("fetchGetHeaderDurationMs", fetchGetHeaderDurationMS).
		Int64("initialBidFetchDurationMs", initialBidFetchDurationMs).

		// repick config + outcome
		Int64("replacementDelayMs", delayGetHeaderResponse.ReplacementDelayMs).
		Bool("usedRepick", usedRepick).
		Bool("repickDataExist", repickDataExist).
		Bool("repickDataSuccess", repickDataSuccess).
		Str("repickErr", repickErr).
		Str("repickOutcome", repickOutcome).

		// repick timings
		Time("repickStartTime", repickStartTime).
		Time("repickDeadline", repickDeadline).
		Time("repickEndTime", repickEndTime).
		Int64("repickElapsedMs", repickElapsedMs).
		Int64("onHeaderBidRetrievedDurationMs", repickDurationMs).

		// final fetch timings
		Bool("finalFetchAttempted", finalFetchAttempted).
		Int64("finalFetchRemainingMs", finalFetchRemainingMs).
		Int64("finalFetchDurationMs", finalFetchDurationMs).
		Bool("finalFetchBidUsed", finalFetchBidUsed).
		Bool("initialFetchBidUsed", initialFetchBidUsed).

		// original bid context
		Int64("originalValue", originalValue.Int64()).
		Str("originalBlockHash", originalBlockHash).

		// your existing metric (renamed semantics: this is the whole repick flow, not only "adjustment")
		Int64("bidAdjustmentDurationMs", bidAdjustmentDurationMs).
		Logger()

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

		if v, ok := s.slotStatsHeaderEvents.Get(k); !ok {
			slotStatsSlice := make([]SlotStatsRecord, 0, 5)
			slotStatsSlice = append(slotStatsSlice, slotStats)
			s.slotStatsHeaderEvents.Set(k, slotStatsSlice, cache.DefaultExpiration)

			s.slotStatsEventCh <- slotStatsEvent{
				Slot:      int64(_slot),
				SlotKey:   k,
				UserAgent: in.UserAgent,
			}

		} else {
			slotStatsSlice := v.([]SlotStatsRecord)
			slotStatsSlice = append(slotStatsSlice, slotStats)
			s.slotStatsHeaderEvents.Set(k, slotStatsSlice, cache.DefaultExpiration)
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
		validatorInfo, found := s.miniProposerSlotMap.Load(_slot)
		if found && validatorInfo != nil && validatorInfo.Registration != nil {
			record := headerProvidedToValidatorIP{
				IPMatches:                true,
				Slot:                     strconv.FormatUint(_slot, 10),
				ProposerPublicKey:        in.PubKey,
				Value:                    blockValue.String(),
				BlockHash:                slotBestHeader.BlockHash,
				ExtraData:                slotBestHeader.BuilderExtraData,
				FeeRecipient:             validatorInfo.Registration.Message.FeeRecipient.String(),
				BidPubkey:                slotBestHeader.BuilderPubkey,
				BuilderPubkey:            slotBestHeader.BuilderPubkey,
				MSIntoSlot:               msIntoSlot,
				GetHeaderRequestSendTime: msIntoSlot - latency,
				UserAgent:                in.UserAgent,
				UsingRelayProxy:          true,
				ClientIPAddress:          in.ClientIP,
				RequestID:                in.ValidatorID,
				Region:                   s.nodeID,
				SleepAmount:              delayGetHeaderResponse.Sleep,
				MaxSleepIntoSlot:         delayGetHeaderResponse.MaxSleep,
				SleepType:                "proxy",
				ISP:                      "",
				IPOrganization:           "",
				State:                    "",
				Country:                  "",
				DataSource:               "proxy",
				Duration:                 time.Since(in.ReceivedAt).Milliseconds(),

				OriginalValue:         originalValue.String(),
				OriginalBlockHash:     originalBlockHash,
				BidAdjustmentDuration: bidAdjustmentDurationMs,
				UsedAdjustment:        usedRepick,
				AdjustmentDataExist:   repickDataExist,
				AdjustmentDataSuccess: repickDataSuccess,
				AdjustmentError:       repickErr,

				SecondPlaceBuilderValue:         "",
				SecondPlaceBuilderBlockHash:     "",
				SecondPlaceBuilderBuilderPubkey: "",
				SecondPlaceBuilderExtraData:     "",
				SecondPlaceBuilderFeeRecipient:  validatorInfo.Registration.Message.FeeRecipient.String(),

				Type: "StatsHeaderProvidedToValidatorIP",
			}
			if secondBestHeader != nil {
				record.SecondPlaceBuilderBlockHash = secondBestHeader.BlockHash
				record.SecondPlaceBuilderValue = weiToEther(new(big.Int).SetBytes(secondBestHeader.Value))
				record.SecondPlaceBuilderBuilderPubkey = secondBestHeader.BuilderPubkey
				record.SecondPlaceBuilderExtraData = secondBestHeader.BuilderExtraData
			}

			s.fluentD.LogToFluentD(fluentstats.Record{
				Type: "StatsHeaderProvidedToValidatorIP",
				Data: record,
			}, time.Now().UTC(), s.nodeID, "stats.header_provided_to_validator_ip")
		}
	}()

	// send in payload to pre fetcher event
	s.preFetchPayloadChan <- preFetcherFields{
		clientIP:                          in.ClientIP,
		authHeader:                        in.AuthHeader,
		slot:                              _slot,
		parentHash:                        in.ParentHash,
		blockHash:                         slotBestHeader.BlockHash,
		proposerPubKey:                    in.PubKey,
		builderPubKey:                     slotBestHeader.BuilderPubkey,
		blockValue:                        weiToEther(blockValue),
		client:                            slotBestHeader.Client,
		payloadFetchUrl:                   slotBestHeader.PayloadFetchUrl,
		slotStartTime:                     slotStartTime,
		msIntoSlotGetHeaderIncludingDelay: msIntoSlotIncludingDelay,
		getHeaderReqID:                    id,
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
		Sleep:                    sleep,
		MaxSleep:                 maxSleep,
		MsIntoSlot:               msIntoSlot,
		MsIntoSlotWithDelay:      msIntoSlotIncludingDelay,
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
		MsIntoSlotWithDelay:  msIntoSlotIncludingDelay,
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
		Sleep:                sleep,
		MaxSleep:             maxSleep,
		ClientIP:             in.ClientIP,
		NodeID:               s.nodeID,
		SlotUID:              in.SlotUID,
		HeaderUserAgent:      statsUserAgent,
		RepickedBlock:        usedRepick,
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
