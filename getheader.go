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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	relaygrpc "github.com/bloXroute-Labs/relay-grpc"
	"github.com/bloXroute-Labs/relay-grpc/optimisticv3"
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
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---------- pooled HTTP client (keep-alive) ----------
var (
	prefetchHTTPOnce sync.Once
	prefetchHTTP     *http.Client
)

func getPrefetchHTTPClient() *http.Client {
	prefetchHTTPOnce.Do(func() {
		tr := &http.Transport{
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 200,
			IdleConnTimeout:     60 * time.Second,
			ForceAttemptHTTP2:   true,
		}
		prefetchHTTP = &http.Client{
			Transport: tr,
			Timeout:   900 * time.Millisecond,
		}
	})
	return prefetchHTTP
}

// tracker to ensure single success/failure log per protocol
type protoLogTracker struct {
	grpcAttempted  atomic.Bool
	httpAttempted  atomic.Bool
	grpcSuccess    atomic.Bool
	httpSuccess    atomic.Bool
	grpcLoggedOnce atomic.Bool
	httpLoggedOnce atomic.Bool
}

// ========================= GetHeader =========================

func (s *Service) GetHeader(parentSpan trace.Span, parentCtx context.Context, log *zerolog.Logger, in *HeaderRequestParams) (json.RawMessage, *common.OnHeaderDeliveredParams, error) {
	startAll := time.Now()
	ctx, span := s.tracer.Start(parentCtx, GetSpanName("svc.getHeader", "START"))
	defer func() {
		span.SetAttributes(
			attribute.Int64("svc.getHeader_total_ms", time.Since(startAll).Milliseconds()),
			attribute.Int64("svc.getHeader_total_from_handler_received_ms", time.Since(in.ReceivedAt).Milliseconds()),
		)
		span.End()
	}()

	id := uuid.NewString()
	k := "slot-" + in.Slot + "-parentHash-" + in.ParentHash

	// -------- DelayGetHeader --------
	delayStart := time.Now()
	delayCtx, delaySpan := s.tracer.Start(ctx, GetSpanName("svc.getHeader", "delayGetHeader"))
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
	delaySpan.SetAttributes(
		attribute.Int64("svc.getHeader_delay_ms", time.Since(delayStart).Milliseconds()),
		attribute.Int64("sleep_ms", delayGetHeaderResponse.Sleep),
		attribute.Int64("maxSleep_ms", delayGetHeaderResponse.MaxSleep),
	)
	delaySpan.End()

	// -------- Pre-storing span (enrich logger etc) --------
	preStoreStart := time.Now()
	_, preStoringHeaderSpan := s.tracer.Start(ctx, GetSpanName("svc.getHeader", "preStore"))
	sleep := delayGetHeaderResponse.Sleep // TODO: refactor for error handling
	maxSleep := delayGetHeaderResponse.MaxSleep
	slotStartTime := delayGetHeaderResponse.SlotStartTime
	latency := delayGetHeaderResponse.Latency
	msIntoSlotIncludingDelay := time.Since(slotStartTime).Milliseconds()
	msIntoSlot := in.ReceivedAt.Sub(slotStartTime).Milliseconds() // without sleep and using received at

	startTime := time.Now().UTC()
	*log = log.With().
		Str("reqID", id).
		Str("slot", in.Slot).
		Int64("slotStartTimeUnix", slotStartTime.Unix()).
		Str("slotStartTime", slotStartTime.UTC().String()).
		Int64("sleep", sleep).
		Int64("maxSleep", maxSleep).
		Int64("msIntoSlot", msIntoSlot).
		Int64("msIntoSlotIncludingDelay", msIntoSlotIncludingDelay).
		Logger()
	log.Info().Msg("received getHeader")

	if err != nil {
		preStoringHeaderSpan.SetAttributes(attribute.Int64("svc.getHeader_prestore_ms", time.Since(preStoreStart).Milliseconds()))
		preStoringHeaderSpan.End()
		return nil, nil, toErrorResp(http.StatusNoContent, err.Error())
	}
	preStoringHeaderSpan.SetAttributes(attribute.Int64("svc.getHeader_prestore_ms", time.Since(preStoreStart).Milliseconds()))
	preStoringHeaderSpan.End()

	// -------- slot fast parsing span --------
	fastParseSlotStart := time.Now()
	_, fPSpan := s.tracer.Start(ctx, GetSpanName("svc.getHeader", "fastParseSlot"))
	_slot, err := fastParseUint(in.Slot)
	if err != nil {
		fPSpan.SetAttributes(attribute.Int64("svc.getHeader_fastParseSlot_ms", time.Since(fastParseSlotStart).Milliseconds()))
		fPSpan.End()
		return nil, nil, toErrorResp(http.StatusNoContent, errInvalidSlot.Error())
	}
	fPSpan.SetAttributes(attribute.Int64("svc.getHeader_fastParseSlot_ms", time.Since(fastParseSlotStart).Milliseconds()))
	fPSpan.End()

	// -------- Validation span --------
	validateStart := time.Now()
	_, valSpan := s.tracer.Start(ctx, GetSpanName("svc.getHeader", "validateInputs"))
	if len(in.PubKey) != 98 {
		valSpan.SetAttributes(attribute.Int64("svc.getHeader_validate_ms", time.Since(validateStart).Milliseconds()))
		valSpan.End()
		return nil, nil, toErrorResp(http.StatusNoContent, errInvalidPubkey.Error())
	}
	if len(in.ParentHash) != 66 {
		valSpan.SetAttributes(attribute.Int64("svc.getHeader_validate_ms", time.Since(validateStart).Milliseconds()))
		valSpan.End()
		return nil, nil, toErrorResp(http.StatusNoContent, errInvalidHash.Error())
	}
	valSpan.SetAttributes(attribute.Int64("svc.getHeader_validate_ms", time.Since(validateStart).Milliseconds()))
	valSpan.End()

	// -------- Fetch best bid (from cache) --------
	fetchStart := time.Now()
	_, fetchSpan := s.tracer.Start(ctx, GetSpanName("svc.getHeader", "fetchTopBid"))
	fetchGetHeaderStartTime := time.Now().UTC()
	keyForCachingBids := s.keyForCachingBids(_slot, in.ParentHash, in.PubKey)
	slotBestHeader, secondBestHeader, getErr := s.GetTopBuilderBid(keyForCachingBids)
	fetchSpan.SetAttributes(
		attribute.Int64("svc.getHeader_fetch_bid_ms", time.Since(fetchStart).Milliseconds()),
		attribute.Bool("haveBestHeader", slotBestHeader != nil && getErr == nil),
		attribute.String("svc.slotBestHeader.blockHash", slotBestHeader.BlockHash),
		attribute.String("svc.slotBestHeader.builderPubkey", slotBestHeader.BuilderPubkey),
		attribute.String("svc.slotBestHeader.payloadFetchUrl", slotBestHeader.PayloadFetchUrl),
		attribute.String("svc.slotBestHeader.blockHashReceivedAt", slotBestHeader.ReceivedAt.String()),
	)
	fetchSpan.End()

	// ---- SPECULATIVE PREFETCH (non-blocking) ----
	if getErr == nil && slotBestHeader != nil {
		specStart := time.Now()
		_, specSpan := s.tracer.Start(ctx, GetSpanName("svc.getHeader", "speculativePrefetch"))
		s.preFetchPayloadChan <- preFetcherFields{
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
		}
		specSpan.SetAttributes(
			attribute.String("prefetch.blockHash", slotBestHeader.BlockHash),
			attribute.String("prefetch.builderPubkey", slotBestHeader.BuilderPubkey),
			attribute.Int64("svc.getHeader_speculative_prefetch_ms", time.Since(specStart).Milliseconds()),
		)
		specSpan.End()
	}

	// Preserve repick bookkeeping
	usedRepick := false
	repickDataExist := false
	repickDataSuccess := true
	repickErr := ""
	originalValue := big.NewInt(0)
	originalBlockHash := ""
	if getErr == nil && slotBestHeader != nil {
		originalValue = new(big.Int).SetBytes(slotBestHeader.Value)
		originalBlockHash = slotBestHeader.BlockHash
	} else {
		log.Debug().Err(getErr).Msg("error getting top builder bid")
	}
	repickDurationMS := int64(0)

	// -------- Repick flow (timed) --------
	repickOuterStart := time.Now()
	_, repickSpan := s.tracer.Start(ctx, GetSpanName("svc.getHeader", "repickFlow"))
	repickTime := time.Now().Add(time.Duration(delayGetHeaderResponse.ReplacementDelayMs) * time.Millisecond)
	replacementTime := repickTime.Add(-5 * time.Millisecond)
	if delayGetHeaderResponse.ReplacementDelayMs > 0 {
		replacementTimer := time.NewTimer(time.Until(replacementTime))
		defer replacementTimer.Stop()
		repickTimer := time.NewTimer(time.Until(repickTime))
		defer repickTimer.Stop()

		log.Debug().Int64("replacementDelayMs", delayGetHeaderResponse.ReplacementDelayMs).Msg("waiting for replacement delay")
		if getErr == nil && s.OnHeaderBidRetrieved != nil {
			newBestHeaderCh := make(chan *common.Bid, 1)
			go func() {
				onHeaderBidRetrievedStart := time.Now()
				onHeaderRetrievedCtx, onHeadonHeaderBidRetrievedSpan := s.tracer.Start(ctx, GetSpanName("svc.getHeader", "onHeaderBidRetrieved"))
				newBestHeader, replaceable, err := s.OnHeaderBidRetrieved(onHeaderRetrievedCtx, slotBestHeader, *log, _slot, in.ParentHash, slotBestHeader.BuilderPubkey, in.AccountID, delayGetHeaderResponse.ReplacementDelayMs, s.uniqueStreamingClients)
				onHeadonHeaderBidRetrievedSpan.SetAttributes(
					attribute.Int64("svc.getHeader_onHeaderBidRetrieved_ms", time.Since(onHeaderBidRetrievedStart).Milliseconds()),
					attribute.Bool("replaceable", replaceable),
					attribute.String("err", func() string {
						if err != nil {
							return err.Error()
						}
						return ""
					}()),
				)
				onHeadonHeaderBidRetrievedSpan.End()
				repickDurationMS = time.Since(onHeaderBidRetrievedStart).Milliseconds()
				log.Debug().Bool("replaceable", replaceable).Int64("onHeaderBidRetrievedDuration", repickDurationMS).Msg("OnHeaderBidRetrieved duration")
				repickDataExist = replaceable
				if err != nil {
					repickErr = err.Error()
					log.Debug().Err(err).Msg("OnHeaderBidRetrieved error")
					newBestHeaderCh <- nil
					return
				}
				newBestHeaderCh <- newBestHeader
			}()
			select {
			case replacementHeader := <-newBestHeaderCh:
				if replacementHeader != nil {
					usedRepick = true
					slotBestHeader = replacementHeader
					getErr = nil
					log.Debug().Msg("got new bid after repick from channel")
				} else {
					log.Debug().Msg("got nil bid after repick from channel")
				}
			case <-replacementTimer.C:
				log.Debug().Time("replacementTime", replacementTime).Time("repickTime", repickTime).Msg("OnHeaderBidRetrieved took too long, proceeding with the original bid")
				repickErr = "timeout waiting for OnHeaderBidRetrieved"
				repickDataSuccess = false
			}
		}
		if !usedRepick {
			<-repickTimer.C
			repickFetchStart := time.Now()
			newBestHeader, secondBidHeader, err := s.GetTopBuilderBid(keyForCachingBids)
			repickSpan.SetAttributes(attribute.Int64("svc.getHeader_repick_fetch_bid_ms", time.Since(repickFetchStart).Milliseconds()))
			if err != nil {
				log.Debug().Err(err).Msg("error getting top builder bid after repick wait")
			} else {
				slotBestHeader = newBestHeader
				secondBestHeader = secondBidHeader
				getErr = err
				log.Debug().Msg("got new bid after repick wait")
			}
		}
	}
	repickSpan.SetAttributes(
		attribute.Int64("svc.getHeader_repick_total_ms", time.Since(repickOuterStart).Milliseconds()),
		attribute.Bool("usedRepick", usedRepick),
		attribute.Bool("repickDataExist", repickDataExist),
		attribute.Bool("repickDataSuccess", repickDataSuccess),
		attribute.String("repickErr", repickErr),
		attribute.Int64("repickDurationMS", repickDurationMS),
	)
	repickSpan.End()

	// -------- Post-fetch bookkeeping --------
	postFetchStart := time.Now()
	_, storingHeaderSpan := s.tracer.Start(ctx, GetSpanName("svc.getHeader", "postFetch"))
	fetchGetHeaderDurationMS := time.Since(fetchGetHeaderStartTime).Milliseconds()
	statsUserAgent := in.UserAgent
	if in.Cluster != "" {
		statsUserAgent += "/" + in.Cluster
	}
	storingHeaderSpan.SetAttributes(
		attribute.Int64("svc.getHeader_postfetch_ms", time.Since(postFetchStart).Milliseconds()),
		attribute.Int64("fetchGetHeaderDurationMS", fetchGetHeaderDurationMS),
	)
	storingHeaderSpan.End()

	// -------- No-bid path --------
	if slotBestHeader == nil || getErr != nil {
		noBidStart := time.Now()
		_, noBidSpan := s.tracer.Start(ctx, GetSpanName("svc.getHeader", "noBid"))
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
		noBidSpan.SetAttributes(attribute.Int64("svc.getHeader_nobid_ms", time.Since(noBidStart).Milliseconds()))
		noBidSpan.End()
		return nil, nil, toErrorResp(http.StatusNoContent, "Header value is not present")
	}

	// -------- Account mapping --------
	accStart := time.Now()
	_, accSpan := s.tracer.Start(ctx, GetSpanName("svc.getHeader", "accountMapping"))
	if slotBestHeader.AccountID != "" {
		in.AccountID = slotBestHeader.AccountID
		if s.accountsLists.AccountIDToInfo[in.AccountID] != nil &&
			s.accountsLists.AccountIDToInfo[in.AccountID].UseAccountAsValidator {
			in.ValidatorID = in.AccountID
		}
	}
	accSpan.SetAttributes(attribute.Int64("svc.getHeader_accountmap_ms", time.Since(accStart).Milliseconds()))
	accSpan.End()

	// -------- Finalize / Sign --------
	finalStart := time.Now()
	_, signAndFinishSpan := s.tracer.Start(ctx, GetSpanName("svc.getHeader", "finalize"))
	defer func() {
		signAndFinishSpan.SetAttributes(attribute.Int64("svc.getHeader_finalize_ms", time.Since(finalStart).Milliseconds()))
		signAndFinishSpan.End()
	}()

	blockValue := new(big.Int).SetBytes(slotBestHeader.Value)
	*log = log.With().
		Str("blockHash", slotBestHeader.BlockHash).
		Str("blockValue", blockValue.String()).
		Int64("replacementDelayMs", delayGetHeaderResponse.ReplacementDelayMs).
		Bool("usedRepick", usedRepick).
		Bool("repickDataExist", repickDataExist).
		Bool("repickDataSuccess", repickDataSuccess).
		Str("repickErr", repickErr).
		Int64("repickDurationMS", repickDurationMS).
		Int64("originalValue", originalValue.Int64()).
		Str("originalBlockHash", originalBlockHash).
		Time("replacementTime", time.Now().Add(-time.Duration(delayGetHeaderResponse.ReplacementDelayMs)*time.Millisecond+5*time.Millisecond)). // informational
		Time("repickTime", time.Now().Add(time.Duration(delayGetHeaderResponse.ReplacementDelayMs)*time.Millisecond)).
		Logger()
	// -------- flow : record header info -------
	go s.IDataService.GetFlowService().RecordHeaderFlow(_slot, in.ParentHash, slotBestHeader.BlockHash, weiToEther(blockValue), in.PubKey, HeaderFlowEvent{
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
		RelayURL:             slotBestHeader.PayloadFetchUrl,
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
	// -------- Stats logging goroutine --------
	go func(statsStart time.Time) {
		statsSpanStart := time.Now()
		slotStats := SlotStatsRecord{
			HeaderReqID:               id,
			HeaderReqReceivedAt:       in.ReceivedAt,
			HeaderReqDuration:         time.Since(in.ReceivedAt), // not used directly
			HeaderReqDurationInMs:     time.Since(in.ReceivedAt).Milliseconds(),
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
			FetchGetHeaderDurationMS: time.Since(fetchGetHeaderStartTime).Milliseconds(),
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
			UserAgent: func() string {
				if in.Cluster != "" {
					return in.UserAgent + "/" + in.Cluster
				}
				return in.UserAgent
			}(),
			SlotUID:               in.SlotUID,
			HeaderStartTimeUnixMs: in.GetHeaderStartTimeUnixMS,
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
				BidAdjustmentDuration: repickDurationMS,
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

		// annotate finalize span with stats duration
		signAndFinishSpan.AddEvent("stats_flushed", trace.WithAttributes(
			attribute.Int64("svc.getHeader_stats_async_ms", time.Since(statsSpanStart).Milliseconds()),
		))
	}(time.Now())

	// -------- Enqueue (existing, kept) --------
	enqStart := time.Now()
	_, enqSpan := s.tracer.Start(ctx, GetSpanName("svc.getHeader", "enqueueFinalPrefetch"))
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
	enqSpan.SetAttributes(
		attribute.String("prefetch.blockHash", slotBestHeader.BlockHash),
		attribute.String("prefetch.builderPubkey", slotBestHeader.BuilderPubkey),
		attribute.Int64("svc.getHeader_enqueue_prefetch_ms", time.Since(enqStart).Milliseconds()),
	)
	enqSpan.End()

	// -------- Sign header --------
	signStart := time.Now()
	signedHeaderResponse, prevSigned, err := slotBestHeader.GetSignedHeaderResponse(s.secretKey, &s.publicKey, s.builderSigningDomain)
	span.AddEvent("signedHeader", trace.WithAttributes(
		attribute.Bool("prevSigned", prevSigned),
		attribute.Int64("svc.getHeader_sign_ms", time.Since(signStart).Milliseconds()),
	))
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
	}

	return json.RawMessage(signedHeaderResponse), onHeaderDeliveredParams, nil
}

// ========================= Prefetcher Loop =========================

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
	var (
		clientURL string
		success   bool
	)

	startTime := time.Now().UTC()

	var msIntoSlotPrefetchStart int64
	if !fields.slotStartTime.IsZero() {
		msIntoSlotPrefetchStart = time.Since(fields.slotStartTime).Milliseconds()
	}
	id := uuid.NewString()

	// record prefetch start into flow cache
	go s.IDataService.GetFlowService().RecordPrefetchStart(
		fields.slot,
		fields.parentHash,
		fields.blockHash,
		fields.proposerPubKey,
		PrefetchFlowEvent{
			ReqID:                   id,
			GetHeaderReqID:          fields.getHeaderReqID,
			StartedAt:               startTime,
			MsIntoSlotPrefetchStart: msIntoSlotPrefetchStart,
		},
	)

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
		)
		span.End()

		s.performancestats.SetEndpointStats(
			"PreFetchGetPayload-rproxy",
			uint64(time.Since(startTime).Microseconds()),
			success,
			100,
		)
	}()

	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", s.authKey)

	uKey := fmt.Sprintf("slot_%v_bHash_%v_pHash_%v", fields.slot, fields.blockHash, fields.parentHash)

	if fields.client != nil {
		clientURL = fields.client.SafeClient.URL
	}

	logMetric := NewLogMetric(
		map[string]any{
			"method":                            preFetchPayload,
			"prefetchStartedAt":                 startTime,
			"clientIP":                          fields.clientIP,
			"clientURL":                         clientURL,
			"reqID":                             id,
			"traceID":                           span.SpanContext().TraceID().String(),
			"uKey":                              uKey,
			"slot":                              int64(fields.slot),
			"blockHash":                         fields.blockHash,
			"msIntoSlotStart":                   msIntoSlotPrefetchStart,
			"msIntoSlotGetHeaderIncludingDelay": fields.msIntoSlotGetHeaderIncludingDelay,
			"getHeaderReqID":                    fields.getHeaderReqID,
		},
	)

	s.logger.Debug().Fields(logMetric.GetFields()).Msg("received preFetchPayload")

	// If necessary, fetch the Optimistic V3 payload directly from the specified builder URL(s)
	if fields.payloadFetchUrl != "" {
		subStart := time.Now()
		_, sub := s.tracer.Start(spanCtx, GetSpanName("prefetch", "builderHTTPorGRPC"))
		success = s.prefetchPayloadFromBuilder(ctx, spanCtx, &fields, logMetric.Copy())
		sub.SetAttributes(
			attribute.Bool("success", success),
			attribute.Int64("duration_ms", time.Since(subStart).Milliseconds()),
		)
		sub.End()
		// NOTE: builder path does not currently call RecordPrefetchDone.
		// If you needed,  wire it into processGetPayloadV3Responses.
		return
	}

	// gRPC/HTTP fanout core
	fanoutStart := time.Now()
	_, fanoutSpan := s.tracer.Start(spanCtx, GetSpanName("prefetch", "grpcFanout"))
	s.prefetchPayloadGRPC(ctx, spanCtx, &fields, logMetric.Copy(), span, id, startTime, &success, fields.getHeaderReqID)
	fanoutDurationMs := time.Since(fanoutStart).Milliseconds()
	fanoutSpan.SetAttributes(
		attribute.Bool("success", success),
		attribute.Int64("duration_ms", fanoutDurationMs),
	)
	fanoutSpan.End()

	// Optional “summary” flow record (coarse, without URL/payload size).
	// Detailed records are written inside prefetchPayloadGRPC.
	go s.IDataService.GetFlowService().RecordPrefetchDone(fields.slot, fields.parentHash, fields.blockHash, fields.proposerPubKey, id, fields.getHeaderReqID, success, fanoutDurationMs, FlowSourceUnknown, "", "", 0, "")
}

// ========================= prefetchPayloadGRPC (core fanout) =========================

// wrapper for downstream prefetch result so we can track source + URL + payload size
type prefetchResult struct {
	resp   *relaygrpc.PreFetchGetPayloadResponse
	source FlowSource
	url    string
	nodeID string
}

func (s *Service) prefetchPayloadGRPC(
	ctx context.Context,
	spanctx context.Context,
	fields *preFetcherFields,
	logMetric *LogMetric,
	parentSpan trace.Span,
	reqID string,
	startTime time.Time,
	success *bool,
	getHeaderReqID string,
) {
	start := time.Now()
	spanCtx, svcSpan := s.tracer.Start(spanctx, GetSpanName("prefetch", "grpcFanoutCore"))
	defer func() {
		svcSpan.SetAttributes(attribute.Int64("total_ms", time.Since(start).Milliseconds()))
		svcSpan.End()
	}()

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
		errChan         = make(chan *ErrorResp, len(s.clients)+2)
		respChan        = make(chan *prefetchResult, len(s.clients)+2)
		payloadCacheKey = common.GetKeyForCachingPayload(fields.slot, fields.parentHash, fields.blockHash, fields.proposerPubKey)
		wg              sync.WaitGroup
		requestCount    = 0
	)

	tracker := &protoLogTracker{}

	// ---- Cache check span ----
	cacheStart := time.Now()
	_, cacheSpan := s.tracer.Start(spanCtx, GetSpanName("prefetch", "cacheCheck"))

	// If cache available and has the payload, SHORT-CIRCUIT: mark success and return immediately.
	if s.getPayloadResponseForProxySlot == nil {
		s.logger.Error().Fields(logMetric.GetFields()).Msg("PreFetchPayload :: cache is nil")
		errChan <- toErrorResp(http.StatusInternalServerError, "cache is nil")
		cacheSpan.SetAttributes(attribute.String("result", "nil_cache"))
	} else if cachedValue, exists := s.getPayloadResponseForProxySlot.Get(payloadCacheKey); exists && cachedValue != nil {
		payloadResponseForProxy, ok := cachedValue.(*common.PayloadResponseForProxy)
		if !ok {
			cacheSpan.SetAttributes(attribute.String("result", "cast_error"))
			errChan <- toErrorResp(http.StatusInternalServerError, "failed to cast cached value")
		} else if marshaledVal, err := payloadResponseForProxy.GetMarshalledResponse(); err != nil {
			cacheSpan.SetAttributes(attribute.String("result", "marshal_error"))
			errChan <- toErrorResp(http.StatusInternalServerError, "failed to marshal cached value")
		} else {
			if tracker.grpcLoggedOnce.CompareAndSwap(false, true) {
				s.logger.Info().Fields(logMetric.GetFields()).Msg("prefetch: cache hit")
			}

			// Fast-path success: write into our cache as the winner (idempotent) and return.
			proxyCacheKey := common.GetKeyForCachingPayload(fields.slot, fields.parentHash, fields.blockHash, fields.proposerPubKey)
			payloadResponse := &common.PayloadResponseForProxy{
				MarshalledPayloadResponse: marshaledVal,
				BlockValue:                fields.blockValue,
			}
			// Allow "already exists"
			_ = s.getPayloadResponseForProxySlot.Add(proxyCacheKey, payloadResponse, cache.DefaultExpiration)

			*success = true
			payloadSize := len(marshaledVal)
			cacheSpan.SetAttributes(
				attribute.String("result", "hit_fastpath"),
				attribute.Int64("duration_ms", time.Since(cacheStart).Milliseconds()),
				attribute.Int("payload_size_bytes", payloadSize),
			)
			cacheSpan.End()

			durationMs := time.Since(start).Milliseconds()
			// record cache fastpath as prefetch success (non-blocking)
			go s.IDataService.GetFlowService().RecordPrefetchDone(fields.slot, fields.parentHash, fields.blockHash, fields.proposerPubKey, reqID, "", true, durationMs, FlowSourcePrefetchCache, "", "", payloadSize, "")

			// Add a small outcome event on the parent span for visibility
			parentSpan.AddEvent("cache_fastpath_return", trace.WithAttributes(
				attribute.String("cacheKey", proxyCacheKey),
			))
			s.logger.Info().Fields(logMetric.GetFields()).Msg("PreFetchPayload :: prefetch succeeded (cache-fastpath)")
			return
		}
	} else {
		errChan <- toErrorResp(http.StatusBadRequest, "local payload not found")
		cacheSpan.SetAttributes(attribute.String("result", "miss"))
	}
	cacheSpan.SetAttributes(attribute.Int64("duration_ms", time.Since(cacheStart).Milliseconds()))
	cacheSpan.End()

	// ---- Fanout setup span ----
	setupStart := time.Now()
	_, setupSpan := s.tracer.Start(spanCtx, GetSpanName("prefetch", "fanoutSetup"))
	clients := s.clients
	if fields.client != nil {
		clients = append(clients, fields.client)
	}
	requestCount = len(clients)
	setupSpan.SetAttributes(
		attribute.Int("clients_count", len(clients)),
		attribute.Int("expected_responses", requestCount),
		attribute.Int64("duration_ms", time.Since(setupStart).Milliseconds()),
	)
	setupSpan.End()

	// nothing to do except cache check
	if len(clients) == 0 {
		noClientsStart := time.Now()
		_, noClientsSpan := s.tracer.Start(spanCtx, GetSpanName("prefetch", "noClients"))
		noClientsSpan.SetAttributes(
			attribute.String("status", "no_downstreams"),
			attribute.Int64("duration_ms", time.Since(noClientsStart).Milliseconds()),
		)
		noClientsSpan.End()
		*success = false
		return
	}

	// Spawn client attempts
	for _, client := range clients {
		wg.Add(1)
		go func(client *common.ParentClient) {
			defer wg.Done()
			prefetchLogger := s.logger.With().Fields(logMetric.GetFields()).Logger()
			s.prefetchPayload(ctx, spanCtx, client.SafeClient, req, parentSpan, errChan, respChan, prefetchLogger, tracker)
		}(client)
	}

	// ---- Select loop span ----
	loopStart := time.Now()
	_, loopSpan := s.tracer.Start(spanCtx, GetSpanName("prefetch", "waitForWinner"))
	defer func() {
		loopSpan.SetAttributes(attribute.Int64("duration_ms", time.Since(loopStart).Milliseconds()))
		loopSpan.End()
	}()

	for i := 0; i < requestCount; i++ {
		select {
		case <-ctx.Done():
			s.logger.Debug().Fields(logMetric.GetFields()).Msg("PreFetchPayload :: context canceled")
			loopSpan.AddEvent("ctx_done", trace.WithAttributes(
				attribute.String("ctx_err", func() string {
					if ctx.Err() != nil {
						return ctx.Err().Error()
					}
					return ""
				}()),
			))
			*success = false
			go s.IDataService.GetFlowService().RecordPrefetchDone(fields.slot, fields.parentHash, fields.blockHash, fields.proposerPubKey, reqID, getHeaderReqID, false, time.Since(start).Milliseconds(), FlowSourceUnknown, "", "", 0, "ctx_cancelled")
			return

		case _err := <-errChan:
			if _err != nil {
				s.logger.Debug().Fields(logMetric.GetFields()).Interface("error", _err).Msg("PreFetchPayload :: received error")
				loopSpan.AddEvent("error", trace.WithAttributes(attribute.String("err", _err.Error())))
			}

		case out := <-respChan:
			if out == nil || out.resp == nil {
				continue
			}

			resp := out.resp
			proxyCacheKey := common.GetKeyForCachingPayload(fields.slot, fields.parentHash, fields.blockHash, fields.proposerPubKey)
			*success = true
			payloadResponse := &common.PayloadResponseForProxy{
				MarshalledPayloadResponse: resp.VersionedExecutionPayload,
				BlockValue:                fields.blockValue,
			}
			payloadSize := len(resp.VersionedExecutionPayload)

			// Treat "already exists" as success (payload ready).
			if err := s.getPayloadResponseForProxySlot.Add(proxyCacheKey, payloadResponse, cache.DefaultExpiration); err != nil {
				s.logger.Debug().Fields(logMetric.GetFields()).Err(err).Msg("PreFetchPayload :: cache already has payload (ok)")
			}
			s.logger.Info().Fields(logMetric.GetFields()).
				Int("payload_size_bytes", payloadSize).
				Str("winner_url", out.url).
				Str("winner_source", string(out.source)).
				Msg("PreFetchPayload :: prefetch succeeded")

			loopSpan.AddEvent("winner", trace.WithAttributes(
				attribute.String("cacheKey", proxyCacheKey),
				attribute.Int("payload_size_bytes", payloadSize),
				attribute.String("winner_url", out.url),
				attribute.String("winner_source", string(out.source)),
			))

			durationMs := time.Since(start).Milliseconds()

			go s.IDataService.GetFlowService().RecordPrefetchDone(fields.slot, fields.parentHash, fields.blockHash, fields.proposerPubKey, reqID, getHeaderReqID, true, durationMs, out.source, out.url, out.nodeID, payloadSize, "no error")
			return
		}
	}

	// ---- Outcome span (no winner) ----
	wg.Wait()
	close(respChan)
	close(errChan)

	outcomeStart := time.Now()
	_, outcomeSpan := s.tracer.Start(spanCtx, GetSpanName("prefetch", "outcome"))
	if tracker.grpcAttempted.Load() && !tracker.grpcSuccess.Load() {
		if tracker.grpcLoggedOnce.CompareAndSwap(false, true) {
			s.logger.Warn().Fields(logMetric.GetFields()).Msg("prefetch gRPC: all attempts failed")
		}
	}
	if tracker.httpAttempted.Load() && !tracker.httpSuccess.Load() {
		if tracker.httpLoggedOnce.CompareAndSwap(false, true) {
			s.logger.Warn().Fields(logMetric.GetFields()).Msg("prefetch HTTP: all attempts failed")
		}
	}
	*success = false
	outcomeSpan.SetAttributes(
		attribute.Bool("grpcAttempted", tracker.grpcAttempted.Load()),
		attribute.Bool("grpcSuccess", tracker.grpcSuccess.Load()),
		attribute.Bool("httpAttempted", tracker.httpAttempted.Load()),
		attribute.Bool("httpSuccess", tracker.httpSuccess.Load()),
		attribute.Int64("duration_ms", time.Since(outcomeStart).Milliseconds()),
	)
	outcomeSpan.End()

	// record failure outcome
	go s.IDataService.GetFlowService().RecordPrefetchDone(fields.slot, fields.parentHash, fields.blockHash, fields.proposerPubKey, reqID, getHeaderReqID, false, time.Since(start).Milliseconds(), FlowSourceUnknown, "", "", 0, "")
}

// ========================= Builder (Optimistic V3) path =========================

func (s *Service) prefetchPayloadFromBuilder(ctx context.Context, spanCtx context.Context, fields *preFetcherFields, logMetric *LogMetric) bool {
	_, span := s.tracer.Start(spanCtx, GetSpanName("prefetch", "fromBuilder"))
	var success atomic.Bool
	defer func() {
		span.SetAttributes(attribute.Bool("success", success.Load()))
		span.End()
	}()

	payloadUrlsData := common.SafeSplit(fields.payloadFetchUrl, optimisticv3.PayloadUrlsTypeSeparator)
	if len(payloadUrlsData) != optimisticv3.PayloadUrlsDataExpectedLength {
		logMetric.Fields(map[string]any{"payloadUrlsData": payloadUrlsData})
		s.logger.Debug().Err(errors.New("invalid payload URL format")).Fields(logMetric.GetFields()).Msg("Failed to fetch Optimistic V3 payload from builder")
		return success.Load()
	}

	payloadUrlType := payloadUrlsData[optimisticv3.PayloadUrlTypeIndex]
	payloadUrlsCSV := payloadUrlsData[optimisticv3.PayloadUrlsCSVIndex]
	payloadUrls := common.SafeSplit(payloadUrlsCSV, ",")

	span.SetAttributes(attribute.String("payloadUrlType", payloadUrlType), attribute.StringSlice("payloadUrls", payloadUrls))

	switch optimisticv3.PayloadUrlType(payloadUrlType) {
	case optimisticv3.PayloadUrlTypeHTTP:
		success.Store(s.clientPreFetchGetPayloadHTTP(ctx, logMetric, fields, payloadUrls))
		return success.Load()
	case optimisticv3.PayloadUrlTypeGRPC:
		// We only support HTTP requests for Optimistic V3 payloads from builders for now
		s.logger.Debug().Fields(logMetric.GetFields()).Msg("Ignoring fetch Optimistic V3 payload request with 'grpc' URL type")
		return success.Load()
	default:
		s.logger.Debug().Err(errors.New("invalid payload URL type")).Fields(logMetric.GetFields()).Msg("Failed to fetch Optimistic V3 payload from builder")
		return success.Load()
	}
}

// ========================= HTTP fanout to builder =========================

func (s *Service) clientPreFetchGetPayloadHTTP(ctx context.Context, logMetric *LogMetric, fields *preFetcherFields, payloadUrls []string) bool {
	_, fetchSpan := s.tracer.Start(ctx, GetSpanName("prefetch", "httpFanout"))
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
		s.logger.Debug().Err(err).Fields(logMetric.GetFields()).Msg("failed to prepare HTTP get_payload_v3 request")
		return false
	}

	// we keep this function focused only on builder success/failure.
	// Detailed flow recording for builder could be added here later if needed.
	responseChan := make(chan *common.VersionedSubmitBlockRequest, len(payloadUrls))

	// Send request to all builders
	for _, payloadUrl := range payloadUrls {
		url := payloadUrl + common.PathGetPayloadV3
		go func(url string) {
			result := new(common.VersionedSubmitBlockRequest)
			reqStart := time.Now()
			code, durationMS, err := httpclient.FetchSSZ(http.MethodPost, url, payload, result, nil, true)
			if err != nil {
				s.logger.Debug().Fields(logMetric.GetFields()).
					Err(err).
					Str("url", url).
					Int("code", code).
					Int64("durationMS", durationMS).
					Int64("duration_ms_measured", time.Since(reqStart).Milliseconds()).
					Msg("failed to prefetch payload with HTTP")
				return
			}
			responseChan <- result
		}(url)
	}

	// Process first positive response from builder (or timeout)
	return s.processGetPayloadV3Responses(ctx, responseChan, logMetric, fields)
}

// ========================= Helpers for builder V3 =========================

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

func (s *Service) processGetPayloadV3Responses(
	ctx context.Context,
	responseChan chan *common.VersionedSubmitBlockRequest,
	logMetric *LogMetric,
	fields *preFetcherFields,
) bool {
	for {
		select {
		case <-ctx.Done():
			s.logger.Debug().Fields(logMetric.GetFields()).Msg("PreFetchPayloadV3 :: context cancelled")
			return false
		case response := <-responseChan:
			if response == nil {
				s.logger.Debug().Fields(logMetric.GetFields()).Msg("PreFetchPayloadV3 :: nil payload from builder")
				continue
			}
			getPayloadResponseSpec, err := common.BuildGetPayloadResponse(response)
			if err != nil {
				s.logger.Debug().Fields(logMetric.GetFields()).Err(err).Msg("PreFetchPayloadV3 :: BuildGetPayloadResponse failed")
				continue
			}
			getPayloadResponse := common.VersionedSubmitBlindedBlockResponse{
				VersionedSubmitBlindedBlockResponse: *getPayloadResponseSpec,
			}
			proxyCacheKey := common.GetKeyForCachingPayload(fields.slot, fields.parentHash, fields.blockHash, fields.proposerPubKey)

			payloadResponse := &common.PayloadResponseForProxy{
				PayloadResponse: getPayloadResponse,
				BlockValue:      fields.blockValue,
			}

			if err := s.getPayloadResponseForProxySlot.Add(proxyCacheKey, payloadResponse, cache.DefaultExpiration); err != nil {
				s.logger.Debug().Fields(logMetric.GetFields()).Err(err).Msg("PreFetchPayloadV3 :: cache already exists")
				return true // payload ready already
			}

			s.logger.Info().Fields(logMetric.GetFields()).Msg("PreFetchPayloadV3 :: HTTP builder prefetch succeeded")
			return true
		case <-time.After(common.OptimisticV3FetchPayloadTimeout):
			s.logger.Warn().Fields(logMetric.GetFields()).Msg("PreFetchPayloadV3 :: timeout waiting for builder HTTP response")
			return false
		}
	}
}

// ========================= Helpers for JSON/SSZ decode path =========================

func (s *Service) prefetchPayloadToSignedBlindedBeaconBlock(ctx context.Context, payload []byte) (*common.VersionedSignedBlindedBeaconBlock, *ErrorResp) {
	_, readPayload := s.tracer.Start(ctx, GetSpanName("validateAndFetchPayload", "readPayload"))

	bodyString := string(payload)
	blockHashIndex := strings.LastIndex(bodyString, "\"block_hash\"")

	if blockHashIndex == -1 {
		return nil, toErrorResp(http.StatusBadRequest, "invalid input")
	}
	readPayload.End(trace.WithTimestamp(time.Now()))

	_, decodeJSONSpan := s.tracer.Start(ctx, GetSpanName("validateAndFetchPayload", "decodeJSON"))
	signedBlindedBeaconBlock, err := fastjson.UnmarshalToSignedBlindedBeaconBlock(bodyString)
	if err != nil {
		decodeJSONSpan.End(trace.WithTimestamp(time.Now()))
		return nil, toErrorResp(http.StatusBadRequest, err.Error())
	}
	decodeJSONSpan.End(trace.WithTimestamp(time.Now()))
	return signedBlindedBeaconBlock, nil
}

// ========================= Downstream attempts (gRPC + HTTP hedge) =========================

func (s *Service) prefetchPayload(
	ctx context.Context,
	spanctx context.Context,
	client *common.Client,
	req *relaygrpc.PreFetchGetPayloadRequest,
	span trace.Span,
	errChan chan *ErrorResp,
	respChan chan *prefetchResult,
	logger zerolog.Logger,
	tracker *protoLogTracker,
) {
	// short hedged timeout
	clientCtx, cancel := context.WithTimeout(ctx, 900*time.Millisecond)
	defer cancel()

	exitSignal := false
	wg := &sync.WaitGroup{}
	mu := &sync.Mutex{}

	// gRPC attempt
	tracker.grpcAttempted.Store(true)
	wg.Add(1)
	go func() {
		defer wg.Done()
		reqStart := time.Now()
		_, childSpan := s.tracer.Start(spanctx, GetSpanName("prefetch", "gRPC"))
		childSpan.SetAttributes(attribute.String("url", client.URL), attribute.String("nodeID", client.NodeID))
		out, err := client.PreFetchGetPayload(clientCtx, req)
		reqDurMs := time.Since(reqStart).Milliseconds()
		if err == nil && out != nil && out.Code == uint32(codes.OK) {
			if !tracker.grpcSuccess.Swap(true) {
				if tracker.grpcLoggedOnce.CompareAndSwap(false, true) {
					logger.Info().Str("url", client.URL).Int64("duration_ms", reqDurMs).Msg("prefetch gRPC: succeeded")
				}
			}
			childSpan.SetAttributes(
				attribute.Int64("request_duration_ms", reqDurMs),
				attribute.Int("payload_size_bytes", len(out.VersionedExecutionPayload)),
			)
			mu.Lock()
			if !exitSignal {
				exitSignal = true
				select {
				case respChan <- &prefetchResult{resp: out, source: FlowSourcePrefetchGRPC, url: client.URL, nodeID: client.NodeID}:
				default:
				}
				cancel()
			}
			mu.Unlock()
		}
		if err != nil {
			childSpan.SetAttributes(
				attribute.Int64("request_duration_ms", reqDurMs),
				attribute.String("error", err.Error()),
			)
		}
		childSpan.End()
	}()

	// HTTP hedge
	tracker.httpAttempted.Store(true)
	wg.Add(1)
	go func() {
		defer wg.Done()
		reqCtx, childSpan := s.tracer.Start(spanctx, GetSpanName("prefetch", "HTTP"))
		childSpan.SetAttributes(
			attribute.String("url", client.URL),
			attribute.String("nodeID", client.NodeID),
		)
		reqStart := time.Now()
		out, err := s.PreFetchGetPayloadPlaceHTTPRequest(clientCtx, reqCtx, req, client.URL, client.NodeID)
		reqDurMs := time.Since(reqStart).Milliseconds()
		if err == nil && out != nil && out.Code == uint32(codes.OK) {
			if !tracker.httpSuccess.Swap(true) {
				if tracker.httpLoggedOnce.CompareAndSwap(false, true) {
					logger.Info().
						Str("url", client.URL).
						Int64("duration_ms", reqDurMs).
						Msg("prefetch HTTP: succeeded")
				}
			}
			childSpan.SetAttributes(
				attribute.Int64("request_duration_ms", reqDurMs),
				attribute.Int("payload_size_bytes", len(out.VersionedExecutionPayload)),
			)
			mu.Lock()
			if !exitSignal {
				exitSignal = true
				select {
				case respChan <- &prefetchResult{resp: out, source: FlowSourcePrefetchHTTP, url: client.URL, nodeID: client.NodeID}:
				default:
				}
				cancel()
			}
			mu.Unlock()
		}
		if err != nil {
			childSpan.SetAttributes(
				attribute.Int64("request_duration_ms", reqDurMs),
				attribute.String("error", err.Error()),
			)
		}
		childSpan.End()
	}()

	wg.Wait()
	if exitSignal {
		return
	}
	errChan <- toErrorResp(http.StatusInternalServerError, "relay failed prefetch attempts")
}

// ========================= HTTP placement helper =========================

func (s *Service) PreFetchGetPayloadPlaceHTTPRequest(
	ctx context.Context,
	spanCtx context.Context,
	origReq *relaygrpc.PreFetchGetPayloadRequest,
	url string,
	nodeID string,
) (*relaygrpc.PreFetchGetPayloadResponse, error) {
	reqData := common.PreFetchGetPayloadRequestHTTP{
		Slot:       origReq.GetSlot(),
		ParentHash: origReq.GetParentHash(),
		BlockHash:  origReq.GetBlockHash(),
		Pubkey:     origReq.GetPubkey(),
		ClientIp:   origReq.GetClientIp(),
		ReceivedAt: origReq.GetReceivedAt(),
		ReqID:      origReq.GetReqId(),
	}
	_, marshalSpan := s.tracer.Start(spanCtx, GetSpanName("prefetch.httpPlace", "marshal"))
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
	s.logger.Debug().
		Str("nodeID", nodeID).
		Str("finalURL", finalURL).
		Str("originalURL", originalURL).
		Msg("making prefetch request")

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, finalURL, bytes.NewReader(reqJSON))
	if err != nil {
		s.logger.Error().
			Str("nodeID", nodeID).
			Str("finalURL", finalURL).
			Str("originalURL", originalURL).
			Msg("prefetch.httpPlace failed ")
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpCli := getPrefetchHTTPClient()
	reqStart := time.Now()
	_, requestSpan := s.tracer.Start(spanCtx, GetSpanName("prefetch.httpPlace", "request"))
	resp, err := httpCli.Do(httpReq)
	requestSpan.SetAttributes(
		attribute.Int64("duration_ms", time.Since(reqStart).Milliseconds()),
	)
	requestSpan.End()
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	_, unmarshalSpan := s.tracer.Start(spanCtx, GetSpanName("prefetch.httpPlace", "unmarshal"))
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
