package relayproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	relaygrpc "github.com/bloXroute-Labs/relay-grpc"
	"github.com/bloXroute-Labs/relayproxy/common"
	"github.com/bloXroute-Labs/relayproxy/fastjson"
	"github.com/bloXroute-Labs/relayproxy/fluentstats"
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

func (s *Service) GetPayload(ctx context.Context, log *zerolog.Logger, in *PayloadRequestParams) (*common.VersionedPayloadInfo, error) {
	startTime := time.Now().UTC()
	id := uuid.NewString()

	parentSpan := trace.SpanFromContext(ctx)
	ctx = trace.ContextWithSpan(context.Background(), parentSpan)

	authKey := s.authKey
	if in.AuthHeader != "" {
		authKey = in.AuthHeader
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", authKey)

	*log = log.With().
		Str("method", getPayload).
		Time("receivedAt", in.ReceivedAt).
		Str("reqID", id).
		Bool("isAuthHeaderProvided", in.AuthHeader != "").
		Logger()
	log.Info().Msg("received getPayloadTrusted")
	ctx, span := s.tracer.Start(ctx, "getPayload-start")
	var (
		slotInt       int64
		blockHashStr  string
		parentHashStr string
		blockValueStr string
		uKey          string
		latency       int64
	)
	defer func() {
		_, logTimingSpan := s.tracer.Start(ctx, "getPayload-logTimingSpan")
		parentSpan.SetAttributes(
			attribute.String("method", getPayload),
			attribute.String("reqID", id),
			attribute.Int64("receivedAt", in.ReceivedAt.Unix()),
			attribute.Int64("slot", slotInt),
			attribute.String("blockHash", blockHashStr),
			attribute.String("parentHash", parentHashStr),
			attribute.String("blockValue", blockValueStr),
			attribute.String("uniqueKey", uKey),
			attribute.Int64("latency", latency),
		)
		log.Info().Msg("added spans getPayloadTrusted")
		logTimingSpan.End()
		span.End()
	}()

	_, timeToRelayRequestSpan := s.tracer.Start(ctx, "getPayload-TimeToRelayRequest")

	if in.GetPayloadStartTimeUnixMS != "" {
		if getPayloadStartTime, err := strconv.ParseInt(in.GetPayloadStartTimeUnixMS, 10, 64); err == nil {
			latency = in.ReceivedAt.Sub(time.UnixMilli(getPayloadStartTime)).Milliseconds()
		} else {
			log.Warn().Err(err).Msg("failed to parse getPayloadStartTimeUnixMS")
		}
	}

	req := &relaygrpc.GetPayloadRequest{
		ReqId:       id,
		Payload:     in.Payload,
		ClientIp:    in.ClientIP,
		Version:     s.version,
		ReceivedAt:  timestamppb.New(in.ReceivedAt),
		SecretToken: s.secretToken,
	}
	timeToRelayRequestSpan.End()

	_, prefetchPayloadToSignedBlindedBeaconBlockSpan := s.tracer.Start(ctx, "getPayload-prefetchPayloadToSignedBlindedBeaconBlockSpan")
	blindedBeaconBlock, errRes := s.prefetchPayloadToSignedBlindedBeaconBlock(ctx, in.Payload)
	if errRes != nil {
		log.Error().Err(errRes).Msg("prefetchPayloadToSignedBlindedBeaconBlock failed")
		go s.sendPayloadStats(in.Payload, log, false, nil, startTime, time.Now(), 0, id, latency, *in, errRes.Error())
		return nil, errRes
	}
	slot, err := blindedBeaconBlock.Slot()
	if err != nil {
		return nil, toErrorResp(http.StatusBadRequest, "failed to get slot")
	}
	blockHash, err := blindedBeaconBlock.ExecutionBlockHash()
	if err != nil {
		return nil, toErrorResp(http.StatusBadRequest, "failed to get block hash")
	}
	parentHash, err := blindedBeaconBlock.ExecutionParentHash()
	if err != nil {
		return nil, toErrorResp(http.StatusBadRequest, "failed to get parent hash")
	}
	slotInt = int64(slot)
	blockHashStr = blockHash.String()
	parentHashStr = parentHash.String()
	uKey = fmt.Sprintf("slot_%v_bHash_%v_pHash_%v", slotInt, blockHashStr, parentHashStr)
	*log = log.With().
		Int64("Slot", slotInt).
		Str("blockHash", blockHashStr).
		Str("parentHash", parentHashStr).
		Str("uKey", uKey).
		Logger()
	prefetchPayloadToSignedBlindedBeaconBlockSpan.End()

	go func() {
		if s.OnPayloadRequested == nil {
			log.Warn().Msg("skipping OnPayloadRequested")
			return
		}
		var pubkeyStr string
		miniSlotDuty, err := s.IDataService.GetSlotDuty(uint64(slot))
		if err == nil && miniSlotDuty != nil && miniSlotDuty.Registration != nil && miniSlotDuty.Registration.Message != nil {
			pub := miniSlotDuty.Registration.Message.Pubkey
			pubkeyStr = pub.String()
		}
		proposerRequestStartTimeUnixMS, _ := strconv.ParseInt(in.GetPayloadStartTimeUnixMS, 10, 64)
		err = s.OnPayloadRequested(uint64(slot), blockHashStr, parentHashStr, pubkeyStr, in.ClientIP, in.ReceivedAt, &blindedBeaconBlock.VersionedSignedBlindedBeaconBlock, proposerRequestStartTimeUnixMS, in.ValidatorID)
		if err != nil {
			log.Error().Err(err).Msg("failed to call OnPayloadRequested")
		}
	}()

	payloadInfoChan := make(chan *common.VersionedPayloadInfo, 1)

	// validate and  fetch payload from cache
	go func(ctx context.Context, l zerolog.Logger, parent trace.Span) {
		ctx, childSpan := s.tracer.Start(ctx, "validateAndFetchPayload")
		defer childSpan.End()

		payloadInfo, err := s.validateAndFetchPayload(ctx, blindedBeaconBlock)
		if err == nil && payloadInfo != nil {
			select {
			case payloadInfoChan <- payloadInfo:
			default:
			}
			if err != nil {
				l.Warn().Err(err).Msg("validateAndFetchPayload returned payload with partial error")
			}
		} else {
			l.Warn().Err(err).Msg("validateAndFetchPayload returned no payload")
		}
	}(ctx, *log, parentSpan)

	// fetch payload relay
	for _, client := range s.clients {
		go func(c *common.ParentClient, parent trace.Span) {
			ctx, childSpan := s.tracer.Start(ctx, "getPayloadWithRetry")
			defer childSpan.End()

			resp, err := s.getPayloadWithRetry(ctx, c.SafeClient, childSpan, req, maxGetPayloadRetry)
			if err == nil && resp != nil {
				select {
				case payloadInfoChan <- resp:
				default:
				}
			}
		}(client, parentSpan)
	}

	select {
	case payloadInfo := <-payloadInfoChan:
		go func() {
			if s.BlockPublishFunc != nil {
				s.BlockPublishFunc(s.tracer, s.logger, payloadInfo, blindedBeaconBlock, s.blockPublishingGatewayClient, s.gatewayAuthKey)
			}
		}()
		slotStartTime := GetSlotStartTime(s.beaconGenesisTime, int64(payloadInfo.Slot), s.secondsPerSlot)
		msIntoSlot := in.ReceivedAt.Sub(slotStartTime).Milliseconds()
		duration := time.Since(startTime)
		go s.sendPayloadStats(in.Payload, log, true, payloadInfo, startTime, slotStartTime, msIntoSlot, id, latency, *in, "no error")
		blockValueStr = payloadInfo.GetBlockValue()
		*log = log.With().
			Int64("latency", latency).
			Dur("duration", duration).
			Int64("slotStartTime", slotStartTime.UnixMilli()).
			Int64("msIntoSlot", msIntoSlot).
			Str("blockValue", blockValueStr).
			Logger()

		return payloadInfo, nil
	case <-time.After(1500 * time.Millisecond):
	}
	log.Error().Msg("timeout waiting for payload response")
	go s.sendPayloadStats(in.Payload, log, false, nil, startTime, time.Now(), 0, id, latency, *in, "timeout waiting for payload response,no execution payload for this request")
	return nil, toErrorResp(http.StatusBadRequest, "no execution payload for this request")
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

func (s *Service) sendPayloadStats(payload []byte, log *zerolog.Logger, isSucceeded bool, resp *common.VersionedPayloadInfo, startTime, slotStartTime time.Time, msIntoSlot int64, id string, latency int64, in PayloadRequestParams, errMsg string) {
	// 3 different scenario calling sendPayload stats
	// case 1 : resp success
	// case 2: Err case with resp
	// case 2: Err case with no resp
	out := resp.Copy()
	if out.GetSlot() != 0 {
		slotStartTime = GetSlotStartTime(s.beaconGenesisTime, int64(out.GetSlot()), s.secondsPerSlot)
		msIntoSlot = in.ReceivedAt.Sub(slotStartTime).Milliseconds()
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
				msIntoSlot = in.ReceivedAt.Sub(slotStartTime).Milliseconds()
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

	statsUserAgent := in.UserAgent
	if in.Cluster != "" {
		statsUserAgent = fmt.Sprintf("%s/%s", statsUserAgent, in.Cluster)
	}

	go s.IDataService.GetFlowService().RecordGetPayload(out.GetSlot(), out.GetParentHash(), out.GetBlockHash(), out.GetPubkey(), out.GetBlockValue(), s.nodeID, GetPayloadFlowEvent{
		FlowEventSentAt:       time.Now().UTC(),
		ReqID:                 id,
		ClientIP:              in.ClientIP,
		Source:                "",
		Success:               isSucceeded,
		DurationMs:            time.Since(startTime).Milliseconds(),
		MsIntoSlotStart:       msIntoSlot,
		MsIntoSlotEnd:         0,
		PayloadSizeBytes:      0,
		BlockValueEth:         out.GetBlockValue(),
		RelayURL:              "",
		Error:                 errMsg,
		GetHeaderReqID:        "",
		GetPayloadStartUnixMs: in.GetPayloadStartTimeUnixMS,
		SlotStartTimeUnix:     0,
		MsIntoSlotHeaderStart: 0,
		UserAgent:             statsUserAgent,
		AccountID:             in.AccountID,
		ValidatorID:           in.ValidatorID,
		Latency:               latency,
		SlotUID:               in.SlotUID,
		NodeID:                s.nodeID,
	})

	statsRecord := SlotStatsRecord{
		PayloadReqID:              id,
		PayloadReqReceivedAt:      in.ReceivedAt,
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
		ClientIP:                  in.ClientIP,
		NodeID:                    s.nodeID,
		AccountID:                 in.AccountID,
		ValidatorID:               in.ValidatorID,
		GetPayloadLatency:         latency,
		PayloadSlotUID:            in.SlotUID,
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
		RequestReceivedAt: in.ReceivedAt,
		Duration:          time.Since(startTime),
		SlotStartTime:     slotStartTime,
		MsIntoSlot:        msIntoSlot,
		Slot:              out.GetSlot(),
		ParentHash:        out.GetParentHash(),
		PubKey:            out.GetPubkey(),
		BlockHash:         out.GetBlockHash(),
		BlockValue:        out.GetBlockValue(),
		ReqID:             id,
		ClientIP:          in.ClientIP,
		Succeeded:         true,
		NodeID:            s.nodeID,
		AccountID:         in.AccountID,
		ValidatorID:       in.ValidatorID,
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

	for i := 0; i < 30; i++ { // try for 1.5s with 50ms interval
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
	}, toErrorResp(http.StatusBadRequest, "pre fetch payload not available in cache after retries")

}
