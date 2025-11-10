package relayproxy

import (
	"sync"
	"time"

	"github.com/bloXroute-Labs/relayproxy/common"
	"github.com/patrickmn/go-cache"
)

type FlowSource string

const (
	FlowSourceUnknown         FlowSource = ""
	FlowSourceLocalBidCache   FlowSource = "local_bid_cache"
	FlowSourceRemoteRelay     FlowSource = "remote_relay"
	FlowSourceBuilder         FlowSource = "builder"
	FlowSourcePrefetchCache   FlowSource = "prefetch_cache"
	FlowSourcePrefetchGRPC    FlowSource = "prefetch_grpc"
	FlowSourcePrefetchHTTP    FlowSource = "prefetch_http"
	FlowSourceGetPayloadLocal FlowSource = "getpayload_local"
	FlowSourceGetPayloadRelay FlowSource = "getpayload_remote_relay"
	FlowSourceGetPayloadBldr  FlowSource = "getpayload_builder"
)

type HeaderFlowEvent struct {
	FlowEventSentAt      time.Time  `json:"at"`
	ServedByThisNode     bool       `json:"servedByThisNode"`
	SlotStartTime        time.Time  `json:"slot_start_time"`
	MsIntoSlot           int64      `json:"msIntoSlot"`
	MsIntoSlotWithDelay  int64      `json:"msIntoSlotWithDelay"`
	AccountID            string     `json:"accountId"`
	ValidatorID          string     `json:"validatorId"`
	Source               FlowSource `json:"source"`
	GetHeaderReqID       string     `json:"getHeaderReqId"`
	GetHeaderStartUnixMs string     `json:"getHeaderStartUnixMs"`
	BlockValue           string     `json:"block_value"`
	BuilderPubkey        string     `json:"builderPubkey"`
	BuilderExtraData     string     `json:"builderExtraData"`
	BlockHashReceivedAt  time.Time  `json:"block_hash_received_at"`
	RelayURL             string     `json:"relayUrl"`
	BlockSequenceNumber  *uint64    `json:"block_sequence_number"`
	Latency              int64      `json:"latency"`
	Sleep                int64      `json:"sleep"`
	MaxSleep             int64      `json:"max_sleep"`
	ClientIP             string     `json:"client_ip"`
	NodeID               string     `json:"node_id"`
	SlotUID              string     `json:"slot_uid"`
	HeaderUserAgent      string     `json:"header_user_agent"`
}

type PrefetchFlowEvent struct {
	ReqID                   string     `json:"reqId"`
	GetHeaderReqID          string     `json:"get_header_req_id"`
	StartedAt               time.Time  `json:"startedAt"`
	MsIntoSlotPrefetchStart int64      `json:"msIntoSlotStart"`
	FinishedAt              time.Time  `json:"finishedAt"`
	DurationMs              int64      `json:"durationMs"`
	Success                 bool       `json:"success"`
	Source                  FlowSource `json:"source"`
	Error                   string     `json:"error"`
}

type GetPayloadFlowEvent struct {
	FlowEventSentAt       time.Time  `json:"at"`
	ReqID                 string     `json:"reqID"`
	ClientIP              string     `json:"clientIP"`
	Source                FlowSource `json:"source"` // local_cache / prefetch / remote etc
	Success               bool       `json:"success"`
	DurationMs            int64      `json:"durationMs"`
	MsIntoSlotStart       int64      `json:"msIntoSlotStart"`
	MsIntoSlotEnd         int64      `json:"msIntoSlotEnd"`
	PayloadSizeBytes      int        `json:"payloadSizeBytes"`
	BlockValueEth         string     `json:"blockValueEth"`
	RelayURL              string     `json:"relayURL"`
	Error                 string     `json:"error"`
	GetHeaderReqID        string     `json:"getHeaderReqID"`
	SlotStartTimeUnix     int64      `json:"slotStartTimeUnix"`
	MsIntoSlotHeaderStart int64      `json:"msIntoSlotHeaderStart"`
	UserAgent             string     `json:"user_agent"`
	AccountID             string     `json:"account_id"`
	ValidatorID           string     `json:"validator_id"`
	Latency               int64      `json:"latency"`
	SlotUID               string     `json:"slot_uid"`
	NodeID                string     `json:"node_id"`
}

// Root record keyed by common.GetKeyForCachingPayload()
type FlowRecord struct {
	Slot           uint64 `json:"slot"`
	ParentHash     string `json:"parentHash"`
	BlockHash      string `json:"blockHash"`
	BlockValue     string `json:"block_value"`
	ProposerPubkey string `json:"proposerPubkey"`

	BuilderPubkey    string `json:"builderPubkey"`
	BuilderExtraData string `json:"builderExtraData"`
	RelayURL         string `json:"relayUrl"`

	Headers    []HeaderFlowEvent     `json:"headers"`
	Prefetches []PrefetchFlowEvent   `json:"prefetches"`
	GetPayload []GetPayloadFlowEvent `json:"getPayload"`
}

type IFlowService interface {
	RecordHeaderFlow(
		slot uint64,
		parentHash, blockHash, proposerPubkey string,
		ev HeaderFlowEvent,
	)

	RecordPrefetchStart(
		slot uint64,
		parentHash, blockHash, proposerPubkey string,
		ev PrefetchFlowEvent,
	)

	RecordPrefetchDone(slot uint64, parentHash, blockHash, proposerPubkey, reqID, getHeaderReqID string, success bool, durationMs int64, source FlowSource, errStr string)

	RecordGetPayload(
		slot uint64,
		parentHash, blockHash, proposerPubkey string,
		ev GetPayloadFlowEvent,
	)

	GetAllFlowsSnapshot() map[string]*FlowRecord
	GetFlowsBySlot(slot uint64) []*FlowRecord
	GetFlowsBySlotAndBlock(slot uint64, blockHash string) []*FlowRecord
}

type FlowService struct {
	flowCache *cache.Cache
	mu        sync.RWMutex
}

func NewFlowService(defaultTTL, cleanupInterval time.Duration) *FlowService {
	return &FlowService{
		flowCache: cache.New(defaultTTL, cleanupInterval),
	}
}

func (fs *FlowService) getOrCreateFlowRecord(
	key string,
	slot uint64,
	parentHash, blockHash, proposerPubkey string,
) *FlowRecord {
	if fs.flowCache == nil {
		return nil
	}

	if v, ok := fs.flowCache.Get(key); ok {
		if rec, ok2 := v.(*FlowRecord); ok2 && rec != nil {
			return rec
		}
	}

	rec := &FlowRecord{
		Slot:           slot,
		ParentHash:     parentHash,
		BlockHash:      blockHash,
		ProposerPubkey: proposerPubkey,
	}
	fs.flowCache.Set(key, rec, cache.DefaultExpiration)
	return rec
}

// ---------------------- Flow write methods ----------------------

func (fs *FlowService) RecordHeaderFlow(
	slot uint64,
	parentHash, blockHash, proposerPubkey string,
	ev HeaderFlowEvent,
) {
	if fs.flowCache == nil {
		return
	}
	key := common.GetKeyForCachingPayload(slot, parentHash, blockHash, proposerPubkey)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	rec := fs.getOrCreateFlowRecord(key, slot, parentHash, blockHash, proposerPubkey)
	if rec == nil {
		return
	}

	rec.Headers = append(rec.Headers, ev)

	if ev.BuilderPubkey != "" {
		rec.BuilderPubkey = ev.BuilderPubkey
	}
	if ev.BuilderExtraData != "" {
		rec.BuilderExtraData = ev.BuilderExtraData
	}
	if ev.RelayURL != "" {
		rec.RelayURL = ev.RelayURL
	}
}

func (fs *FlowService) RecordPrefetchStart(
	slot uint64,
	parentHash, blockHash, proposerPubkey string,
	ev PrefetchFlowEvent,
) {
	if fs.flowCache == nil {
		return
	}
	key := common.GetKeyForCachingPayload(slot, parentHash, blockHash, proposerPubkey)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	rec := fs.getOrCreateFlowRecord(key, slot, parentHash, blockHash, proposerPubkey)
	if rec == nil {
		return
	}
	rec.Prefetches = append(rec.Prefetches, ev)
}

func (fs *FlowService) RecordPrefetchDone(slot uint64, parentHash, blockHash, proposerPubkey, reqID, getHeaderReqID string, success bool, durationMs int64, source FlowSource, errStr string) {
	if fs.flowCache == nil {
		return
	}
	key := common.GetKeyForCachingPayload(slot, parentHash, blockHash, proposerPubkey)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	v, ok := fs.flowCache.Get(key)
	if !ok || v == nil {
		return
	}
	rec, ok := v.(*FlowRecord)
	if !ok || rec == nil {
		return
	}

	// find last matching ReqID, update in-place
	for i := len(rec.Prefetches) - 1; i >= 0; i-- {
		if rec.Prefetches[i].ReqID == reqID {
			rec.Prefetches[i].Success = success
			rec.Prefetches[i].DurationMs = durationMs
			rec.Prefetches[i].FinishedAt = time.Now().UTC()
			rec.Prefetches[i].GetHeaderReqID = getHeaderReqID
			if source != "" {
				rec.Prefetches[i].Source = source
			}
			rec.Prefetches[i].Error = errStr
			return
		}
	}

	// no matching start – append synthetic completion
	rec.Prefetches = append(rec.Prefetches, PrefetchFlowEvent{
		ReqID:      reqID,
		FinishedAt: time.Now().UTC(),
		DurationMs: durationMs,
		Success:    success,
		Source:     source,
		Error:      errStr,
	})
}

func (fs *FlowService) RecordGetPayload(
	slot uint64,
	parentHash, blockHash, proposerPubkey string,
	ev GetPayloadFlowEvent,
) {
	if fs.flowCache == nil {
		return
	}
	key := common.GetKeyForCachingPayload(slot, parentHash, blockHash, proposerPubkey)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	rec := fs.getOrCreateFlowRecord(key, slot, parentHash, blockHash, proposerPubkey)
	if rec == nil {
		return
	}
	rec.GetPayload = append(rec.GetPayload, ev)
}

// ---------------------- Flow read methods ----------------------

func (fs *FlowService) GetAllFlowsSnapshot() map[string]*FlowRecord {
	if fs.flowCache == nil {
		return nil
	}
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	items := fs.flowCache.Items()
	out := make(map[string]*FlowRecord, len(items))
	for k, v := range items {
		if rec, ok := v.Object.(*FlowRecord); ok && rec != nil {
			out[k] = rec
		}
	}
	return out
}

func (fs *FlowService) GetFlowsBySlot(slot uint64) []*FlowRecord {
	if fs.flowCache == nil {
		return nil
	}
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	items := fs.flowCache.Items()
	res := make([]*FlowRecord, 0)
	for _, v := range items {
		rec, ok := v.Object.(*FlowRecord)
		if !ok || rec == nil {
			continue
		}
		if rec.Slot == slot {
			res = append(res, rec)
		}
	}
	return res
}

func (fs *FlowService) GetFlowsBySlotAndBlock(slot uint64, blockHash string) []*FlowRecord {
	if fs.flowCache == nil {
		return nil
	}
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	items := fs.flowCache.Items()
	res := make([]*FlowRecord, 0)
	for _, v := range items {
		rec, ok := v.Object.(*FlowRecord)
		if !ok || rec == nil {
			continue
		}
		if rec.Slot == slot && rec.BlockHash == blockHash {
			res = append(res, rec)
		}
	}
	return res
}
