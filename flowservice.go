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
	FlowSourceLocalBidCache   FlowSource = "localBidCache"
	FlowSourceRemoteRelay     FlowSource = "remoteRelay"
	FlowSourceBuilder         FlowSource = "builder"
	FlowSourcePrefetchCache   FlowSource = "prefetchCache"
	FlowSourcePrefetchGRPC    FlowSource = "prefetchGrpc"
	FlowSourcePrefetchHTTP    FlowSource = "prefetchHttp"
	FlowSourceGetPayloadLocal FlowSource = "getPayloadLocal"
	FlowSourceGetPayloadRelay FlowSource = "getPayloadRemoteRelay"
	FlowSourceGetPayloadBldr  FlowSource = "getPayloadBuilder"
)

type HeaderFlowEvent struct {
	FlowEventSentAt      time.Time  `json:"at"`
	ServedByThisNode     bool       `json:"servedByThisNode"`
	SlotStartTime        time.Time  `json:"slotStartTime"`
	MsIntoSlot           int64      `json:"msIntoSlot"`
	MsIntoSlotWithDelay  int64      `json:"msIntoSlotWithDelay"`
	AccountID            string     `json:"accountId"`
	ValidatorID          string     `json:"validatorId"`
	Source               FlowSource `json:"source"`
	GetHeaderReqID       string     `json:"getHeaderReqId"`
	GetHeaderStartUnixMs string     `json:"getHeaderStartUnixMs"`
	BlockValue           string     `json:"blockValue"`
	BuilderPubkey        string     `json:"builderPubkey"`
	BuilderExtraData     string     `json:"builderExtraData"`
	BlockHashReceivedAt  time.Time  `json:"blockHashReceivedAt"`
	RelayURL             string     `json:"relayUrl"`
	BlockSequenceNumber  *uint64    `json:"blockSequenceNumber"`
	Latency              int64      `json:"latency"`
	Sleep                int64      `json:"sleep"`
	MaxSleep             int64      `json:"maxSleep"`
	ClientIP             string     `json:"clientIp"`
	NodeID               string     `json:"nodeId"`
	SlotUID              string     `json:"slotUid"`
	HeaderUserAgent      string     `json:"headerUserAgent"`
	RepickedBlock        bool       `json:"repicked"`
}

type PrefetchFlowEvent struct {
	PrefetchID              string     `json:"prefetchId"`
	GetHeaderReqID          string     `json:"getHeaderReqId"`
	StartedAt               time.Time  `json:"startedAt"`
	MsIntoSlotPrefetchStart int64      `json:"msIntoSlotStart"`
	FinishedAt              time.Time  `json:"finishedAt"`
	DurationMs              int64      `json:"durationMs"`
	Success                 bool       `json:"success"`
	Source                  FlowSource `json:"source"`
	ServerURL               string     `json:"serverUrl"`
	ServerNodeID            string     `json:"serverNodeId"`
	PayloadSizeBytes        int        `json:"payloadSizeBytes"`
	Error                   string     `json:"error"`
}

type GetPayloadFlowEvent struct {
	FlowEventSentAt       time.Time  `json:"at"`
	ReqID                 string     `json:"reqId"`
	ClientIP              string     `json:"clientIp"`
	Source                FlowSource `json:"source"` // localCache / prefetch / remote etc
	Success               bool       `json:"success"`
	DurationMs            int64      `json:"durationMs"`
	MsIntoSlotStart       int64      `json:"msIntoSlotStart"`
	MsIntoSlotEnd         int64      `json:"msIntoSlotEnd"`
	PayloadSizeBytes      int        `json:"payloadSizeBytes"`
	BlockValueEth         string     `json:"blockValueEth"`
	RelayURL              string     `json:"relayUrl"`
	Error                 string     `json:"error"`
	GetHeaderReqID        string     `json:"getHeaderReqId"`
	GetPayloadStartUnixMs string     `json:"getPayloadStartUnixMs"`
	SlotStartTimeUnix     int64      `json:"slotStartTimeUnix"`
	MsIntoSlotHeaderStart int64      `json:"msIntoSlotHeaderStart"`
	UserAgent             string     `json:"userAgent"`
	AccountID             string     `json:"accountId"`
	ValidatorID           string     `json:"validatorId"`
	Latency               int64      `json:"latency"`
	SlotUID               string     `json:"slotUid"`
	NodeID                string     `json:"nodeId"`
}

// Root record keyed by common.GetKeyForCachingPayload()
type FlowRecord struct {
	NodeID         string `json:"nodeId"`
	Slot           uint64 `json:"slot"`
	ParentHash     string `json:"parentHash"`
	BlockHash      string `json:"blockHash"`
	BlockValue     string `json:"blockValue"`
	ProposerPubkey string `json:"proposerPubkey"`

	BuilderPubkey    string `json:"builderPubkey"`
	BuilderExtraData string `json:"builderExtraData"`
	RelayURL         string `json:"relayUrl"`

	Headers    []HeaderFlowEvent     `json:"headers"`
	Prefetches []PrefetchFlowEvent   `json:"prefetches"`
	GetPayload []GetPayloadFlowEvent `json:"getPayload"`
}

type IFlowService interface {
	RecordHeaderFlow(slot uint64, parentHash, blockHash, blockValue, proposerPubkey, nodeID string, ev HeaderFlowEvent)

	RecordPrefetchStart(slot uint64, parentHash, blockHash, proposerPubkey, blockValue, nodeID string, ev PrefetchFlowEvent)

	RecordPrefetchDone(slot uint64, parentHash, blockHash, proposerPubkey, reqID, getHeaderReqID string, success bool, durationMs int64, source FlowSource, serverURL, serverNodeID string, payloadSizeBytes int, errStr string)

	RecordGetPayload(slot uint64, parentHash, blockHash, proposerPubkey, blockValue, nodeID string, ev GetPayloadFlowEvent)

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

func (fs *FlowService) getOrCreateFlowRecord(key string, slot uint64, parentHash, blockHash, proposerPubkey, blockValue, nodeID string) *FlowRecord {
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
		BlockValue:     blockValue,
		NodeID:         nodeID,
	}
	fs.flowCache.Set(key, rec, cache.DefaultExpiration)
	return rec
}

// ---------------------- Flow write methods ----------------------

func (fs *FlowService) RecordHeaderFlow(slot uint64, parentHash, blockHash, blockValue, proposerPubkey, nodeID string, ev HeaderFlowEvent) {
	if fs.flowCache == nil {
		return
	}
	key := common.GetKeyForCachingPayload(slot, parentHash, blockHash, proposerPubkey)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	rec := fs.getOrCreateFlowRecord(key, slot, parentHash, blockHash, proposerPubkey, blockValue, nodeID)
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

func (fs *FlowService) RecordPrefetchStart(slot uint64, parentHash, blockHash, proposerPubkey, blockValue, nodeID string, ev PrefetchFlowEvent) {
	if fs.flowCache == nil {
		return
	}
	key := common.GetKeyForCachingPayload(slot, parentHash, blockHash, proposerPubkey)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	rec := fs.getOrCreateFlowRecord(key, slot, parentHash, blockHash, proposerPubkey, blockValue, nodeID)
	if rec == nil {
		return
	}
	rec.Prefetches = append(rec.Prefetches, ev)
}

func (fs *FlowService) RecordPrefetchDone(slot uint64, parentHash, blockHash, proposerPubkey, reqID, getHeaderReqID string, success bool, durationMs int64, source FlowSource, serverURL, serverNodeID string, payloadSizeBytes int, errStr string) {
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
		if rec.Prefetches[i].PrefetchID == reqID {
			rec.Prefetches[i].Success = success
			rec.Prefetches[i].DurationMs = durationMs
			rec.Prefetches[i].FinishedAt = time.Now().UTC()
			rec.Prefetches[i].GetHeaderReqID = getHeaderReqID
			if source != "" {
				rec.Prefetches[i].Source = source
			}
			rec.Prefetches[i].ServerURL = serverURL
			rec.Prefetches[i].ServerNodeID = serverNodeID
			rec.Prefetches[i].PayloadSizeBytes = payloadSizeBytes
			rec.Prefetches[i].Error = errStr
			return
		}
	}

	// no matching start – append synthetic completion
	rec.Prefetches = append(rec.Prefetches, PrefetchFlowEvent{
		PrefetchID:       reqID,
		FinishedAt:       time.Now().UTC(),
		DurationMs:       durationMs,
		GetHeaderReqID:   getHeaderReqID,
		ServerURL:        serverURL,
		ServerNodeID:     serverNodeID,
		PayloadSizeBytes: payloadSizeBytes,
		Success:          success,
		Source:           source,
		Error:            errStr,
	})
}

func (fs *FlowService) RecordGetPayload(slot uint64, parentHash, blockHash, proposerPubkey, blockValue, nodeID string, ev GetPayloadFlowEvent) {
	if fs.flowCache == nil {
		return
	}
	key := common.GetKeyForCachingPayload(slot, parentHash, blockHash, proposerPubkey)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	rec := fs.getOrCreateFlowRecord(key, slot, parentHash, blockHash, proposerPubkey, blockValue, nodeID)
	if rec == nil {
		return
	}
	rec.GetPayload = append(rec.GetPayload, ev)
}

// ---------------------- Flow read methods ----------------------

func (fs *FlowService) GetAllFlowsSnapshot() map[string]*FlowRecord {
	if fs.flowCache == nil {
		return map[string]*FlowRecord{}
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
		return []*FlowRecord{}
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
		return []*FlowRecord{}
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
