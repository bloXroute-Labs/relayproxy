package relayproxy

import (
	"time"
)

const (
	StatsRelayProxyGetHeader              = "relay-proxy-getHeader"
	StatsRelayProxyGetPayload             = "relay-proxy-getPayload"
	StatsRelayProxySlotStats              = "stats.relay-proxy-slotStats"
	StatsRelayProxySlotWon                = "stats.relay-proxy-slot-won"
	StatsRelayProxyHeaderStreamReceived   = "stats.relay-proxy-headerStreamReceived"
	StatsRelayProxyBlockStreamReceived    = "stats.relay-proxy-blockStreamReceived"
	StatsRelayProxyGetHeaderExternalRelay = "stats.relay-proxy-getHeader-externalRelay"

	TypeRelayProxyGetHeader              = "relay_proxy_provided_header"
	TypeRelayProxyGetPayload             = "relay_proxy_provided_payload"
	TypeRelayProxySlotStats              = "relay_proxy_slot_stats"
	TypeRelayProxySlotWon                = "relay_proxy_slot_won"
	TypeRelayProxyHeaderStreamReceived   = "relay_proxy_header_stream_received"
	TypeRelayProxyGetHeaderExternalRelay = "relay_proxy_external_relay_header"
	TypeRelayProxyBlockStreamReceived    = "relay_proxy_block_stream_received"
)

type HeaderStreamReceivedRecord struct {
	RelayReceivedAt   time.Time `json:"relay_received_at"`
	ReceivedAt        time.Time `json:"received_at"`
	SentAt            time.Time `json:"sent_at"`
	StreamLatencyInMS int64
	Slot              int64  `json:"slot"`
	ParentHash        string `json:"parent_hash"`
	PubKey            string `json:"pub_key"`
	BlockHash         string `json:"block_hash"`
	BlockValue        string `json:"block_value"`
	BuilderPubKey     string `json:"builder_pub_key"`
	BuilderExtraData  string `json:"builder_extra_data"`
	PaidBLXR          bool   `json:"paid_blxr"` // block paying to blxr
	ClientIP          string `json:"client_ip"`
	NodeID            string `json:"node_id"`
	AccountID         string `json:"account_id"`
	Method            string `json:"method"`
	PayloadFetchUrl   string `json:"payload_fetch_url"`
}

type BlockStreamReceivedRecord struct {
	RelayReceivedAt   time.Time `json:"relay_received_at"`
	ReceivedAt        time.Time `json:"received_at"`
	SentAt            time.Time `json:"sent_at"`
	StreamLatencyInMS int64     `json:"stream_latency_in_ms"`
	Slot              int64     `json:"slot"`
	ParentHash        string    `json:"parent_hash"`
	PubKey            string    `json:"pub_key"`
	BlockHash         string    `json:"block_hash"`
	BlockValue        string    `json:"block_value"`
	BuilderPubKey     string    `json:"builder_pub_key"`
	BuilderExtraData  string    `json:"builder_extra_data"`
	PaidBLXR          bool      `json:"paid_blxr"` // block paying to blxr
	ClientIP          string    `json:"client_ip"`
	NodeID            string    `json:"node_id"`
	AccountID         string    `json:"account_id"`
	Method            string    `json:"method"`
	ProcessLatency    int64     `json:"process_latency"`
	Diff              int64     `json:"diff"`
	HandleLatency     int64     `json:"handle_latency"`
	PayloadSize       int64     `json:"payload_size"`
}

type GetHeaderStatsRecord struct {
	RequestReceivedAt         time.Time     `json:"request_received_at"`
	FetchGetHeaderStartTime   string        `json:"fetch_get_header_start_time"`
	FetchGetHeaderDurationMS  int64         `json:"fetch_get_header_duration_ms"`
	Duration                  time.Duration `json:"duration"`
	MsIntoSlot                int64         `json:"ms_into_slot"`
	HeaderMsIntoSlotWithDelay int64         `json:"header_ms_into_slot_with_delay"`
	ParentHash                string        `json:"parent_hash"`
	PubKey                    string        `json:"pub_key"`
	BlockHash                 string        `json:"block_hash"`
	ReqID                     string        `json:"req_id"`
	ClientIP                  string        `json:"client_ip"`
	BlockValue                string        `json:"block_value"`
	Succeeded                 bool          `json:"succeeded"`
	NodeID                    string        `json:"node_id"`
	Slot                      int64         `json:"slot"`
	AccountID                 string        `json:"account_id"`
	ValidatorID               string        `json:"validator_id"`
	Latency                   int64         `json:"latency"`
	UserAgent                 string        `json:"user_agent"`
}

type ExternalRelayStats struct {
	Slot             int64     `json:"slot"`
	ParentHash       string    `json:"parent_hash"`
	PubKey           string    `json:"pub_key"`
	BlockHash        string    `json:"block_hash"`
	BlockValue       string    `json:"block_value"`
	Succeeded        bool      `json:"succeeded"`
	NodeID           string    `json:"node_id"`
	ReqStartTime     time.Time `json:"req_start_time"`
	ResReceivedAt    time.Time `json:"res_received_at"`
	ReqDurationInMS  int64     `json:"req_duration_in_ms"`
	Err              string    `json:"Err"`
	BuilderPubKey    string    `json:"builder_pub_key"`
	BuilderExtraData string    `json:"builder_extra_data"`
	AccountID        string    `json:"account_id"`
	URL              string    `json:"url"`
}

type GetPayloadStatsRecord struct {
	RequestReceivedAt time.Time     `json:"request_received_at"`
	Duration          time.Duration `json:"duration"`
	SlotStartTime     time.Time     `json:"slot_start_time"`
	MsIntoSlot        int64         `json:"ms_into_slot"`
	Slot              uint64        `json:"slot"`
	ParentHash        string        `json:"parent_hash"`
	PubKey            string        `json:"pub_key"`
	BlockHash         string        `json:"block_hash"`
	BlockValue        string        `json:"block_value"`
	ReqID             string        `json:"req_id"`
	ClientIP          string        `json:"client_ip"`
	Succeeded         bool          `json:"succeeded"`
	NodeID            string        `json:"node_id"`
	AccountID         string        `json:"account_id"`
	ValidatorID       string        `json:"validator_id"`
	Latency           int64         `json:"latency"`
	UserAgent         string        `json:"user_agent"`
}

type SlotStatsRecord struct {
	// header fields
	HeaderReqID               string        `json:"header_req_id"`
	HeaderReqReceivedAt       time.Time     `json:"header_req_received_at"`
	HeaderReqDuration         time.Duration `json:"header_req_duration"` // complete duration from the time req received including sleep
	HeaderReqDurationInMs     int64         `json:"header_req_duration_in_ms"`
	HeaderMsIntoSlot          int64         `json:"header_ms_into_slot"`            // time when request received at without sleep in ms
	HeaderMsIntoSlotWithDelay int64         `json:"header_ms_into_slot_with_delay"` // time from request received at including sleep in ms
	HeaderDelayInMs           int64         `json:"header_delay_in_ms"`
	HeaderMaxDelayInMs        int64         `json:"header_max_delay_in_ms"`
	HeaderSucceeded           bool          `json:"header_succeeded"`
	HeaderDeliveredBlockHash  string        `json:"header_delivered_block_hash"`
	HeaderBlockValue          string        `json:"header_block_value"`
	HeaderUserAgent           string        `json:"header_user_agent"`

	// payload fields
	PayloadReqID              string        `json:"payload_req_id"`
	PayloadReqReceivedAt      time.Time     `json:"payload_req_received_at"`
	PayloadReqDuration        time.Duration `json:"payload_req_duration"`
	PayloadReqDurationInMs    int64         `json:"payload_req_duration_in_ms"`
	PayloadMsIntoSlot         int64         `json:"payload_ms_into_slot"`
	PayloadSucceeded          bool          `json:"payload_succeeded"`
	PayloadDeliveredBlockHash string        `json:"payload_delivered_block_hash"`
	PayloadBlockValue         string        `json:"payload_block_value"`
	PayloadUserAgent          string        `json:"payload_user_agent"`

	// slot info
	Slot          uint64    `json:"slot"`
	ParentHash    string    `json:"parent_hash"`
	PubKey        string    `json:"pub_key"`
	SlotStartTime time.Time `json:"slot_start_time"`

	// node
	ClientIP string `json:"client_ip"`
	NodeID   string `json:"node_id"`

	// vg fields
	AccountID         string `json:"account_id"`
	ValidatorID       string `json:"validator_id"`
	GetHeaderLatency  int64  `json:"get_header_latency"`
	GetPayloadLatency int64  `json:"get_payload_latency"`
}
