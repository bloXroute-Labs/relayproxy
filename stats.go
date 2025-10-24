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
	StatsRelayProxyPerformanceStats       = "builder-relay.stats.performance"

	TypeRelayProxyGetHeader              = "relay_proxy_provided_header"
	TypeRelayProxyGetPayload             = "relay_proxy_provided_payload"
	TypeRelayProxySlotStats              = "relay_proxy_slot_stats"
	TypeRelayProxySlotWon                = "relay_proxy_slot_won"
	TypeRelayProxyHeaderStreamReceived   = "relay_proxy_header_stream_received"
	TypeRelayProxyGetHeaderExternalRelay = "relay_proxy_external_relay_header"
	TypeRelayProxyBlockStreamReceived    = "relay_proxy_block_stream_received"
	TypeRelayProxyPerformanceStats       = "builder-relay.performance_stats"
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
	SlotUID                   string        `json:"slot_uid"`
	HeaderStartTimeUnixMs     string        `json:"header_start_time_unix_ms"`
}

type headerProvidedToValidatorIP struct {
	IPMatches                bool   `json:"ip_matches"`
	Slot                     string `json:"slot"`
	ProposerPublicKey        string `json:"proposer_public_key"`
	Value                    string `json:"value"`
	BlockHash                string `json:"block_hash"`
	BidPubkey                string `json:"bid_pubkey"`
	BuilderPubkey            string `json:"builder_pubkey"`
	ExtraData                string `json:"extra_data"`
	FeeRecipient             string `json:"fee_recipient"`
	Type                     string `json:"type"`
	MSIntoSlot               int64  `json:"ms_into_slot"`
	GetHeaderRequestSendTime int64  `json:"get_header_request_send_time"`
	UserAgent                string `json:"user_agent"`
	UsingRelayProxy          bool   `json:"using_relay_proxy"`
	ClientIPAddress          string `json:"client_ip_address"`
	RequestID                string `json:"request_id"`
	Region                   string `json:"region"`
	SleepAmount              int64  `json:"sleep_amount"`
	CutoffReached            bool   `json:"cutoff_reached"`
	SleepType                string `json:"sleep_type"`
	MaxSleepIntoSlot         int64  `json:"max_sleep_into_slot"`
	ISP                      string `json:"isp"`
	IPOrganization           string `json:"ip_organization"`
	Country                  string `json:"country"`
	State                    string `json:"state"`
	DataSource               string `json:"data_source"`
	Duration                 int64  `json:"duration"`
	OriginalValue            string `json:"original_value"`
	OriginalBlockHash        string `json:"original_block_hash"`
	BidAdjustmentDuration    int64  `json:"bid_adjustment_duration"`
	UsedAdjustment           bool   `json:"used_adjustment"`
	AdjustmentDataExist      bool   `json:"adjustment_data_exist"`
	AdjustmentDataSuccess    bool   `json:"adjustment_data_success"`
	AdjustmentError          string `json:"adjustment_error"`

	SecondPlaceBuilderValue         string `json:"second_place_builder_value"`
	SecondPlaceBuilderBlockHash     string `json:"second_place_builder_block_hash"`
	SecondPlaceBuilderBuilderPubkey string `json:"second_place_builder_builder_pubkey"`
	SecondPlaceBuilderExtraData     string `json:"second_place_builder_extra_data"`
	SecondPlaceBuilderFeeRecipient  string `json:"second_place_builder_fee_recipient"`
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
	SlotUID           string        `json:"slot_uid"`
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
	HeaderStartTimeUnixMs     string        `json:"header_start_time_unix_ms"`
	HeaderSlotUID             string        `json:"header_slot_uid"`

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
	PayloadSlotUID            string        `json:"payload_slot_uid"`

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

type HeaderMemoryMetricsRecord struct {
	Method     string    `json:"method"`
	Duration   time.Time `json:"durationMs"`
	Alloc      uint64    `json:"alloc"`
	MAlloc     uint64    `json:"malloc"`
	HeapInuse  uint64    `json:"heap_inuse"`
	NumGC      uint32    `json:"num_gc"`
	CpuPercent float64   `json:"cpu_percent"`
	Slot       string    `json:"slot"`
	ClientIP   string    `json:"client_ip"`
	PublicKey  string    `json:"public_key"`
	Success    bool      `json:"success"`
	AccountID  string    `json:"account_id"`
}

type GetPayloadMetrics struct {
	Method      string    `json:"method"`
	ClientIP    string    `json:"client_ip"`
	RequestIP   string    `json:"request_ip"`
	Duration    time.Time `json:"duration"`
	Size        int64     `json:"size"`
	UserAgent   string    `json:"user_agent"`
	Alloc       uint64    `json:"alloc"`
	Malloc      uint64    `json:"malloc"`
	HeapIdle    uint64    `json:"heap_idle"`
	HeapInuse   uint64    `json:"heap_inuse"`
	NumGC       uint32    `json:"num_gc"`
	CpuPercent  float64   `json:"cpu_percent"`
	ValidatorID string    `json:"validator_id"`
	AccountID   string    `json:"account_id"`
	URL         string    `json:"url"`
}
