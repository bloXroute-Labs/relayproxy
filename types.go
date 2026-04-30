package relayproxy

import (
	"net/http"
	"time"
)

// RegistrationParams holds the input parameters for registering a validator.
type RegistrationParams struct {
	// The time when the registration request was received.
	ReceivedAt time.Time
	// The raw payload for registration.
	Payload []byte
	// Client IP address.
	ClientIP string
	// The authentication header.
	AuthHeader string
	// Validator identifier.
	ValidatorID string
	// Account identifier.
	AccountID string
	// Compliance list (if any).
	ComplianceList string
	// Whether MEV protection is enabled for the proposer.
	ProposerMevProtect bool
	// Whether to skip optimism checks.
	SkipOptimism bool
}

// HeaderRequestParams holds the input parameters for getting header information.
type HeaderRequestParams struct {
	// The actual HTTP request
	HttpRequest *http.Request
	// The time when the header request was received.
	ReceivedAt time.Time
	// The Unix timestamp (as string) when getHeader processing started.
	GetHeaderStartTimeUnixMS string
	// Request Latency
	Latency int64
	// Client IP address.
	ClientIP string
	// The slot identifier.
	Slot string
	// The parent block hash.
	ParentHash string
	// The public key of the validator.
	PubKey string
	// The authentication header.
	AuthHeader string
	// Validator identifier.
	ValidatorID string
	// Account identifier.
	AccountID string
	// The cluster identifier.
	Cluster string
	// User agent string.
	UserAgent string
	//Unique id provided by MEVBoost for each request
	SlotUID string
	// Header which communicates timeout set by client. Used to tweak block creation delay together with Date-Milliseconds.
	HeaderTimeoutMs uint64
}

// PayloadRequestParams holds the input parameters for getting payload data.
type PayloadRequestParams struct {
	// The time when the payload request was received.
	ReceivedAt time.Time
	// The raw payload.
	Payload []byte
	// Client IP address.
	ClientIP string
	// The authentication header.
	AuthHeader string
	// Validator identifier.
	ValidatorID string
	// Account identifier.
	AccountID string
	// The Unix timestamp (as string) when payload processing started.
	GetPayloadStartTimeUnixMS string
	// The cluster identifier.
	Cluster string
	// User agent string.
	UserAgent string
	//Unique id provided by MEVBoost for each request
	SlotUID string
}

type DelayGetHeaderParams struct {
	ReceivedAt                time.Time
	Slot                      string
	AccountID                 string
	Cluster                   string
	UserAgent                 string
	ClientIP                  string
	SlotWithParentHash        string
	BoostSendTimeUnixMS       string
	Latency                   int64
	HeaderTimeoutMS           uint64 // client timeout
	BidAdjustmentBufferTimeMs int64
}

type DelayGetHeaderResponse struct {
	Sleep, MaxSleep    int64
	SlotStartTime      time.Time
	Latency            int64
	ReplacementDelayMs int64
	DelayInfo          DelayInfo
}

type DelayInfo struct {
	IsSleepUpdated     bool
	SleepMsBefore      int64
	SleepMsAfter       int64
	SleptMsActual      int64
	OneWayMs           int64 // one way ping ms which rtt/2
	RequestInitiatedAt int64
	RequestTimeout     int64
	RequestDeadline    time.Time
	GetHeaderDeadline  time.Time // default getHeader window 2.9secs
	EffectiveDeadline  time.Time
	DefaultWakeupAt    time.Time
	UpdatedWakeupAt    time.Time
}
