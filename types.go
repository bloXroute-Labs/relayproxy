package relayproxy

import "time"

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
}

type DelayGetHeaderParams struct {
	ReceivedAt          time.Time
	Slot                string
	AccountID           string
	Cluster             string
	UserAgent           string
	ClientIP            string
	SlotWithParentHash  string
	BoostSendTimeUnixMS string
	Latency             int64
}
