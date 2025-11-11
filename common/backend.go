package common

const (
	// Proxy
	PathIndex                     = "/"
	PathDelaySettings             = "/relay_proxy/v1/delay_settings"
	PathGetAccounts               = "/relay_proxy/v1/accounts"
	PathGetFlows                  = "/relay_proxy/v1/flows"
	PathGetFlowBySlot             = "/relay_proxy/v1/flow_by_Slot"
	PathGetFlowBySlotAndBlockHash = "/relay_proxy/v1/flow_by_Slot_and_block"

	// Relay
	PathStatus            = "/eth/v1/builder/status"
	PathRegisterValidator = "/eth/v1/builder/validators"
	PathGetHeaderPrefix   = "/eth/v1/builder/header"
	PathGetHeader         = "/eth/v1/builder/header/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	PathGetPayload        = "/eth/v1/builder/blinded_blocks"
	PathGetPayloadV2      = "/eth/v2/builder/blinded_blocks"
	PathNode              = "/blxr/node"
	PathPrefetchBlock     = "/blxr/prefetch_block"

	// Builder
	PathGetPayloadV3 = "/get_payload_v3"
)
