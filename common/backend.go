package common

const (
	//Proxy
	PathIndex         = "/"
	PathDelaySettings = "/relay_proxy/v1/delay_settings"
	PathGetAccounts   = "/relay_proxy/v1/accounts"

	//Relay
	PathStatus            = "/eth/v1/builder/status"
	PathRegisterValidator = "/eth/v1/builder/validators"
	PathGetHeaderPrefix   = "/eth/v1/builder/header"
	PathGetHeader         = "/eth/v1/builder/header/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	PathGetPayload        = "/eth/v1/builder/blinded_blocks"
	PathNode              = "/blxr/node"
	PathPrefetchBlock     = "/blxr/prefetch_block"
)
