package fastjson

import "math/big"

const (
	bytes8Length   = 8
	bytes20Length  = 20
	bytes32Length  = 32
	bytes48Length  = 48
	bytes96Length  = 96
	bytes256Length = 256

	hexPrefixString     = "0x"
	hexPrefixByteLength = 2

	kzgCommitmentJSONBytesLength = 98

	// SignedBlindedBeaconBlock JSON fields
	jsonMessage   = "message"
	jsonSignature = "signature"

	// BlindedBeaconBlock JSON fields
	jsonSlot          = "slot"
	jsonProposerIndex = "proposer_index"
	jsonParentRoot    = "parent_root"
	jsonStateRoot     = "state_root"
	jsonBody          = "body"

	// BlindedBeaconBlockBody JSON fields
	jsonRandaoReveal           = "randao_reveal"
	jsonETH1Data               = "eth1_data"
	jsonGraffiti               = "graffiti"
	jsonProposerSlashings      = "proposer_slashings"
	jsonAttesterSlashings      = "attester_slashings"
	jsonAttestations           = "attestations"
	jsonDeposits               = "deposits"
	jsonVoluntaryExits         = "voluntary_exits"
	jsonSyncAggregate          = "sync_aggregate"
	jsonExecutionPayloadHeader = "execution_payload_header"
	jsonBLSToExecutionChanges  = "bls_to_execution_changes"

	// Deneb BlindedBeaconBlockBody JSON fields
	jsonBlobKZGCommitments = "blob_kzg_commitments"

	// ETH1DATA JSON fields
	jsonDepositRoot  = "deposit_root"
	jsonDepositCount = "deposit_count"
	jsonBlockHash    = "block_hash"

	// SyncAggregate JSON fields
	jsonSyncCommitteeBits      = "sync_committee_bits"
	jsonSyncCommitteeSignature = "sync_committee_signature"

	// ExecutionPayloadHeader JSON fields
	jsonParentHash       = "parent_hash"
	jsonFeeRecipient     = "fee_recipient"
	jsonReceiptsRoot     = "receipts_root"
	jsonLogsBloom        = "logs_bloom"
	jsonPrevRandao       = "prev_randao"
	jsonBlockNumber      = "block_number"
	jsonGasLimit         = "gas_limit"
	jsonGasUsed          = "gas_used"
	jsonTimestamp        = "timestamp"
	jsonExtraData        = "extra_data"
	jsonBaseFeePerGas    = "base_fee_per_gas"
	jsonTransactionsRoot = "transactions_root"
	jsonWithdrawalsRoot  = "withdrawals_root"

	// Deneb ExecutionPayloadHeader JSON fields
	jsonBlobGasUsed   = "blob_gas_used"
	jsonExcessBlobGas = "excess_blob_gas"

	// BLSToExecutionChange JSON fields
	jsonValidatorIndex     = "validator_index"
	jsonFromBLSPubkey      = "from_bls_pubkey"
	jsonToExecutionAddress = "to_execution_address"

	// VoluntaryExit JSON fields
	jsonEpoch = "epoch"

	// Deposit JSON fields
	jsonProof = "proof"
	jsonData  = "data"

	// DepositData JSON fields
	jsonPublicKey             = "pubkey"
	jsonWithdrawalCredentials = "withdrawal_credentials"
	jsonAmount                = "amount"

	// Attestation JSON fields
	jsonAggregationBits = "aggregation_bits"
	jsonCommitteeBits   = "committee_bits"

	// AttestationData JSON fields
	jsonIndex           = "index"
	jsonBeaconBlockRoot = "beacon_block_root"
	jsonSource          = "source"
	jsonTarget          = "target"

	// Checkpoint JSON fields
	jsonRoot = "root"

	// AttesterSlashing JSON fields
	jsonAttestation1 = "attestation_1"
	jsonAttestation2 = "attestation_2"

	// IndexedAttestation JSON fields
	jsonAttestingIndices = "attesting_indices"

	// ProposerSlashing JSON fields
	jsonSignedHeader1 = "signed_header_1"
	jsonSignedHeader2 = "signed_header_2"

	// BeaconBlockHeader JSON fields
	jsonBodyRoot = "body_root"

	// Electra ExecutionRequests JSON fields
	jsonExecutionRequests     = "execution_requests"
	jsonDepositRequests       = "deposits"
	jsonWithdrawalRequests    = "withdrawals"
	jsonConsolidationRequests = "consolidations"

	// DepositRequest JSON fields
	// jsonPublicKey = "pubkey"
	// jsonWithdrawalCredentials = "withdrawal_credentials"
	// jsonAmount    = "amount"
	// jsonSignature = "signature"
	// jsonIndex     = "index"

	// WithdrawalRequest JSON fields
	jsonSourceAddress   = "source_address"
	jsonValidatorPubkey = "validator_pubkey"
	// jsonAmount          = "amount"

	// ConsolidationRequest JSON fields
	// jsonSourceAddress = "source_address"
	jsonSourcePubkey = "source_pubkey"
	jsonTargetPubkey = "target_pubkey"
)

var (
	hexPrefixBytes = []byte("0x")

	maxBaseFeePerGas = new(big.Int).SetBytes([]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	})
)
