package common

import (
	"crypto/rand"
	"math/big"
	"time"

	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiElectra "github.com/attestantio/go-builder-client/api/electra"
	builderapiv1 "github.com/attestantio/go-builder-client/api/v1"
	v1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	denebspec "github.com/attestantio/go-eth2-client/spec/deneb"
	electraspec "github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

const (
	sha256HashByteLength = 32
	publicKeyByteLength  = 48
)

func GenerateBytes(count int) []byte {
	b := make([]byte, count)
	_, _ = rand.Read(b)
	return b
}

func GenerateRandomEthHash() common.Hash {
	return common.BytesToHash(GenerateBytes(sha256HashByteLength))
}

// GenerateRandomPublicKey returns a random 48-byte public key
func GenerateRandomPublicKey() phase0.BLSPubKey {
	return phase0.BLSPubKey(GenerateBytes(publicKeyByteLength))
}

func NewDenebBuilderSubmitBlockRequest(builderPubKey phase0.BLSPubKey, blockHash common.Hash, bidValue *big.Int, receiveTime time.Time) *builderApiDeneb.SubmitBlockRequest {
	bidBlockHash := phase0.Hash32(blockHash.Bytes())
	value := new(uint256.Int)
	value.SetFromBig(bidValue)

	return &builderApiDeneb.SubmitBlockRequest{
		Signature: phase0.BLSSignature{},
		Message: &v1.BidTrace{
			Slot:                 0,
			ParentHash:           phase0.Hash32{},
			BlockHash:            bidBlockHash,
			BuilderPubkey:        builderPubKey,
			ProposerPubkey:       phase0.BLSPubKey{},
			ProposerFeeRecipient: bellatrix.ExecutionAddress{},
			GasLimit:             0,
			GasUsed:              0,
			Value:                value,
		},
		ExecutionPayload: &denebspec.ExecutionPayload{
			ParentHash:    phase0.Hash32{1},
			FeeRecipient:  bellatrix.ExecutionAddress{2},
			StateRoot:     [32]byte{3},
			ReceiptsRoot:  [32]byte{4},
			LogsBloom:     [256]byte{5},
			PrevRandao:    [32]byte{6},
			BlockNumber:   7,
			GasLimit:      8,
			GasUsed:       9,
			Timestamp:     1,
			ExtraData:     nil,
			BaseFeePerGas: uint256.NewInt(10),
			BlockHash:     (phase0.Hash32)(blockHash),
			Transactions:  nil,
			Withdrawals:   []*capella.Withdrawal{},
		},
		BlobsBundle: &builderApiDeneb.BlobsBundle{},
	}
}

func NewElectraBuilderSubmitBlockRequest(slot uint64, proposerPubKey, builderPubKey phase0.BLSPubKey, parentHash, blockHash common.Hash, bidValue *big.Int, feeRecipient bellatrix.ExecutionAddress, extraData []byte) *builderApiElectra.SubmitBlockRequest {
	bidBlockHash := phase0.Hash32(blockHash.Bytes())
	value := new(uint256.Int)
	value.SetFromBig(bidValue)
	credentials := [32]byte{8}
	return &builderApiElectra.SubmitBlockRequest{
		Signature: phase0.BLSSignature{},
		Message: &builderapiv1.BidTrace{
			Slot:                 slot,
			ParentHash:           phase0.Hash32(parentHash),
			BlockHash:            bidBlockHash,
			BuilderPubkey:        builderPubKey,
			ProposerPubkey:       proposerPubKey,
			ProposerFeeRecipient: feeRecipient,
			GasLimit:             0,
			GasUsed:              0,
			Value:                value,
		},
		ExecutionPayload: &denebspec.ExecutionPayload{
			ParentHash:    phase0.Hash32(parentHash),
			FeeRecipient:  feeRecipient,
			StateRoot:     [32]byte{3},
			ReceiptsRoot:  [32]byte{4},
			LogsBloom:     [256]byte{5},
			PrevRandao:    [32]byte{6},
			BlockNumber:   7,
			GasLimit:      8,
			GasUsed:       9,
			Timestamp:     12 * 1,
			ExtraData:     extraData,
			BaseFeePerGas: uint256.NewInt(11),
			BlockHash:     (phase0.Hash32)(blockHash),
			Transactions:  []bellatrix.Transaction{},
			Withdrawals:   []*capella.Withdrawal{},
			BlobGasUsed:   0,
		},
		BlobsBundle: &builderApiDeneb.BlobsBundle{
			Commitments: []denebspec.KZGCommitment{},
			Proofs:      []denebspec.KZGProof{},
			Blobs:       []denebspec.Blob{},
		},
		ExecutionRequests: &electraspec.ExecutionRequests{
			Deposits: []*electraspec.DepositRequest{
				{
					Pubkey:                phase0.BLSPubKey{},
					WithdrawalCredentials: credentials[:],
					Amount:                12,
					Signature:             phase0.BLSSignature{13},
					Index:                 14,
				},
			},
			Withdrawals: []*electraspec.WithdrawalRequest{
				{
					SourceAddress:   bellatrix.ExecutionAddress{15},
					ValidatorPubkey: phase0.BLSPubKey{16},
					Amount:          17,
				},
			},
			Consolidations: []*electraspec.ConsolidationRequest{
				{
					SourceAddress: bellatrix.ExecutionAddress{18},
					SourcePubkey:  phase0.BLSPubKey{19},
					TargetPubkey:  phase0.BLSPubKey{20},
				},
			},
		},
	}
}
