package common

import (
	"encoding/json"
	"fmt"

	builderApiFulu "github.com/attestantio/go-builder-client/api/fulu"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	relayGRPC "github.com/bloXroute-Labs/relay-grpc"
	"github.com/bloXroute-Labs/relay-grpc/bidadjustment"
	ssz "github.com/ferranbt/fastssz"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
)

// Extended models - full structures with standard fields + NewItems used for blobs hydration
type FuluHydrationBlobItem struct {
	Proof      []deneb.KZGProof    `json:"proof" ssz-max:"128" ssz-size:"?,48"` // In fact we get fixed count 128 per blob (CELLS_PER_EXT_BLOB)
	Commitment deneb.KZGCommitment `json:"commitment" ssz-size:"48"`
	Blob       deneb.Blob          `json:"blob" ssz-size:"131072"`
}

type FuluExtendedBlobsBundle struct {
	Commitments []deneb.KZGCommitment    `json:"commitments" ssz-max:"4096" ssz-size:"?,48"`
	Proofs      []deneb.KZGProof         `json:"proofs" ssz-max:"33554432" ssz-size:"?,48"`
	Blobs       []deneb.Blob             `json:"blobs" ssz-max:"4096" ssz-size:"?,131072"`
	NewItems    []*FuluHydrationBlobItem `json:"new_items" ssz-max:"4096" ssz-size:"?,137268"` // see fuluHydrationItemMaxSize
}

type FuluExtendedSubmitBlockRequest struct {
	Message           *apiv1.BidTrace               `json:"message"`
	ExecutionPayload  *deneb.ExecutionPayload       `json:"execution_payload"`
	BlobsBundle       *FuluExtendedBlobsBundle      `json:"blobs_bundle"`
	ExecutionRequests *electra.ExecutionRequests    `json:"execution_requests"`
	Signature         phase0.BLSSignature           `json:"signature" ssz-size:"96"`
	TxRoot            *[32]byte                     `json:"tx_root,omitempty"` // Optional: encoded with 1-byte selector (0=None/1 byte, 1=Some/33 bytes). This is ported from Rust hydration impl.
	AdjustmentData    *bidadjustment.AdjustmentData `json:"adjustment_data,omitempty"`
}

// Transactions root computation is not used yet as Titan is not sending tx_root for hydrated submissions.
const (
	maxTransactionsPerPayload = 1048576    // 2^20
	maxBytesPerTransaction    = 1073741824 // 2^30
)

func (r *FuluExtendedSubmitBlockRequest) ComputeTransactionsRoot() ([32]byte, error) {
	txs := r.ExecutionPayload.Transactions

	// Get hasher for the transaction list
	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)

	subIndx := hh.Index()

	// Compute tree hash root for EACH transaction and append
	for _, tx := range txs {
		// Each transaction is a List<u8> - compute its SSZ tree hash root
		txRoot, err := computeTransactionRoot(tx)
		if err != nil {
			return [32]byte{}, fmt.Errorf("failed to hash transaction: %w", err)
		}
		hh.Append(txRoot[:])
	}

	// Merkleize the list of transaction roots with list length
	hh.MerkleizeWithMixin(subIndx, uint64(len(txs)), maxTransactionsPerPayload)

	return hh.HashRoot()
}

// computeTransactionRoot computes SSZ tree hash for a single transaction (List<u8>)
func computeTransactionRoot(tx []byte) ([32]byte, error) {
	// Get a separate hasher for this transaction
	txHasher := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(txHasher)

	// Record index, chunk bytes into 32-byte pieces, then merkleize with length mixin
	indx := txHasher.Index()
	txHasher.AppendBytes32(tx) // Chunk into 32-byte pieces
	txHasher.MerkleizeWithMixin(indx, uint64(len(tx)), maxBytesPerTransaction)

	return txHasher.HashRoot()
}

type VersionedExtendedSubmitBlockRequest struct {
	Version consensusspec.DataVersion       `json:"version"`
	Fulu    *FuluExtendedSubmitBlockRequest `json:"fulu,omitempty"`
}

func (e *VersionedExtendedSubmitBlockRequest) GetAdjustmentData() (*bidadjustment.AdjustmentData, error) {
	switch e.Version {
	case consensusspec.DataVersionFulu:
		if e.Fulu != nil {
			return e.Fulu.AdjustmentData, nil
		}
		return nil, fmt.Errorf("fulu request is nil")
	default:
		return nil, fmt.Errorf("unsupported version %d for getting adjustment data", e.Version)
	}
}

func (r *VersionedExtendedSubmitBlockRequest) UnmarshalJSON(input []byte) error {
	if IsFulu {
		r.Version = consensusspec.DataVersionFulu

		fuluRequest := new(FuluExtendedSubmitBlockRequest)
		if err := json.Unmarshal(input, fuluRequest); err != nil {
			return errors.Wrap(err, "failed to unmarshal extended SubmitBlockRequest")
		}
		r.Fulu = fuluRequest
		return nil
	}
	return fmt.Errorf("only fulu version is supported for extended SubmitBlockRequest")
}

// ConvertToBuilderSpec converts ExtendedVersionedSubmitBlockRequest to builderSpec.VersionedSubmitBlockRequest
// NewItems data is lost in this conversion, AdjustmentData is returned separately
func (e *VersionedExtendedSubmitBlockRequest) ConvertToSpec() (*builderSpec.VersionedSubmitBlockRequest, error) {
	result := &builderSpec.VersionedSubmitBlockRequest{
		Version: e.Version,
	}

	switch e.Version {
	case consensusspec.DataVersionFulu:
		if e.Fulu != nil {
			result.Fulu = &builderApiFulu.SubmitBlockRequest{
				Message:           e.Fulu.Message,
				ExecutionPayload:  e.Fulu.ExecutionPayload,
				ExecutionRequests: e.Fulu.ExecutionRequests,
				Signature:         e.Fulu.Signature,
			}
			if e.Fulu.BlobsBundle != nil {
				result.Fulu.BlobsBundle = &builderApiFulu.BlobsBundle{
					Commitments: e.Fulu.BlobsBundle.Commitments,
					Proofs:      e.Fulu.BlobsBundle.Proofs,
					Blobs:       e.Fulu.BlobsBundle.Blobs,
				}
			}
			return result, nil
		}
		return nil, fmt.Errorf("fulu request is nil")
	default:
		return nil, fmt.Errorf("unsupported version %d for conversion to builder spec", e.Version)
	}
}

// ProtoRequestToVersionedExtendedRequest converts a gRPC SubmitBlockRequest to VersionedExtendedSubmitBlockRequest
// Only supports Fulu version. Handles NewItems for blob hydration and AdjustmentData.
func ProtoRequestToVersionedExtendedRequest(block *relayGRPC.SubmitBlockRequest) (*VersionedExtendedSubmitBlockRequest, error) {
	transactions := make([]bellatrix.Transaction, len(block.ExecutionPayload.Transactions))
	for index, tx := range block.ExecutionPayload.Transactions {
		transactions[index] = tx.RawData
	}

	// Withdrawal is defined in capella spec
	// https://github.com/attestantio/go-eth2-client/blob/21f7dd480fed933d8e0b1c88cee67da721c80eb2/spec/deneb/executionpayload.go#L42
	withdrawals := make([]*capella.Withdrawal, len(block.ExecutionPayload.Withdrawals))
	for index, withdrawal := range block.ExecutionPayload.Withdrawals {
		withdrawals[index] = &capella.Withdrawal{
			ValidatorIndex: phase0.ValidatorIndex(withdrawal.ValidatorIndex),
			Index:          capella.WithdrawalIndex(withdrawal.Index),
			Amount:         phase0.Gwei(withdrawal.Amount),
			Address:        b20(withdrawal.Address),
		}
	}

	// BlobsBundle
	extendedBlobsBundle := &FuluExtendedBlobsBundle{
		Commitments: make([]deneb.KZGCommitment, len(block.BlobsBundle.Commitments)),
		Proofs:      make([]deneb.KZGProof, len(block.BlobsBundle.Proofs)),
		Blobs:       make([]deneb.Blob, len(block.BlobsBundle.Blobs)),
	}
	for index, commitment := range block.BlobsBundle.Commitments {
		copy(extendedBlobsBundle.Commitments[index][:], commitment)
	}

	for index, proof := range block.BlobsBundle.Proofs {
		copy(extendedBlobsBundle.Proofs[index][:], proof)
	}

	for index, blob := range block.BlobsBundle.Blobs {
		copy(extendedBlobsBundle.Blobs[index][:], blob)
	}

	// Convert NewItems if present
	if len(block.BlobsBundle.NewItems) > 0 {
		extendedBlobsBundle.NewItems = make([]*FuluHydrationBlobItem, len(block.BlobsBundle.NewItems))
		for index, item := range block.BlobsBundle.NewItems {
			// Convert commitment
			var commitment deneb.KZGCommitment
			copy(commitment[:], item.Commitment)

			// Convert proofs array
			proofs := make([]deneb.KZGProof, len(item.Proofs))
			for j, proofBytes := range item.Proofs {
				copy(proofs[j][:], proofBytes)
			}

			// Convert blob
			var blob deneb.Blob
			copy(blob[:], item.Blob)

			extendedBlobsBundle.NewItems[index] = &FuluHydrationBlobItem{
				Proof:      proofs,
				Commitment: commitment,
				Blob:       blob,
			}
		}
	}

	value, err := uint256.FromHex(block.BidTrace.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to convert fulu block value %s to uint256: %s", block.BidTrace.Value, err.Error())
	}

	// Unmarshal AdjustmentData if present
	var adjustmentData *bidadjustment.AdjustmentData
	if len(block.AdjustmentData) > 0 {
		adjustmentData = new(bidadjustment.AdjustmentData)
		if err := adjustmentData.UnmarshalSSZ(block.AdjustmentData); err != nil {
			// TODO: log error?
			return nil, fmt.Errorf("failed to unmarshal adjustment data: %w", err)
		}
	}

	return &VersionedExtendedSubmitBlockRequest{
		Version: consensusspec.DataVersionFulu,
		Fulu: &FuluExtendedSubmitBlockRequest{
			Message: &apiv1.BidTrace{
				Slot:                 block.BidTrace.Slot,
				ParentHash:           b32(block.BidTrace.ParentHash),
				BlockHash:            b32(block.BidTrace.BlockHash),
				BuilderPubkey:        b48(block.BidTrace.BuilderPubkey),
				ProposerPubkey:       b48(block.BidTrace.ProposerPubkey),
				ProposerFeeRecipient: b20(block.BidTrace.ProposerFeeRecipient),
				GasLimit:             block.BidTrace.GasLimit,
				GasUsed:              block.BidTrace.GasUsed,
				Value:                value,
			},
			ExecutionPayload: &deneb.ExecutionPayload{
				ParentHash:    b32(block.ExecutionPayload.ParentHash),
				StateRoot:     b32(block.ExecutionPayload.StateRoot),
				ReceiptsRoot:  b32(block.ExecutionPayload.ReceiptsRoot),
				LogsBloom:     b256(block.ExecutionPayload.LogsBloom),
				PrevRandao:    b32(block.ExecutionPayload.PrevRandao),
				BaseFeePerGas: byteSliceToUint256Int(block.ExecutionPayload.BaseFeePerGas),
				FeeRecipient:  b20(block.ExecutionPayload.FeeRecipient),
				BlockHash:     b32(block.ExecutionPayload.BlockHash),
				ExtraData:     block.ExecutionPayload.ExtraData,
				BlockNumber:   block.ExecutionPayload.BlockNumber,
				GasLimit:      block.ExecutionPayload.GasLimit,
				Timestamp:     block.ExecutionPayload.Timestamp,
				GasUsed:       block.ExecutionPayload.GasUsed,
				Transactions:  transactions,
				Withdrawals:   withdrawals,
				BlobGasUsed:   block.ExecutionPayload.BlobGasUsed,
				ExcessBlobGas: block.ExecutionPayload.ExcessBlobGas,
			},
			BlobsBundle:       extendedBlobsBundle,
			ExecutionRequests: convertProtoToFuluExecutionRequest(block.ExecutionRequests),
			Signature:         b96(block.Signature),
			TxRoot:            nil, // TxRoot not present in gRPC proto
			AdjustmentData:    adjustmentData,
		},
	}, nil
}

// Helper functions for byte array conversions
func b20(b []byte) [20]byte {
	var out [20]byte
	copy(out[:], b)
	return out
}

func b32(b []byte) [32]byte {
	var out [32]byte
	copy(out[:], b)
	return out
}

func b48(b []byte) [48]byte {
	var out [48]byte
	copy(out[:], b)
	return out
}

func b96(b []byte) [96]byte {
	var out [96]byte
	copy(out[:], b)
	return out
}

func b256(b []byte) [256]byte {
	var out [256]byte
	copy(out[:], b)
	return out
}

func byteSliceToUint256Int(b []byte) *uint256.Int {
	return new(uint256.Int).SetBytes(b)
}

func convertProtoToFuluExecutionRequest(protoExecutionRequests *relayGRPC.ExecutionRequests) *electra.ExecutionRequests {
	executionRequests := &electra.ExecutionRequests{
		Deposits:       make([]*electra.DepositRequest, len(protoExecutionRequests.Deposits)),
		Withdrawals:    make([]*electra.WithdrawalRequest, len(protoExecutionRequests.Withdrawals)),
		Consolidations: make([]*electra.ConsolidationRequest, len(protoExecutionRequests.Consolidations)),
	}

	for i, deposit := range protoExecutionRequests.Deposits {
		executionRequests.Deposits[i] = &electra.DepositRequest{
			Pubkey:                b48(deposit.Pubkey),
			WithdrawalCredentials: deposit.WithdrawalCredentials,
			Amount:                phase0.Gwei(deposit.Amount),
			Signature:             b96(deposit.Signature),
			Index:                 deposit.Index,
		}
	}

	for i, withdrawalRequest := range protoExecutionRequests.Withdrawals {
		executionRequests.Withdrawals[i] = &electra.WithdrawalRequest{
			SourceAddress:   b20(withdrawalRequest.SourceAddress),
			ValidatorPubkey: b48(withdrawalRequest.ValidatorPubkey),
			Amount:          phase0.Gwei(withdrawalRequest.Amount),
		}
	}

	for i, consolidation := range protoExecutionRequests.Consolidations {
		executionRequests.Consolidations[i] = &electra.ConsolidationRequest{
			SourceAddress: b20(consolidation.SourceAddress),
			SourcePubkey:  b48(consolidation.SourcePubkey),
			TargetPubkey:  b48(consolidation.TargetPubkey),
		}
	}
	return executionRequests
}
