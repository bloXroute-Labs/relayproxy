package common

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

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
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
)

// Extended models - full structures with standard fields + NewItems used for blobs hydration
type FuluHydrationBlobItem struct {
	Proof      []deneb.KZGProof    `ssz-max:"128" ssz-size:"?,48"`
	Commitment deneb.KZGCommitment `ssz-size:"48"`
	Blob       deneb.Blob          `ssz-size:"131072"`
}

// UnmarshalSSZ unmarshals FuluHydrationBlobItem from SSZ format
func (item *FuluHydrationBlobItem) UnmarshalSSZ(buf []byte) error {
	size := uint64(len(buf))
	if size < 131124 {
		return fmt.Errorf("buffer too small, expected at least 131124 bytes, got %d: %w", size, ssz.ErrSize)
	}

	tail := buf
	var o0 uint64

	// Offset (0) 'Proofs'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return fmt.Errorf("failed to unmarshal field 'Proofs': offset %d exceeds buffer size %d: %w", o0, size, ssz.ErrOffset)
	}
	if o0 != 131124 {
		return fmt.Errorf("failed to unmarshal field 'Proofs': invalid offset %d, expected 131124: %w", o0, ssz.ErrInvalidVariableOffset)
	}

	// Field (1) 'Commitment' - 48 bytes at [4:52]
	copy(item.Commitment[:], buf[4:52])

	// Field (2) 'Blob' - 131072 bytes at [52:131124]
	copy(item.Blob[:], buf[52:131124])

	// Field (0) 'Proofs' (variable) but in fact expected to be 128 always
	{
		seg := tail[o0:]
		num, err := ssz.DivideInt2(len(seg), 48, 128)
		if err != nil {
			return fmt.Errorf("failed to unmarshal field 'Proofs': invalid segment size %d: %w", len(seg), err)
		}
		item.Proof = make([]deneb.KZGProof, num)
		for i := 0; i < num; i++ {
			copy(item.Proof[i][:], seg[i*48:(i+1)*48])
		}
	}

	return nil
}

type FuluExtendedBlobsBundle struct {
	Commitments []deneb.KZGCommitment   `ssz-max:"4096" ssz-size:"?,48"`
	Proofs      []deneb.KZGProof        `ssz-max:"33554432" ssz-size:"?,48"`
	Blobs       []deneb.Blob            `ssz-max:"4096" ssz-size:"?,131072"`
	NewItems    []FuluHydrationBlobItem `ssz-max:"4096" ssz-size:"?,137268"`
}

type FuluExtendedSubmitBlockRequest struct {
	Message           *apiv1.BidTrace
	ExecutionPayload  *deneb.ExecutionPayload
	BlobsBundle       *FuluExtendedBlobsBundle
	ExecutionRequests *electra.ExecutionRequests
	Signature         phase0.BLSSignature `ssz-size:"96"`
	TxRoot            *[32]byte           // Optional: encoded with 1-byte selector (0=None/1 byte, 1=Some/33 bytes). This is ported from Rust hydration impl.
	AdjustmentData    *bidadjustment.AdjustmentData
}

type VersionedExtendedSubmitBlockRequest struct {
	Version consensusspec.DataVersion
	Fulu    *FuluExtendedSubmitBlockRequest
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
		extendedBlobsBundle.NewItems = make([]FuluHydrationBlobItem, len(block.BlobsBundle.NewItems))
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

			extendedBlobsBundle.NewItems[index] = FuluHydrationBlobItem{
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

// SSZ Unmarshaller impl for VersionedExtendedSubmitBlockRequest with caching and object pooling.
// It's capable of processing both standard and dehydrated formats for Fulu blobs bundle as well as optional AdjustmentData.
type BlockSubmissionSSZFastUnmarshaller struct {
	// Key: sha256(raw SSZ bytes of BlobsBundle) as binary string
	// Val: *apideneb.BlobsBundle (immutable, cached)
	blobCache *cache.Cache
	// Fulu blobs
	fuluBundlePool sync.Pool
}

func NewBlockSubmissionSSZFastUnmarshaller() *BlockSubmissionSSZFastUnmarshaller {
	return &BlockSubmissionSSZFastUnmarshaller{
		blobCache: cache.New(1*time.Minute, 1*time.Minute),
		fuluBundlePool: sync.Pool{
			New: func() any { return new(FuluExtendedBlobsBundle) },
		},
	}
}

func (u *BlockSubmissionSSZFastUnmarshaller) UnmarshalSSZ(input []byte, out *VersionedExtendedSubmitBlockRequest) error {
	if IsFulu {
		out.Version = consensusspec.DataVersionFulu
		fuluExtendedRequest := new(FuluExtendedSubmitBlockRequest)
		if err := u.unmarshalSSZFulu(fuluExtendedRequest, input); err != nil {
			return fmt.Errorf("failed to unmarshal Fulu extended submit block request: %w", err)
		}
		out.Fulu = fuluExtendedRequest
		return nil
	}
	return errors.New("only fulu version is supported for extended SubmitBlockRequest")
}

func (u *BlockSubmissionSSZFastUnmarshaller) unmarshalSSZFulu(r *FuluExtendedSubmitBlockRequest, buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 344 {
		return fmt.Errorf("buffer too small, expected at least 344 bytes, got %d: %w", size, ssz.ErrSize)
	}

	tail := buf
	var o1, o2, o3, o5 uint64

	// Field (0) 'Message'
	if r.Message == nil {
		r.Message = new(apiv1.BidTrace)
	}
	if err = r.Message.UnmarshalSSZ(buf[0:236]); err != nil {
		return fmt.Errorf("failed to unmarshal field 'Message' (BidTrace): %w", err)
	}

	// Offset (1) 'ExecutionPayload'
	if o1 = ssz.ReadOffset(buf[236:240]); o1 > size {
		return fmt.Errorf("failed to unmarshal field 'ExecutionPayload': offset %d exceeds buffer size %d: %w", o1, size, ssz.ErrOffset)
	}

	// Offset (2) 'BlobsBundle'
	if o2 = ssz.ReadOffset(buf[240:244]); o2 > size || o1 > o2 {
		return fmt.Errorf("failed to unmarshal field 'BlobsBundle': invalid offset %d (previous offset: %d, size: %d): %w", o2, o1, size, ssz.ErrOffset)
	}

	// Offset (3) 'ExecutionRequests'
	if o3 = ssz.ReadOffset(buf[244:248]); o3 > size || o2 > o3 {
		return fmt.Errorf("failed to unmarshal field 'ExecutionRequests': invalid offset %d (previous offset: %d, size: %d): %w", o3, o2, size, ssz.ErrOffset)
	}

	// Field (4) 'Signature' - always at [248:344]
	copy(r.Signature[:], buf[248:344])

	// Detect optional fields based on where ExecutionPayload offset points
	// o1 is the ExecutionPayload offset read from [236:240]
	// TxRoot in Rust is encoded as Option<B256> with 1-byte selector:
	//   - selector = 0: None (1 byte total)
	//   - selector = 1: Some (1 byte selector + 32 bytes data = 33 bytes total)
	//
	// Possible layouts after Signature (position 344):
	// 1. o1 == 344: No optional fields
	// 2. o1 == 345: Only TxRoot=None (1 byte selector)
	// 3. o1 == 348: Only AdjustmentData offset (legacy format, 4 bytes)
	// 4. o1 == 349: TxRoot=None + AdjustmentData (1 byte + 4 bytes offset)
	// 5. o1 == 377: Only TxRoot=Some (1 byte selector + 32 bytes)
	// 6. o1 == 381: TxRoot=Some + AdjustmentData (1 byte + 32 bytes + 4 bytes offset)

	var txRootPos uint64 = 344
	var txRootSize uint64 = 0 // 0 = not present, 1 = None, 33 = Some
	var adjustmentDataOffsetPos uint64 = 344
	hasAdjustmentDataOffset := false

	switch o1 {
	case 344:
		// No optional fields
		o5 = size
	case 345:
		// Only TxRoot=None (1 byte selector)
		txRootSize = 1
		o5 = size
	case 348:
		// Only AdjustmentData offset (legacy format)
		hasAdjustmentDataOffset = true
		adjustmentDataOffsetPos = 344
	case 349:
		// TxRoot=None (1 byte) + AdjustmentData offset (4 bytes)
		txRootSize = 1
		hasAdjustmentDataOffset = true
		adjustmentDataOffsetPos = 345
	case 377:
		// Only TxRoot=Some (1 byte selector + 32 bytes data)
		txRootSize = 33
		o5 = size
	case 381:
		// TxRoot=Some (33 bytes) + AdjustmentData offset (4 bytes)
		txRootSize = 33
		hasAdjustmentDataOffset = true
		adjustmentDataOffsetPos = 377
	default:
		return fmt.Errorf("invalid header layout: ExecutionPayload offset %d not recognized (expected 344, 345, 348, 349, 377, or 381)", o1)
	}

	// Field (5) 'TxRoot' - optional field with 1-byte selector
	if txRootSize > 0 {
		if size < txRootPos+txRootSize {
			return fmt.Errorf("buffer too small for TxRoot: expected at least %d bytes, got %d", txRootPos+txRootSize, size)
		}

		// Read selector byte
		selector := buf[txRootPos]
		switch selector {
		case 0:
			// None: TxRoot is not present
			if txRootSize != 1 {
				return fmt.Errorf("TxRoot selector is 0 (None) but size is %d, expected 1", txRootSize)
			}
			r.TxRoot = nil
		case 1:
			// Some: Read 32 bytes of data
			if txRootSize != 33 {
				return fmt.Errorf("TxRoot selector is 1 (Some) but size is %d, expected 33", txRootSize)
			}
			txRoot := new([32]byte)
			copy(txRoot[:], buf[txRootPos+1:txRootPos+33])
			r.TxRoot = txRoot
		default:
			return fmt.Errorf("invalid TxRoot selector byte: %d (expected 0 or 1)", selector)
		}
	} else {
		// TxRoot field not present in this layout
		r.TxRoot = nil
	}

	// Offset (6) 'AdjustmentData' (only if header contains it)
	if hasAdjustmentDataOffset {
		if o5 = ssz.ReadOffset(buf[adjustmentDataOffsetPos : adjustmentDataOffsetPos+4]); o5 > size || o3 > o5 {
			return fmt.Errorf("failed to unmarshal field 'AdjustmentData': invalid offset %d (previous offset: %d, size: %d): %w", o5, o3, size, ssz.ErrOffset)
		}
	}

	// Field (1) 'ExecutionPayload'
	{
		buf = tail[o1:o2]
		if r.ExecutionPayload == nil {
			r.ExecutionPayload = new(deneb.ExecutionPayload)
		}
		if err = r.ExecutionPayload.UnmarshalSSZ(buf); err != nil {
			return fmt.Errorf("failed to unmarshal field 'ExecutionPayload': %w", err)
		}
	}

	// Field (2) 'BlobsBundle' — zero-copy on cache hits
	{
		buf = tail[o2:o3]
		key := u.hashByteKey(buf)

		if val, ok := u.blobCache.Get(key); ok {
			// Reuse cached immutable pointer (downstream code must not mutate)
			r.BlobsBundle = val.(*FuluExtendedBlobsBundle)
		} else {
			// Parse into pooled scratch
			tmp := u.getFuluBundle()
			u.resetFuluBlobsBundle(tmp)

			if err = u.unmarshalFuluBlobsBundleReuse(tmp, buf); err != nil {
				u.putFuluBundle(tmp)
				return fmt.Errorf("failed to unmarshal field 'BlobsBundle': %w", err)
			}

			// Clone once for immutable cache entry and reuse that pointer
			cached := u.cloneFuluBlobsBundle(tmp)
			u.blobCache.SetDefault(key, cached)
			r.BlobsBundle = cached

			u.putFuluBundle(tmp)
		}
	}

	// Field (3) 'ExecutionRequests'
	{
		buf = tail[o3:o5]
		if r.ExecutionRequests == nil {
			r.ExecutionRequests = new(electra.ExecutionRequests)
		}
		if err = r.ExecutionRequests.UnmarshalSSZ(buf); err != nil {
			return fmt.Errorf("failed to unmarshal field 'ExecutionRequests': %w", err)
		}
	}

	// Field (6) 'AdjustmentData' (optional)
	// Only unmarshal if there's data beyond o5
	if hasAdjustmentDataOffset && o5 < size {
		buf = tail[o5:]
		if r.AdjustmentData == nil {
			r.AdjustmentData = new(bidadjustment.AdjustmentData)
		}
		if err = r.AdjustmentData.UnmarshalSSZ(buf); err != nil {
			return fmt.Errorf("failed to unmarshal field 'AdjustmentData': %w", err)
		}
	} else {
		// No adjustment data present
		r.AdjustmentData = nil
	}

	return nil
}

func (u *BlockSubmissionSSZFastUnmarshaller) hashByteKey(b []byte) string {
	sum := sha256.Sum256(b)
	return string(sum[:])
}

func (u *BlockSubmissionSSZFastUnmarshaller) getFuluBundle() *FuluExtendedBlobsBundle {
	return u.fuluBundlePool.Get().(*FuluExtendedBlobsBundle)
}

func (u *BlockSubmissionSSZFastUnmarshaller) putFuluBundle(b *FuluExtendedBlobsBundle) {
	u.resetFuluBlobsBundle(b)
	u.fuluBundlePool.Put(b)
}

func (u *BlockSubmissionSSZFastUnmarshaller) resetFuluBlobsBundle(b *FuluExtendedBlobsBundle) {
	b.Commitments = b.Commitments[:0]
	b.Proofs = b.Proofs[:0]
	b.Blobs = b.Blobs[:0]
	b.NewItems = b.NewItems[:0]
}

func (u *BlockSubmissionSSZFastUnmarshaller) cloneFuluBlobsBundle(src *FuluExtendedBlobsBundle) *FuluExtendedBlobsBundle {
	if src == nil {
		return nil
	}
	dst := &FuluExtendedBlobsBundle{
		Commitments: make([]deneb.KZGCommitment, len(src.Commitments)),
		Proofs:      make([]deneb.KZGProof, len(src.Proofs)),
		Blobs:       make([]deneb.Blob, len(src.Blobs)),
		NewItems:    make([]FuluHydrationBlobItem, len(src.NewItems)),
	}
	copy(dst.Commitments, src.Commitments)
	copy(dst.Proofs, src.Proofs)
	copy(dst.Blobs, src.Blobs)
	copy(dst.NewItems, src.NewItems)
	return dst
}

func (u *BlockSubmissionSSZFastUnmarshaller) unmarshalFuluBlobsBundleReuse(b *FuluExtendedBlobsBundle, buf []byte) error {
	size := uint64(len(buf))
	if size < 12 {
		return fmt.Errorf("buffer too small, expected at least 12 bytes, got %d: %w", size, ssz.ErrSize)
	}

	tail := buf
	var o0, o1, o2, o3 uint64

	// Detect format by reading first offset
	// Offset (0) 'Commitments'
	o0 = ssz.ReadOffset(buf[0:4])
	if o0 != 12 && o0 != 8 { // 12 is for standard format and 8 is for dehydrated (with NewItems and no Proofs/Blobs)
		return fmt.Errorf("failed to unmarshal field 'Commitments': invalid offset %d, expected 12 (standard) or 8 (dehydrated): %w", o0, ssz.ErrInvalidVariableOffset)
	} else if o0 > size {
		return fmt.Errorf("failed to unmarshal field 'Commitments': offset %d exceeds buffer size %d: %w", o0, size, ssz.ErrOffset)
	}
	hasNewItems := o0 == 8
	if !hasNewItems && size < 12 {
		return ssz.ErrSize
	}

	if hasNewItems {
		// Dehydrated format: only Commitments and NewItems offsets
		if o3 = ssz.ReadOffset(buf[4:8]); o3 > size {
			return fmt.Errorf("failed to unmarshal field 'NewItems' (dehydrated format): offset %d exceeds buffer size %d: %w", o3, size, ssz.ErrOffset)
		}
		// For dehydrated format: Commitments[o0:o3], Proofs and Blobs are empty
		o1 = o3 // Proofs start where Commitments end (empty segment)
		o2 = o3 // Blobs start where Commitments end (empty segment)
	} else {
		// Standard format: read all offsets
		// Offset (1) 'Proofs'
		if o1 = ssz.ReadOffset(buf[4:8]); o1 > size || o0 > o1 {
			return fmt.Errorf("failed to unmarshal field 'Proofs': invalid offset %d (previous offset: %d, size: %d): %w", o1, o0, size, ssz.ErrOffset)
		}

		// Offset (2) 'Blobs'
		if o2 = ssz.ReadOffset(buf[8:12]); o2 > size || o1 > o2 {
			return fmt.Errorf("failed to unmarshal field 'Blobs': invalid offset %d (previous offset: %d, size: %d): %w", o2, o1, size, ssz.ErrOffset)
		}

		o3 = size
	}

	// Field (0) 'Commitments'
	{
		seg := tail[o0:o1]
		num, err := ssz.DivideInt2(len(seg), 48, 4096)
		if err != nil {
			return fmt.Errorf("failed to unmarshal field 'Commitments': invalid segment size %d: %w", len(seg), err)
		}
		if num > 0 {
			if cap(b.Commitments) >= num {
				b.Commitments = b.Commitments[:num]
			} else {
				b.Commitments = make([]deneb.KZGCommitment, num)
			}
			for i := 0; i < num; i++ {
				copy(b.Commitments[i][:], seg[i*48:(i+1)*48])
			}
		} else {
			b.Commitments = b.Commitments[:0]
		}
	}

	// Field (1) 'Proofs'
	{
		seg := tail[o1:o2]
		// NOTE: max = 33554432 here, same as generated UnmarshalSSZ
		num, err := ssz.DivideInt2(len(seg), 48, 33554432)
		if err != nil {
			return fmt.Errorf("failed to unmarshal field 'Proofs': invalid segment size %d: %w", len(seg), err)
		}
		if num > 0 {
			if cap(b.Proofs) >= num {
				b.Proofs = b.Proofs[:num]
			} else {
				b.Proofs = make([]deneb.KZGProof, num)
			}
			for i := 0; i < num; i++ {
				copy(b.Proofs[i][:], seg[i*48:(i+1)*48])
			}
		} else {
			b.Proofs = b.Proofs[:0]
		}
	}

	// Field (2) 'Blobs'
	{
		seg := tail[o2:o3]
		num, err := ssz.DivideInt2(len(seg), 131072, 4096)
		if err != nil {
			return fmt.Errorf("failed to unmarshal field 'Blobs': invalid segment size %d: %w", len(seg), err)
		}
		if num > 0 {
			if cap(b.Blobs) >= num {
				b.Blobs = b.Blobs[:num]
			} else {
				b.Blobs = make([]deneb.Blob, num)
			}
			for i := 0; i < num; i++ {
				copy(b.Blobs[i][:], seg[i*131072:(i+1)*131072])
			}
		} else {
			b.Blobs = b.Blobs[:0]
		}
	}

	// Field (3) 'NewItems' (only if extended format)
	if hasNewItems {
		seg := tail[o3:]
		num, err := ssz.DivideInt2(len(seg), 137268, 4096)
		if err != nil {
			return fmt.Errorf("failed to unmarshal field 'NewItems': invalid segment size %d: %w", len(seg), err)
		}
		b.NewItems = make([]FuluHydrationBlobItem, num)
		for i := 0; i < num; i++ {
			if err = b.NewItems[i].UnmarshalSSZ(seg[i*137268 : (i+1)*137268]); err != nil {
				return fmt.Errorf("failed to unmarshal field 'NewItems' item %d: %w", i, err)
			}
		}
	} else {
		b.NewItems = nil
	}

	return nil
}
