package common

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloXroute-Labs/relay-grpc/bidadjustment"
	ssz "github.com/ferranbt/fastssz"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

const (
	// SSZ size constants for Fulu w/o hydration
	kzgProofSize      = 48     // Size of a single KZG proof in bytes
	kzgCommitmentSize = 48     // Size of a KZG commitment in bytes
	blobSize          = 131072 // Size of a blob in bytes (128 KiB)
	maxProofsPerBlob  = 128    // Maximum number of proofs per blob (CELLS_PER_EXT_BLOB in PeerDAS of Fulu spec)
	maxBlobsPerBlock  = 4096   // Maximum number of blobs per block

	// fuluHydrationItemFixedSize is the size of fixed fields in FuluHydrationBlobItem:
	// 4 bytes (offset) + 48 bytes (commitment) + 131072 bytes (blob)
	fuluHydrationItemFixedSize = 4 + kzgCommitmentSize + blobSize // = 131124

	// fuluHydrationItemMaxSize is the maximum encoded size of FuluHydrationBlobItem:
	// 131124 bytes (fixed) + 128*48 bytes (max proofs)
	fuluHydrationItemMaxSize = fuluHydrationItemFixedSize + (maxProofsPerBlob * kzgProofSize) // = 137268
)

// UnmarshalSSZ unmarshals FuluHydrationBlobItem from SSZ format
func (item *FuluHydrationBlobItem) UnmarshalSSZ(buf []byte) error {
	size := uint64(len(buf))
	if size < fuluHydrationItemFixedSize {
		return fmt.Errorf("buffer too small, expected at least %d bytes, got %d: %w", fuluHydrationItemFixedSize, size, ssz.ErrSize)
	}

	var o0 uint64

	// Offset (0) 'Proofs'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return fmt.Errorf("failed to unmarshal field 'Proofs': offset %d exceeds buffer size %d: %w", o0, size, ssz.ErrOffset)
	}
	if o0 != fuluHydrationItemFixedSize {
		return fmt.Errorf("failed to unmarshal field 'Proofs': invalid offset %d, expected %d: %w", o0, fuluHydrationItemFixedSize, ssz.ErrInvalidVariableOffset)
	}

	// Field (1) 'Commitment' - 48 bytes at [4:52]
	copy(item.Commitment[:], buf[4:4+kzgCommitmentSize])

	// Field (2) 'Blob' - 131072 bytes at [52:131124]
	copy(item.Blob[:], buf[4+kzgCommitmentSize:fuluHydrationItemFixedSize])

	// Field (0) 'Proofs' (variable) but in fact expected to be 128 always (CELLS_PER_EXT_BLOB)
	{
		seg := buf[o0:]
		num, err := ssz.DivideInt2(len(seg), kzgProofSize, maxProofsPerBlob)
		if err != nil {
			return fmt.Errorf("failed to unmarshal field 'Proofs': invalid segment size %d: %w", len(seg), err)
		}
		item.Proof = make([]deneb.KZGProof, num)
		for i := range num {
			copy(item.Proof[i][:], seg[i*kzgProofSize:(i+1)*kzgProofSize])
		}
	}

	return nil
}

type Hydrator interface {
	HydrateFuluTransactions(builderPubkey phase0.BLSPubKey, payload *deneb.ExecutionPayload) (*TransactionsHydrateData, error)
	HydrateFuluBlobs(blobsBundle *FuluExtendedBlobsBundle) (*BlobsHydrateData, error)
}

// SSZ Unmarshaller impl for VersionedExtendedSubmitBlockRequest with caching and object pooling.
// It's capable of processing both standard and dehydrated formats for Fulu blobs bundle as well as optional AdjustmentData.
type BlockSubmissionSSZFastUnmarshaller struct {
	log *zerolog.Logger
	// Key: sha256(raw SSZ bytes of BlobsBundle) as binary string
	// Val: *apideneb.BlobsBundle (immutable, cached)
	blobCache *cache.Cache
	// Fulu blobs
	fuluBundlePool sync.Pool
	// Hydrator for optional hydration of transactions and blobs during unmarshalling
	hydrator Hydrator
}

func NewBlockSubmissionSSZFastUnmarshaller(log *zerolog.Logger, hydrator Hydrator) *BlockSubmissionSSZFastUnmarshaller {
	return &BlockSubmissionSSZFastUnmarshaller{
		log:       log,
		blobCache: cache.New(1*time.Minute, 1*time.Minute),
		fuluBundlePool: sync.Pool{
			New: func() any { return new(FuluExtendedBlobsBundle) },
		},
		hydrator: hydrator,
	}
}

func (u *BlockSubmissionSSZFastUnmarshaller) UnmarshalSSZ(input []byte, out *VersionedExtendedSubmitBlockRequest, hydrate bool) error {
	if IsFulu {
		out.Version = consensusspec.DataVersionFulu
		fuluExtendedRequest := new(FuluExtendedSubmitBlockRequest)
		if err := u.unmarshalSSZFulu(fuluExtendedRequest, input, hydrate); err != nil {
			return fmt.Errorf("failed to unmarshal Fulu extended submit block request: %w", err)
		}
		out.Fulu = fuluExtendedRequest
		return nil
	}
	return errors.New("only fulu version is supported for extended SubmitBlockRequest")
}

func (u *BlockSubmissionSSZFastUnmarshaller) unmarshalSSZFulu(r *FuluExtendedSubmitBlockRequest, buf []byte, hydrate bool) error {
	var err error
	size := uint64(len(buf))
	if size < 344 {
		return fmt.Errorf("buffer too small, expected at least 344 bytes, got %d: %w", size, ssz.ErrSize)
	}

	tail := buf
	var o1, o2, o3, o4 uint64

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
	//
	// TxRoot encoding (hydrated format only):
	//   - 4 bytes for offset in fixed section
	//   - Variable section contains: 1-byte selector (0=None, 1=Some) + 32 bytes if selector=1
	//
	// Possible layouts after Signature (position 344):
	// 1. o1 == 344: No optional fields
	// 2. o1 == 348: Single 4-byte offset (could be TxRoot or AdjustmentData, need to inspect data)
	// 3. o1 == 352: TxRoot offset (4 bytes) + AdjustmentData offset (4 bytes)

	var txRootOffsetPos uint64 = 344
	var adjustmentDataOffsetPos uint64 = 344
	hasTxRootOffset := false
	hasAdjustmentDataOffset := false

	switch o1 {
	case 344:
		// No optional fields
		o4 = size
	case 348:
		// Single 4-byte offset at position 344
		// Could be either TxRoot or AdjustmentData - need to inspect the data
		// TxRoot data is always exactly 1 byte (None) or 33 bytes (Some with hash)
		// AdjustmentData is much larger (typically ~200 bytes)
		// We check the size to determine which it is
		o4 = ssz.ReadOffset(buf[344:348])
		if o4 >= size {
			return fmt.Errorf("invalid offset at position 344: %d exceeds buffer size %d", o4, size)
		}

		// Calculate data size from offset to end of buffer
		dataSize := size - o4

		// TxRoot is always 1 or 33 bytes
		// Otherwise it's AdjustmentData
		if dataSize == 1 || dataSize == 33 {
			// TxRoot
			hasTxRootOffset = true
			txRootOffsetPos = 344
		} else {
			// AdjustmentData
			hasAdjustmentDataOffset = true
			adjustmentDataOffsetPos = 344
		}
	case 352:
		// TxRoot offset (4 bytes) + AdjustmentData offset (4 bytes)
		o4 = ssz.ReadOffset(buf[344:348])
		if o4 >= size {
			return fmt.Errorf("invalid TxRoot offset at position 344: %d exceeds buffer size %d", o4, size)
		}
		hasTxRootOffset = true
		txRootOffsetPos = 344
		hasAdjustmentDataOffset = true
		adjustmentDataOffsetPos = 348
	default:
		return fmt.Errorf("invalid header layout: ExecutionPayload offset %d not recognized (expected 344, 348, or 352)", o1)
	}

	// Read TxRoot offset if present
	var txRootDataOffset uint64
	if hasTxRootOffset {
		if txRootDataOffset = ssz.ReadOffset(buf[txRootOffsetPos : txRootOffsetPos+4]); txRootDataOffset > size {
			return fmt.Errorf("failed to unmarshal field 'TxRoot': offset %d exceeds buffer size %d: %w", txRootDataOffset, size, ssz.ErrOffset)
		}
	}

	// Offset (6) 'AdjustmentData' (only if header contains it)
	var adjustmentDataOffset uint64
	if hasAdjustmentDataOffset {
		if adjustmentDataOffset = ssz.ReadOffset(buf[adjustmentDataOffsetPos : adjustmentDataOffsetPos+4]); adjustmentDataOffset > size {
			return fmt.Errorf("failed to unmarshal field 'AdjustmentData': invalid offset %d (size: %d): %w", adjustmentDataOffset, size, ssz.ErrOffset)
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
		// Hydrate transactions
		if hydrate {
			if d, err := u.hydrator.HydrateFuluTransactions(r.Message.BuilderPubkey, r.ExecutionPayload); err != nil {
				return fmt.Errorf("failed to hydrate field 'ExecutionPayload': %w", err)
			} else {
				// TODO: set debug
				u.log.Info().Uint64("slot", r.Message.Slot).Int("tx_cache_hits", d.CacheHits).Int("tx_cache_writes", d.CacheWrites).Msg("Hydrated transactions for ExecutionPayload")
			}
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
			// Hydrate blobs
			if hydrate {
				if d, err := u.hydrator.HydrateFuluBlobs(cached); err != nil {
					u.putFuluBundle(tmp)
					return fmt.Errorf("failed to hydrate field 'BlobsBundle': %w", err)
				} else {
					// TODO: set debug
					u.log.Info().Uint64("slot", r.Message.Slot).Int("blob_cache_hits", d.CacheHits).Int("blob_cache_writes", d.CacheWrites).Msg("Hydrated blobs for BlobsBundle")
				}
			}
			u.blobCache.SetDefault(key, cached)
			r.BlobsBundle = cached

			u.putFuluBundle(tmp)
		}
	}

	// Field (3) 'ExecutionRequests'
	{
		buf = tail[o3:o4]
		if r.ExecutionRequests == nil {
			r.ExecutionRequests = new(electra.ExecutionRequests)
		}
		if err = r.ExecutionRequests.UnmarshalSSZ(buf); err != nil {
			return fmt.Errorf("failed to unmarshal field 'ExecutionRequests': %w", err)
		}
	}

	// Field (5) 'TxRoot' variable data (if encoded as variable field)
	// TxRoot data in variable section always has:
	//   - 1 byte selector (0 = None, 1 = Some)
	//   - If selector = 1: followed by 32 bytes of data
	// Total size: 1 byte (None) or 33 bytes (Some)
	if hasTxRootOffset {
		// Determine TxRoot data end position
		var txRootDataEnd uint64
		if hasAdjustmentDataOffset {
			// AdjustmentData follows TxRoot
			txRootDataEnd = adjustmentDataOffset
		} else {
			// TxRoot extends to end of buffer
			txRootDataEnd = size
		}

		switch txRootDataSize := txRootDataEnd - txRootDataOffset; txRootDataSize {
		case 1:
			// Selector = 0 (None)
			selector := tail[txRootDataOffset]
			if selector != 0 {
				return fmt.Errorf("invalid TxRoot: 1-byte size but selector is %d (expected 0)", selector)
			}
			r.TxRoot = nil
		case 33:
			// Selector = 1 (Some) followed by 32 bytes
			selector := tail[txRootDataOffset]
			if selector != 1 {
				return fmt.Errorf("invalid TxRoot: 33-byte size but selector is %d (expected 1)", selector)
			}
			txRoot := new([32]byte)
			copy(txRoot[:], tail[txRootDataOffset+1:txRootDataEnd])
			r.TxRoot = txRoot
		default:
			return fmt.Errorf("invalid TxRoot variable data size: %d (expected 1 for None or 33 for Some)", txRootDataSize)
		}
	}

	// Field (6) 'AdjustmentData' (optional)
	if hasAdjustmentDataOffset {
		buf = tail[adjustmentDataOffset:]
		if r.AdjustmentData == nil {
			r.AdjustmentData = new(bidadjustment.AdjustmentData)
		}
		if err = r.AdjustmentData.UnmarshalSSZ(buf); err != nil {
			return fmt.Errorf("failed to unmarshal field 'AdjustmentData': %w", err)
		}
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
		NewItems:    make([]*FuluHydrationBlobItem, len(src.NewItems)),
	}
	copy(dst.Commitments, src.Commitments)
	copy(dst.Proofs, src.Proofs)
	copy(dst.Blobs, src.Blobs)
	copy(dst.NewItems, src.NewItems)
	return dst
}

func (u *BlockSubmissionSSZFastUnmarshaller) unmarshalFuluBlobsBundleReuse(b *FuluExtendedBlobsBundle, buf []byte) error {
	size := uint64(len(buf))
	if size < 8 {
		return fmt.Errorf("buffer too small, expected at least 8 bytes, got %d: %w", size, ssz.ErrSize)
	}

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
		seg := buf[o0:o1]
		num, err := ssz.DivideInt2(len(seg), kzgCommitmentSize, maxBlobsPerBlock)
		if err != nil {
			return fmt.Errorf("failed to unmarshal field 'Commitments': invalid segment size %d: %w", len(seg), err)
		}
		if cap(b.Commitments) >= num {
			b.Commitments = b.Commitments[:num]
		} else {
			b.Commitments = make([]deneb.KZGCommitment, num)
		}
		for i := range num {
			copy(b.Commitments[i][:], seg[i*kzgCommitmentSize:(i+1)*kzgCommitmentSize])
		}
	}

	// Field (1) 'Proofs'
	{
		seg := buf[o1:o2]
		// max = 33554432 here is same as in fulu.BlobsBundle SSZ max for Proofs
		num, err := ssz.DivideInt2(len(seg), kzgProofSize, 33554432)
		if err != nil {
			return fmt.Errorf("failed to unmarshal field 'Proofs': invalid segment size %d: %w", len(seg), err)
		}
		if cap(b.Proofs) >= num {
			b.Proofs = b.Proofs[:num]
		} else {
			b.Proofs = make([]deneb.KZGProof, num)
		}
		for i := range num {
			copy(b.Proofs[i][:], seg[i*kzgProofSize:(i+1)*kzgProofSize])
		}
	}

	// Field (2) 'Blobs'
	{
		seg := buf[o2:o3]
		num, err := ssz.DivideInt2(len(seg), blobSize, maxBlobsPerBlock)
		if err != nil {
			return fmt.Errorf("failed to unmarshal field 'Blobs': invalid segment size %d: %w", len(seg), err)
		}
		if cap(b.Blobs) >= num {
			b.Blobs = b.Blobs[:num]
		} else {
			b.Blobs = make([]deneb.Blob, num)
		}
		for i := range num {
			copy(b.Blobs[i][:], seg[i*blobSize:(i+1)*blobSize])
		}
	}

	// Field (3) 'NewItems' (only if extended format)
	if hasNewItems {
		if seg := buf[o3:]; len(seg) == 0 {
			// Empty NewItems list
			b.NewItems = nil
		} else if len(seg) < 4 {
			return fmt.Errorf("failed to unmarshal field 'NewItems': segment too small %d: %w", len(seg), ssz.ErrSize)
		} else {
			// NewItems is a list of pointers, so SSZ encodes it with offsets for each item
			// Format: [offset_0][offset_1]...[offset_n][item_0_data][item_1_data]...
			// Each offset is 4 bytes and points to the start of that item's data within the variable section

			// Read first offset to determine number of items
			// The first offset value tells us where the data section starts, which is after all the offsets
			// So: first_offset / 4 = number_of_items
			firstOffset := ssz.ReadOffset(seg[0:4])
			if firstOffset < 4 || firstOffset%4 != 0 {
				return fmt.Errorf("failed to unmarshal field 'NewItems': invalid first offset %d: %w", firstOffset, ssz.ErrInvalidVariableOffset)
			}
			num := int(firstOffset / 4)
			if num > maxBlobsPerBlock {
				return fmt.Errorf("failed to unmarshal field 'NewItems': too many items %d (max %d): %w", num, maxBlobsPerBlock, ssz.ErrSize)
			}
			if uint64(len(seg)) < firstOffset {
				return fmt.Errorf("failed to unmarshal field 'NewItems': segment size %d < first offset %d: %w", len(seg), firstOffset, ssz.ErrSize)
			}

			// Read all offsets
			offsets := make([]uint64, num)
			for i := range num {
				offsets[i] = ssz.ReadOffset(seg[i*4 : (i+1)*4])
				if offsets[i] > uint64(len(seg)) {
					return fmt.Errorf("failed to unmarshal field 'NewItems' item %d: offset %d exceeds segment size %d: %w", i, offsets[i], len(seg), ssz.ErrOffset)
				}
			}

			// Unmarshal each item using its offset
			b.NewItems = make([]*FuluHydrationBlobItem, num)
			for i := range num {
				var itemEnd uint64
				if i+1 < num {
					itemEnd = offsets[i+1]
				} else {
					itemEnd = uint64(len(seg))
				}
				if itemEnd <= offsets[i] {
					return fmt.Errorf("failed to unmarshal field 'NewItems' item %d: invalid item range [%d:%d]: %w", i, offsets[i], itemEnd, ssz.ErrSize)
				}

				b.NewItems[i] = &FuluHydrationBlobItem{}
				if unmarshalErr := b.NewItems[i].UnmarshalSSZ(seg[offsets[i]:itemEnd]); unmarshalErr != nil {
					return fmt.Errorf("failed to unmarshal field 'NewItems' item %d: %w", i, unmarshalErr)
				}
			}
		}
	}

	return nil
}
