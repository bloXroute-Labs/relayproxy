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
	"github.com/bloXroute-Labs/relay-grpc/bidadjustment"
	ssz "github.com/ferranbt/fastssz"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
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

	tail := buf
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
		seg := tail[o0:]
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

	// Field (5) 'TxRoot' - optional field with 1-byte selector (otherwise is not present, even selector)
	if txRootSize > 0 {
		if size < txRootPos+txRootSize {
			return fmt.Errorf("buffer too small for TxRoot: expected at least %d bytes, got %d", txRootPos+txRootSize, size)
		}

		// Read selector byte
		switch selector := buf[txRootPos]; selector {
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
	// Only unmarshal if there's data beyond o5 and buffer is large enough
	if hasAdjustmentDataOffset && o5 < size {
		// Skip if buffer too small (1 byte is likely padding/trailing data, not valid AdjustmentData)
		if adjustmentDataBufSize := size - o5; adjustmentDataBufSize > 1 {
			buf = tail[o5:]
			if r.AdjustmentData == nil {
				r.AdjustmentData = new(bidadjustment.AdjustmentData)
			}
			if err = r.AdjustmentData.UnmarshalSSZ(buf); err != nil {
				return fmt.Errorf("failed to unmarshal field 'AdjustmentData' (offset=%d, bufSize=%d, totalSize=%d): %w", o5, adjustmentDataBufSize, size, err)
			}
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
		seg := tail[o1:o2]
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
		seg := tail[o2:o3]
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
		seg := tail[o3:]
		num, err := ssz.DivideInt2(len(seg), fuluHydrationItemMaxSize, maxBlobsPerBlock)
		if err != nil {
			return fmt.Errorf("failed to unmarshal field 'NewItems': invalid segment size %d: %w", len(seg), err)
		}
		b.NewItems = make([]*FuluHydrationBlobItem, num)
		for i := range num {
			b.NewItems[i] = &FuluHydrationBlobItem{}
			if err = b.NewItems[i].UnmarshalSSZ(seg[i*fuluHydrationItemMaxSize : (i+1)*fuluHydrationItemMaxSize]); err != nil {
				return fmt.Errorf("failed to unmarshal field 'NewItems' item %d: %w", i, err)
			}
		}
	} else {
		b.NewItems = nil
	}

	return nil
}
