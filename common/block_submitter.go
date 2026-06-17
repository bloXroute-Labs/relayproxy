package common

import (
	"crypto/sha256"
	"sync"

	apideneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiElectra "github.com/attestantio/go-builder-client/api/electra"
	builderApiFulu "github.com/attestantio/go-builder-client/api/fulu"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	ssz "github.com/ferranbt/fastssz"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
)

// TODO: this one is for now left only for `submitNewBlock-Websocket` (which is not used)
type BlockSubmitter interface {
	UnmarshalSSZ(in []byte, out *VersionedSubmitBlockRequest) error
}

type BlockSubmission struct {
	// Key: sha256(raw SSZ bytes of BlobsBundle) as binary string
	// Val: *apideneb.BlobsBundle or *builderApiFulu.BlobsBundle (immutable, cached)
	blobCache *cache.Cache

	// Deneb/Electra blobs
	bundlePool sync.Pool
	// Fulu blobs
	fuluBundlePool sync.Pool
}

func NewBlockSubmitter() BlockSubmitter {
	return &BlockSubmission{
		blobCache: cache.New(DefaultBlobCacheExpiration, DefaultBlobCacheExpiration),
		bundlePool: sync.Pool{
			New: func() any { return new(apideneb.BlobsBundle) },
		},
		fuluBundlePool: sync.Pool{
			New: func() any { return new(builderApiFulu.BlobsBundle) },
		},
	}
}

func (b *BlockSubmission) UnmarshalSSZ(input []byte, out *VersionedSubmitBlockRequest) error {
	var err error

	// Fulu fast path
	if IsFulu {
		fuluRequest := new(builderApiFulu.SubmitBlockRequest)
		if err = b.unmarshalSSZFastFulu(fuluRequest, input); err == nil {
			// Adjust this if you have a dedicated Fulu data version.
			out.Version = spec.DataVersionFulu
			out.Fulu = fuluRequest
			return nil
		}
	}

	// Electra fast path
	if IsElectra {
		electraRequest := new(builderApiElectra.SubmitBlockRequest)
		if err = b.unmarshalSSZFast(electraRequest, input); err == nil {
			out.Version = spec.DataVersionElectra
			out.Electra = electraRequest
			return nil
		}
	}

	// Fallback fulu fast path (if first attempt failed but payload was Fulu)
	fuluRequest := new(builderApiFulu.SubmitBlockRequest)
	if err = b.unmarshalSSZFastFulu(fuluRequest, input); err == nil {
		// Adjust this if you have a dedicated Fulu data version.
		out.Version = spec.DataVersionFulu
		out.Fulu = fuluRequest
		return nil
	}

	return errors.Wrap(err, "failed to unmarshal SubmitBlockRequest SSZ")
}

// UnmarshalSSZ fast path for Fulu.
func (b *BlockSubmission) unmarshalSSZFastFulu(s *builderApiFulu.SubmitBlockRequest, buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 344 {
		return ssz.ErrSize
	}

	tail := buf
	var o1, o2, o3 uint64

	// Field (0) 'Message'
	if s.Message == nil {
		s.Message = new(apiv1.BidTrace)
	}
	if err = s.Message.UnmarshalSSZ(buf[0:236]); err != nil {
		return err
	}

	// Offset (1) 'ExecutionPayload'
	if o1 = ssz.ReadOffset(buf[236:240]); o1 > size {
		return ssz.ErrOffset
	}
	if o1 != 344 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (2) 'BlobsBundle'
	if o2 = ssz.ReadOffset(buf[240:244]); o2 > size || o1 > o2 {
		return ssz.ErrOffset
	}

	// Offset (3) 'ExecutionRequests'
	if o3 = ssz.ReadOffset(buf[244:248]); o3 > size || o2 > o3 {
		return ssz.ErrOffset
	}

	// Field (4) 'Signature'
	copy(s.Signature[:], buf[248:344])

	// Field (1) 'ExecutionPayload'
	{
		buf = tail[o1:o2]
		if s.ExecutionPayload == nil {
			s.ExecutionPayload = new(deneb.ExecutionPayload)
		}
		if err = s.ExecutionPayload.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}

	// Field (2) 'BlobsBundle' — zero-copy on cache hits
	{
		buf = tail[o2:o3]
		key := hashByteKey(buf)

		if val, ok := b.blobCache.Get(key); ok {
			// Reuse cached immutable pointer (downstream code must not mutate)
			s.BlobsBundle = val.(*builderApiFulu.BlobsBundle)
		} else {
			// Parse into pooled scratch
			tmp := b.getFuluBundle()
			resetFuluBlobsBundle(tmp)

			if err = unmarshalFuluBlobsBundleReuse(tmp, buf); err != nil {
				b.putFuluBundle(tmp)
				return err
			}

			// Clone once for immutable cache entry and reuse that pointer
			cached := cloneFuluBlobsBundle(tmp)
			b.blobCache.SetDefault(key, cached)
			s.BlobsBundle = cached

			b.putFuluBundle(tmp)
		}
	}

	// Field (3) 'ExecutionRequests'
	{
		buf = tail[o3:]
		if s.ExecutionRequests == nil {
			s.ExecutionRequests = new(electra.ExecutionRequests)
		}
		if err = s.ExecutionRequests.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}
	return nil
}

// UnmarshalSSZ fast path for Electra.
func (b *BlockSubmission) unmarshalSSZFast(s *builderApiElectra.SubmitBlockRequest, buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 344 {
		return ssz.ErrSize
	}

	tail := buf
	var o1, o2, o3 uint64

	// Field (0) 'Message'
	if s.Message == nil {
		s.Message = new(apiv1.BidTrace)
	}
	if err = s.Message.UnmarshalSSZ(buf[0:236]); err != nil {
		return err
	}

	// Offset (1) 'ExecutionPayload'
	if o1 = ssz.ReadOffset(buf[236:240]); o1 > size {
		return ssz.ErrOffset
	}
	if o1 != 344 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (2) 'BlobsBundle'
	if o2 = ssz.ReadOffset(buf[240:244]); o2 > size || o1 > o2 {
		return ssz.ErrOffset
	}

	// Offset (3) 'ExecutionRequests'
	if o3 = ssz.ReadOffset(buf[244:248]); o3 > size || o2 > o3 {
		return ssz.ErrOffset
	}

	// Field (4) 'Signature'
	copy(s.Signature[:], buf[248:344])

	// Field (1) 'ExecutionPayload'
	{
		buf = tail[o1:o2]
		if s.ExecutionPayload == nil {
			s.ExecutionPayload = new(deneb.ExecutionPayload)
		}
		if err = s.ExecutionPayload.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}

	// Field (2) 'BlobsBundle' — zero-copy on cache hits
	{
		buf = tail[o2:o3]
		key := hashByteKey(buf)

		if val, ok := b.blobCache.Get(key); ok {
			// Reuse cached immutable pointer (downstream code must not mutate)
			s.BlobsBundle = val.(*apideneb.BlobsBundle)
		} else {
			// Parse into pooled scratch
			tmp := b.getBundle()
			resetBlobsBundle(tmp)

			if err = unmarshalBlobsBundleReuse(tmp, buf); err != nil {
				b.putBundle(tmp)
				return err
			}

			// Clone once for immutable cache entry and reuse that pointer
			cached := cloneBlobsBundle(tmp)
			b.blobCache.SetDefault(key, cached)
			s.BlobsBundle = cached

			b.putBundle(tmp)
		}
	}

	// Field (3) 'ExecutionRequests'
	{
		buf = tail[o3:]
		if s.ExecutionRequests == nil {
			s.ExecutionRequests = new(electra.ExecutionRequests)
		}
		if err = s.ExecutionRequests.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}
	return nil
}

func unmarshalBlobsBundleReuse(b *apideneb.BlobsBundle, buf []byte) error {
	if len(buf) < 12 {
		return ssz.ErrSize
	}
	size := uint64(len(buf))
	tail := buf
	var o0, o1, o2 uint64

	// Offsets
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size || o0 < 12 {
		return ssz.ErrOffset
	}
	if o1 = ssz.ReadOffset(buf[4:8]); o1 > size || o0 > o1 {
		return ssz.ErrOffset
	}
	if o2 = ssz.ReadOffset(buf[8:12]); o2 > size || o1 > o2 {
		return ssz.ErrOffset
	}

	// Commitments
	seg := tail[o0:o1]
	num, err := ssz.DivideInt2(len(seg), 48, 4096)
	if err != nil {
		return err
	}
	if cap(b.Commitments) >= num {
		b.Commitments = b.Commitments[:num]
	} else {
		b.Commitments = make([]deneb.KZGCommitment, num)
	}
	for i := 0; i < num; i++ {
		copy(b.Commitments[i][:], seg[i*48:(i+1)*48])
	}

	// Proofs
	seg = tail[o1:o2]
	num, err = ssz.DivideInt2(len(seg), 48, 4096)
	if err != nil {
		return err
	}
	if cap(b.Proofs) >= num {
		b.Proofs = b.Proofs[:num]
	} else {
		b.Proofs = make([]deneb.KZGProof, num)
	}
	for i := 0; i < num; i++ {
		copy(b.Proofs[i][:], seg[i*48:(i+1)*48])
	}

	// Blobs (128 KiB each)
	seg = tail[o2:]
	num, err = ssz.DivideInt2(len(seg), 131072, 4096)
	if err != nil {
		return err
	}
	if cap(b.Blobs) >= num {
		b.Blobs = b.Blobs[:num]
	} else {
		b.Blobs = make([]deneb.Blob, num)
	}
	for i := 0; i < num; i++ {
		copy(b.Blobs[i][:], seg[i*131072:(i+1)*131072])
	}
	return nil
}

func unmarshalFuluBlobsBundleReuse(b *builderApiFulu.BlobsBundle, buf []byte) error {
	size := uint64(len(buf))
	if size < 12 {
		return ssz.ErrSize
	}

	tail := buf
	var o0, o1, o2 uint64

	// Offset (0) 'Commitments'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}
	if o0 != 12 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (1) 'Proofs'
	if o1 = ssz.ReadOffset(buf[4:8]); o1 > size || o0 > o1 {
		return ssz.ErrOffset
	}

	// Offset (2) 'Blobs'
	if o2 = ssz.ReadOffset(buf[8:12]); o2 > size || o1 > o2 {
		return ssz.ErrOffset
	}

	// Field (0) 'Commitments'
	{
		seg := tail[o0:o1]
		num, err := ssz.DivideInt2(len(seg), 48, 4096)
		if err != nil {
			return err
		}
		if cap(b.Commitments) >= num {
			b.Commitments = b.Commitments[:num]
		} else {
			b.Commitments = make([]deneb.KZGCommitment, num)
		}
		for i := 0; i < num; i++ {
			copy(b.Commitments[i][:], seg[i*48:(i+1)*48])
		}
	}

	// Field (1) 'Proofs'
	{
		seg := tail[o1:o2]
		// NOTE: max = 33554432 here, same as generated UnmarshalSSZ
		num, err := ssz.DivideInt2(len(seg), 48, 33554432)
		if err != nil {
			return err
		}
		if cap(b.Proofs) >= num {
			b.Proofs = b.Proofs[:num]
		} else {
			b.Proofs = make([]deneb.KZGProof, num)
		}
		for i := 0; i < num; i++ {
			copy(b.Proofs[i][:], seg[i*48:(i+1)*48])
		}
	}

	// Field (2) 'Blobs'
	{
		seg := tail[o2:]
		num, err := ssz.DivideInt2(len(seg), 131072, 4096)
		if err != nil {
			return err
		}
		if cap(b.Blobs) >= num {
			b.Blobs = b.Blobs[:num]
		} else {
			b.Blobs = make([]deneb.Blob, num)
		}
		for i := 0; i < num; i++ {
			copy(b.Blobs[i][:], seg[i*131072:(i+1)*131072])
		}
	}

	return nil
}

func (b *BlockSubmission) getBundle() *apideneb.BlobsBundle {
	return b.bundlePool.Get().(*apideneb.BlobsBundle)
}
func (b *BlockSubmission) putBundle(bun *apideneb.BlobsBundle) {
	resetBlobsBundle(bun)
	b.bundlePool.Put(bun)
}

func (b *BlockSubmission) getFuluBundle() *builderApiFulu.BlobsBundle {
	return b.fuluBundlePool.Get().(*builderApiFulu.BlobsBundle)
}
func (b *BlockSubmission) putFuluBundle(bun *builderApiFulu.BlobsBundle) {
	resetFuluBlobsBundle(bun)
	b.fuluBundlePool.Put(bun)
}

func resetBlobsBundle(bun *apideneb.BlobsBundle) {
	bun.Commitments = bun.Commitments[:0]
	bun.Proofs = bun.Proofs[:0]
	bun.Blobs = bun.Blobs[:0]
}

func resetFuluBlobsBundle(bun *builderApiFulu.BlobsBundle) {
	bun.Commitments = bun.Commitments[:0]
	bun.Proofs = bun.Proofs[:0]
	bun.Blobs = bun.Blobs[:0]
}

func hashByteKey(b []byte) string {
	sum := sha256.Sum256(b)
	return string(sum[:])
}

func cloneBlobsBundle(src *apideneb.BlobsBundle) *apideneb.BlobsBundle {
	if src == nil {
		return nil
	}
	dst := &apideneb.BlobsBundle{
		Commitments: make([]deneb.KZGCommitment, len(src.Commitments)),
		Proofs:      make([]deneb.KZGProof, len(src.Proofs)),
		Blobs:       make([]deneb.Blob, len(src.Blobs)),
	}
	// slice-level copies copy the fixed-size arrays by value efficiently
	copy(dst.Commitments, src.Commitments)
	copy(dst.Proofs, src.Proofs)
	copy(dst.Blobs, src.Blobs)
	return dst
}

func cloneFuluBlobsBundle(src *builderApiFulu.BlobsBundle) *builderApiFulu.BlobsBundle {
	if src == nil {
		return nil
	}
	dst := &builderApiFulu.BlobsBundle{
		Commitments: make([]deneb.KZGCommitment, len(src.Commitments)),
		Proofs:      make([]deneb.KZGProof, len(src.Proofs)),
		Blobs:       make([]deneb.Blob, len(src.Blobs)),
	}
	copy(dst.Commitments, src.Commitments)
	copy(dst.Proofs, src.Proofs)
	copy(dst.Blobs, src.Blobs)
	return dst
}
