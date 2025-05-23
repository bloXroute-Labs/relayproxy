package common

import (
	"fmt"

	v1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	ssz "github.com/ferranbt/fastssz"
	"github.com/pkg/errors"
)

// MarshalSSZ ssz marshals the HeaderSubmissionV3 object
func (h *HeaderSubmissionV3) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(h)
}

// MarshalSSZTo ssz marshals the HeaderSubmissionV3 object to a target array
func (h *HeaderSubmissionV3) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(12)

	// Offset (0) 'URL'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(h.URL)

	// Field (1) 'TxCount'
	dst = ssz.MarshalUint32(dst, h.TxCount)

	// Offset (2) 'Submission'
	dst = ssz.WriteOffset(dst, offset)

	// Field (0) 'URL'
	if size := len(h.URL); size > 256 {
		err = ssz.ErrBytesLengthFn("HeaderSubmissionV3.URL", size, 256)
		return
	}
	dst = append(dst, h.URL...)

	// Field (2) 'Submission'
	if dst, err = h.Submission.MarshalSSZTo(dst); err != nil {
		return
	}

	return
}

// UnmarshalSSZ ssz unmarshals the HeaderSubmissionV3 object
func (h *HeaderSubmissionV3) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 12 {
		return ssz.ErrSize
	}

	tail := buf
	var o0, o2 uint64

	// Offset (0) 'URL'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}

	if o0 != 12 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (1) 'TxCount'
	h.TxCount = ssz.UnmarshallUint32(buf[4:8])

	// Offset (2) 'Submission'
	if o2 = ssz.ReadOffset(buf[8:12]); o2 > size || o0 > o2 {
		return ssz.ErrOffset
	}

	// Field (0) 'URL'
	{
		buf = tail[o0:o2]
		if len(buf) > 256 {
			return ssz.ErrBytesLength
		}
		if cap(h.URL) == 0 {
			h.URL = make([]byte, 0, len(buf))
		}
		h.URL = append(h.URL, buf...)
	}

	// Field (2) 'Submission'
	{
		buf = tail[o2:]
		if h.Submission == nil {
			h.Submission = new(VersionedSignedHeaderSubmission)
		}
		if err = h.Submission.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the HeaderSubmissionV3 object
func (h *HeaderSubmissionV3) SizeSSZ() (size int) {
	size = 12

	// Field (0) 'URL'
	size += len(h.URL)

	// Field (2) 'Submission'
	if h.Submission == nil {
		h.Submission = new(VersionedSignedHeaderSubmission)
	}
	size += h.Submission.SizeSSZ()

	return
}

// HashTreeRoot ssz hashes the HeaderSubmissionV3 object
func (h *HeaderSubmissionV3) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(h)
}

// HashTreeRootWith ssz hashes the HeaderSubmissionV3 object with a hasher
func (h *HeaderSubmissionV3) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'URL'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(h.URL))
		if byteLen > 256 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(h.URL)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (256+31)/32)
	}

	// Field (1) 'TxCount'
	hh.PutUint32(h.TxCount)

	// Field (2) 'Submission'
	if err = h.Submission.HashTreeRootWith(hh); err != nil {
		return
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the HeaderSubmissionV3 object
func (h *HeaderSubmissionV3) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(h)
}

// MarshalSSZ ssz marshals the VersionedSignedHeaderSubmission object
func (v *VersionedSignedHeaderSubmission) MarshalSSZ() ([]byte, error) {
	switch v.Version { //nolint:exhaustive
	case spec.DataVersionElectra:
		return v.Electra.MarshalSSZ()
	case spec.DataVersionDeneb:
		return v.Deneb.MarshalSSZ()
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", v.Version))
	}
}

// MarshalSSZTo ssz marshals the VersionedSignedHeaderSubmission object to a target array
func (v *VersionedSignedHeaderSubmission) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	switch v.Version { //nolint:exhaustive
	case spec.DataVersionElectra:
		return v.Electra.MarshalSSZTo(buf)
	case spec.DataVersionDeneb:
		return v.Deneb.MarshalSSZTo(buf)
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", v.Version))
	}
}

// UnmarshalSSZ ssz unmarshals the VersionedSignedHeaderSubmission object
func (v *VersionedSignedHeaderSubmission) UnmarshalSSZ(input []byte) error {
	var err error

	electraRequest := new(SignedHeaderSubmissionElectra)
	if err = electraRequest.UnmarshalSSZ(input); err == nil {
		v.Version = spec.DataVersionElectra
		v.Electra = electraRequest
		return nil
	}

	denebRequest := new(SignedHeaderSubmissionDeneb)
	if err = denebRequest.UnmarshalSSZ(input); err == nil {
		v.Version = spec.DataVersionDeneb
		v.Deneb = denebRequest
		return nil
	}

	return errors.Wrap(err, "failed to unmarshal SignedHeaderSubmission SSZ")
}

// SizeSSZ returns the ssz encoded size in bytes for the VersionedSignedHeaderSubmission object
func (v *VersionedSignedHeaderSubmission) SizeSSZ() int {
	switch v.Version { //nolint:exhaustive
	case spec.DataVersionElectra:
		return v.Electra.SizeSSZ()
	case spec.DataVersionDeneb:
		return v.Deneb.SizeSSZ()
	default:
		return 0
	}
}

// HashTreeRoot ssz hashes the VersionedSignedHeaderSubmission object
func (v *VersionedSignedHeaderSubmission) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(v)
}

// HashTreeRootWith ssz hashes the VersionedSignedHeaderSubmission object with a hasher
func (v *VersionedSignedHeaderSubmission) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	switch v.Version { //nolint:exhaustive
	case spec.DataVersionElectra:
		return v.Electra.HashTreeRootWith(hh)
	case spec.DataVersionDeneb:
		return v.Deneb.HashTreeRootWith(hh)
	default:
		return errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", v.Version))
	}
}

// GetTree ssz hashes the VersionedSignedHeaderSubmission object
func (v *VersionedSignedHeaderSubmission) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(v)
}

// MarshalSSZ ssz marshals the SignedHeaderSubmissionDeneb object
func (s *SignedHeaderSubmissionDeneb) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(s)
}

// MarshalSSZTo ssz marshals the SignedHeaderSubmissionDeneb object to a target array
func (s *SignedHeaderSubmissionDeneb) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(100)

	// Offset (0) 'Message'
	dst = ssz.WriteOffset(dst, offset)

	// Field (1) 'Signature'
	dst = append(dst, s.Signature[:]...)

	// Field (0) 'Message'
	if dst, err = s.Message.MarshalSSZTo(dst); err != nil {
		return
	}

	return
}

// UnmarshalSSZ ssz unmarshals the SignedHeaderSubmissionDeneb object
func (s *SignedHeaderSubmissionDeneb) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 100 {
		return ssz.ErrSize
	}

	tail := buf
	var o0 uint64

	// Offset (0) 'Message'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}

	if o0 != 100 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (1) 'Signature'
	copy(s.Signature[:], buf[4:100])

	// Field (0) 'Message'
	{
		buf = tail[o0:]
		if err = s.Message.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the SignedHeaderSubmissionDeneb object
func (s *SignedHeaderSubmissionDeneb) SizeSSZ() (size int) {
	size = 100

	// Field (0) 'Message'
	size += s.Message.SizeSSZ()

	return
}

// HashTreeRoot ssz hashes the SignedHeaderSubmissionDeneb object
func (s *SignedHeaderSubmissionDeneb) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(s)
}

// HashTreeRootWith ssz hashes the SignedHeaderSubmissionDeneb object with a hasher
func (s *SignedHeaderSubmissionDeneb) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Message'
	if err = s.Message.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (1) 'Signature'
	hh.PutBytes(s.Signature[:])

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the SignedHeaderSubmissionDeneb object
func (s *SignedHeaderSubmissionDeneb) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(s)
}

// MarshalSSZ ssz marshals the SignedHeaderSubmissionElectra object
func (s *SignedHeaderSubmissionElectra) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(s)
}

// MarshalSSZTo ssz marshals the SignedHeaderSubmissionElectra object to a target array
func (s *SignedHeaderSubmissionElectra) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(100)

	// Offset (0) 'Message'
	dst = ssz.WriteOffset(dst, offset)

	// Field (1) 'Signature'
	dst = append(dst, s.Signature[:]...)

	// Field (0) 'Message'
	if dst, err = s.Message.MarshalSSZTo(dst); err != nil {
		return
	}

	return
}

// UnmarshalSSZ ssz unmarshals the SignedHeaderSubmissionElectra object
func (s *SignedHeaderSubmissionElectra) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 100 {
		return ssz.ErrSize
	}

	tail := buf
	var o0 uint64

	// Offset (0) 'Message'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}

	if o0 != 100 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (1) 'Signature'
	copy(s.Signature[:], buf[4:100])

	// Field (0) 'Message'
	{
		buf = tail[o0:]
		if err = s.Message.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the SignedHeaderSubmissionElectra object
func (s *SignedHeaderSubmissionElectra) SizeSSZ() (size int) {
	size = 100

	// Field (0) 'Message'
	size += s.Message.SizeSSZ()

	return
}

// HashTreeRoot ssz hashes the SignedHeaderSubmissionElectra object
func (s *SignedHeaderSubmissionElectra) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(s)
}

// HashTreeRootWith ssz hashes the SignedHeaderSubmissionElectra object with a hasher
func (s *SignedHeaderSubmissionElectra) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Message'
	if err = s.Message.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (1) 'Signature'
	hh.PutBytes(s.Signature[:])

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the SignedHeaderSubmissionElectra object
func (s *SignedHeaderSubmissionElectra) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(s)
}

// MarshalSSZ ssz marshals the HeaderSubmissionDenebV2 object
func (h *HeaderSubmissionDenebV2) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(h)
}

// MarshalSSZTo ssz marshals the HeaderSubmissionDenebV2 object to a target array
func (h *HeaderSubmissionDenebV2) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(468)

	// Field (0) 'BidTrace'
	if h.BidTrace == nil {
		h.BidTrace = new(v1.BidTrace)
	}
	if dst, err = h.BidTrace.MarshalSSZTo(dst); err != nil {
		return
	}

	// Offset (1) 'ExecutionPayloadHeader'
	dst = ssz.WriteOffset(dst, offset)
	if h.ExecutionPayloadHeader == nil {
		h.ExecutionPayloadHeader = new(deneb.ExecutionPayloadHeader)
	}
	offset += h.ExecutionPayloadHeader.SizeSSZ()

	// Offset (2) 'Commitments'
	dst = ssz.WriteOffset(dst, offset)

	// Field (1) 'ExecutionPayloadHeader'
	if dst, err = h.ExecutionPayloadHeader.MarshalSSZTo(dst); err != nil {
		return
	}

	// Field (2) 'Commitments'
	if size := len(h.Commitments); size > 4096 {
		err = ssz.ErrListTooBigFn("HeaderSubmissionDenebV2.Commitments", size, 4096)
		return
	}
	for ii := 0; ii < len(h.Commitments); ii++ {
		dst = append(dst, h.Commitments[ii][:]...)
	}

	return
}

// UnmarshalSSZ ssz unmarshals the HeaderSubmissionDenebV2 object
func (h *HeaderSubmissionDenebV2) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 468 {
		return ssz.ErrSize
	}

	tail := buf
	var o1, o2 uint64

	// Field (0) 'BidTrace'
	if h.BidTrace == nil {
		h.BidTrace = new(v1.BidTrace)
	}
	if err = h.BidTrace.UnmarshalSSZ(buf[0:236]); err != nil {
		return err
	}

	// Offset (1) 'ExecutionPayloadHeader'
	if o1 = ssz.ReadOffset(buf[236:240]); o1 > size {
		return ssz.ErrOffset
	}

	if o1 != 244 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (2) 'Commitments'
	if o2 = ssz.ReadOffset(buf[240:244]); o2 > size || o1 > o2 {
		return ssz.ErrOffset
	}

	// Field (1) 'ExecutionPayloadHeader'
	{
		buf = tail[o1:o2]
		if h.ExecutionPayloadHeader == nil {
			h.ExecutionPayloadHeader = new(deneb.ExecutionPayloadHeader)
		}
		if err = h.ExecutionPayloadHeader.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}

	// Field (2) 'Commitments'
	{
		buf = tail[o2:]
		num, err := ssz.DivideInt2(len(buf), 48, 4096)
		if err != nil {
			return err
		}
		h.Commitments = make([]deneb.KZGCommitment, num)
		for ii := 0; ii < num; ii++ {
			copy(h.Commitments[ii][:], buf[ii*48:(ii+1)*48])
		}
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the HeaderSubmissionDenebV2 object
func (h *HeaderSubmissionDenebV2) SizeSSZ() (size int) {
	size = 468

	// Field (1) 'ExecutionPayloadHeader'
	if h.ExecutionPayloadHeader == nil {
		h.ExecutionPayloadHeader = new(deneb.ExecutionPayloadHeader)
	}
	size += h.ExecutionPayloadHeader.SizeSSZ()

	// Field (2) 'Commitments'
	size += len(h.Commitments) * 48

	return
}

// HashTreeRoot ssz hashes the HeaderSubmissionDenebV2 object
func (h *HeaderSubmissionDenebV2) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(h)
}

// HashTreeRootWith ssz hashes the HeaderSubmissionDenebV2 object with a hasher
func (h *HeaderSubmissionDenebV2) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'BidTrace'
	if h.BidTrace == nil {
		h.BidTrace = new(v1.BidTrace)
	}
	if err = h.BidTrace.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (1) 'ExecutionPayloadHeader'
	if err = h.ExecutionPayloadHeader.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (2) 'Commitments'
	{
		if size := len(h.Commitments); size > 4096 {
			err = ssz.ErrListTooBigFn("HeaderSubmissionDenebV2.Commitments", size, 4096)
			return
		}
		subIndx := hh.Index()
		for _, i := range h.Commitments {
			hh.PutBytes(i[:])
		}
		numItems := uint64(len(h.Commitments))
		hh.MerkleizeWithMixin(subIndx, numItems, 4096)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the HeaderSubmissionDenebV2 object
func (h *HeaderSubmissionDenebV2) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(h)
}

// MarshalSSZ ssz marshals the HeaderSubmissionElectra object
func (h *HeaderSubmissionElectra) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(h)
}

// MarshalSSZTo ssz marshals the HeaderSubmissionElectra object to a target array
func (h *HeaderSubmissionElectra) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(472)

	// Field (0) 'BidTrace'
	if h.BidTrace == nil {
		h.BidTrace = new(v1.BidTrace)
	}
	if dst, err = h.BidTrace.MarshalSSZTo(dst); err != nil {
		return
	}

	// Offset (1) 'ExecutionPayloadHeader'
	dst = ssz.WriteOffset(dst, offset)
	if h.ExecutionPayloadHeader == nil {
		h.ExecutionPayloadHeader = new(deneb.ExecutionPayloadHeader)
	}
	offset += h.ExecutionPayloadHeader.SizeSSZ()

	// Offset (2) 'ExecutionRequests'
	dst = ssz.WriteOffset(dst, offset)
	if h.ExecutionRequests == nil {
		h.ExecutionRequests = new(electra.ExecutionRequests)
	}
	offset += h.ExecutionRequests.SizeSSZ()

	// Offset (3) 'Commitments'
	dst = ssz.WriteOffset(dst, offset)

	// Field (1) 'ExecutionPayloadHeader'
	if dst, err = h.ExecutionPayloadHeader.MarshalSSZTo(dst); err != nil {
		return
	}

	// Field (2) 'ExecutionRequests'
	if dst, err = h.ExecutionRequests.MarshalSSZTo(dst); err != nil {
		return
	}

	// Field (3) 'Commitments'
	if size := len(h.Commitments); size > 4096 {
		err = ssz.ErrListTooBigFn("HeaderSubmissionElectra.Commitments", size, 4096)
		return
	}
	for ii := 0; ii < len(h.Commitments); ii++ {
		dst = append(dst, h.Commitments[ii][:]...)
	}

	return
}

// UnmarshalSSZ ssz unmarshals the HeaderSubmissionElectra object
func (h *HeaderSubmissionElectra) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 472 {
		return ssz.ErrSize
	}

	tail := buf
	var o1, o2, o3 uint64

	// Field (0) 'BidTrace'
	if h.BidTrace == nil {
		h.BidTrace = new(v1.BidTrace)
	}
	if err = h.BidTrace.UnmarshalSSZ(buf[0:236]); err != nil {
		return err
	}

	// Offset (1) 'ExecutionPayloadHeader'
	if o1 = ssz.ReadOffset(buf[236:240]); o1 > size {
		return ssz.ErrOffset
	}

	if o1 != 248 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (2) 'ExecutionRequests'
	if o2 = ssz.ReadOffset(buf[240:244]); o2 > size || o1 > o2 {
		return ssz.ErrOffset
	}

	// Offset (3) 'Commitments'
	if o3 = ssz.ReadOffset(buf[244:248]); o3 > size || o2 > o3 {
		return ssz.ErrOffset
	}

	// Field (1) 'ExecutionPayloadHeader'
	{
		buf = tail[o1:o2]
		if h.ExecutionPayloadHeader == nil {
			h.ExecutionPayloadHeader = new(deneb.ExecutionPayloadHeader)
		}
		if err = h.ExecutionPayloadHeader.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}

	// Field (2) 'ExecutionRequests'
	{
		buf = tail[o2:o3]
		if h.ExecutionRequests == nil {
			h.ExecutionRequests = new(electra.ExecutionRequests)
		}
		if err = h.ExecutionRequests.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}

	// Field (3) 'Commitments'
	{
		buf = tail[o3:]
		num, err := ssz.DivideInt2(len(buf), 48, 4096)
		if err != nil {
			return err
		}
		h.Commitments = make([]deneb.KZGCommitment, num)
		for ii := 0; ii < num; ii++ {
			copy(h.Commitments[ii][:], buf[ii*48:(ii+1)*48])
		}
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the HeaderSubmissionElectra object
func (h *HeaderSubmissionElectra) SizeSSZ() (size int) {
	size = 472

	// Field (1) 'ExecutionPayloadHeader'
	if h.ExecutionPayloadHeader == nil {
		h.ExecutionPayloadHeader = new(deneb.ExecutionPayloadHeader)
	}
	size += h.ExecutionPayloadHeader.SizeSSZ()

	// Field (2) 'ExecutionRequests'
	if h.ExecutionRequests == nil {
		h.ExecutionRequests = new(electra.ExecutionRequests)
	}
	size += h.ExecutionRequests.SizeSSZ()

	// Field (3) 'Commitments'
	size += len(h.Commitments) * 48

	return
}

// HashTreeRoot ssz hashes the HeaderSubmissionElectra object
func (h *HeaderSubmissionElectra) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(h)
}

// HashTreeRootWith ssz hashes the HeaderSubmissionElectra object with a hasher
func (h *HeaderSubmissionElectra) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'BidTrace'
	if h.BidTrace == nil {
		h.BidTrace = new(v1.BidTrace)
	}
	if err = h.BidTrace.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (1) 'ExecutionPayloadHeader'
	if err = h.ExecutionPayloadHeader.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (2) 'ExecutionRequests'
	if err = h.ExecutionRequests.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (3) 'Commitments'
	{
		if size := len(h.Commitments); size > 4096 {
			err = ssz.ErrListTooBigFn("HeaderSubmissionElectra.Commitments", size, 4096)
			return
		}
		subIndx := hh.Index()
		for _, i := range h.Commitments {
			hh.PutBytes(i[:])
		}
		numItems := uint64(len(h.Commitments))
		hh.MerkleizeWithMixin(subIndx, numItems, 4096)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the HeaderSubmissionElectra object
func (h *HeaderSubmissionElectra) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(h)
}

// MarshalSSZ ssz marshals the GetPayloadV3 object
func (g *GetPayloadV3) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(g)
}

// MarshalSSZTo ssz marshals the GetPayloadV3 object to a target array
func (g *GetPayloadV3) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf

	// Field (0) 'BlockHash'
	dst = append(dst, g.BlockHash[:]...)

	// Field (1) 'RequestTs'
	dst = ssz.MarshalUint64(dst, g.RequestTs)

	// Field (2) 'RelayPublicKey'
	dst = append(dst, g.RelayPublicKey[:]...)

	return
}

// UnmarshalSSZ ssz unmarshals the GetPayloadV3 object
func (g *GetPayloadV3) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size != 88 {
		return ssz.ErrSize
	}

	// Field (0) 'BlockHash'
	copy(g.BlockHash[:], buf[0:32])

	// Field (1) 'RequestTs'
	g.RequestTs = ssz.UnmarshallUint64(buf[32:40])

	// Field (2) 'RelayPublicKey'
	copy(g.RelayPublicKey[:], buf[40:88])

	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the GetPayloadV3 object
func (g *GetPayloadV3) SizeSSZ() (size int) {
	size = 88
	return
}

// HashTreeRoot ssz hashes the GetPayloadV3 object
func (g *GetPayloadV3) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(g)
}

// HashTreeRootWith ssz hashes the GetPayloadV3 object with a hasher
func (g *GetPayloadV3) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'BlockHash'
	hh.PutBytes(g.BlockHash[:])

	// Field (1) 'RequestTs'
	hh.PutUint64(g.RequestTs)

	// Field (2) 'RelayPublicKey'
	hh.PutBytes(g.RelayPublicKey[:])

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the GetPayloadV3 object
func (g *GetPayloadV3) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(g)
}

// MarshalSSZ ssz marshals the SignedGetPayloadV3 object
func (s *SignedGetPayloadV3) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(s)
}

// MarshalSSZTo ssz marshals the SignedGetPayloadV3 object to a target array
func (s *SignedGetPayloadV3) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf

	// Field (0) 'Message'
	if s.Message == nil {
		s.Message = new(GetPayloadV3)
	}
	if dst, err = s.Message.MarshalSSZTo(dst); err != nil {
		return
	}

	// Field (1) 'Signature'
	dst = append(dst, s.Signature[:]...)

	return
}

// UnmarshalSSZ ssz unmarshals the SignedGetPayloadV3 object
func (s *SignedGetPayloadV3) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size != 184 {
		return ssz.ErrSize
	}

	// Field (0) 'Message'
	if s.Message == nil {
		s.Message = new(GetPayloadV3)
	}
	if err = s.Message.UnmarshalSSZ(buf[0:88]); err != nil {
		return err
	}

	// Field (1) 'Signature'
	copy(s.Signature[:], buf[88:184])

	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the SignedGetPayloadV3 object
func (s *SignedGetPayloadV3) SizeSSZ() (size int) {
	size = 184
	return
}

// HashTreeRoot ssz hashes the SignedGetPayloadV3 object
func (s *SignedGetPayloadV3) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(s)
}

// HashTreeRootWith ssz hashes the SignedGetPayloadV3 object with a hasher
func (s *SignedGetPayloadV3) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Message'
	if s.Message == nil {
		s.Message = new(GetPayloadV3)
	}
	if err = s.Message.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (1) 'Signature'
	hh.PutBytes(s.Signature[:])

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the SignedGetPayloadV3 object
func (s *SignedGetPayloadV3) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(s)
}
