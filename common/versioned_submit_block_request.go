package common

import (
	"encoding/json"
	"fmt"

	apideneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiElectra "github.com/attestantio/go-builder-client/api/electra"
	builderApiFulu "github.com/attestantio/go-builder-client/api/fulu"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	ssz "github.com/ferranbt/fastssz"
	"github.com/pkg/errors"
)

// TODO: import this type from 'bloxroute/mev-boost-relay' repo after it's merged
type VersionedSubmitBlockRequest struct {
	builderSpec.VersionedSubmitBlockRequest
}

func (r *VersionedSubmitBlockRequest) SizeSSZ() int {
	switch r.Version { //nolint:exhaustive
	case spec.DataVersionFulu:
		return r.Fulu.SizeSSZ()
	case spec.DataVersionElectra:
		return r.Electra.SizeSSZ()
	case spec.DataVersionDeneb:
		return r.Deneb.SizeSSZ()
	default:
		return 0
	}
}

func (r *VersionedSubmitBlockRequest) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	switch r.Version { //nolint:exhaustive
	case spec.DataVersionFulu:
		return r.Fulu.MarshalSSZTo(buf)
	case spec.DataVersionElectra:
		return r.Electra.MarshalSSZTo(buf)
	case spec.DataVersionDeneb:
		return r.Deneb.MarshalSSZTo(buf)
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSubmitBlockRequest) MarshalSSZ() ([]byte, error) {
	switch r.Version { //nolint:exhaustive
	case spec.DataVersionFulu:
		return r.Fulu.MarshalSSZ()
	case spec.DataVersionElectra:
		return r.Electra.MarshalSSZ()
	case spec.DataVersionDeneb:
		return r.Deneb.MarshalSSZ()
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSubmitBlockRequest) UnmarshalSSZ(input []byte) error {
	var err error

	if IsFulu {
		fuluRequest := new(builderApiFulu.SubmitBlockRequest)
		if err = fuluRequest.UnmarshalSSZ(input); err == nil {
			r.Version = spec.DataVersionFulu
			r.Fulu = fuluRequest
			return nil
		}
	}

	electraRequest := new(builderApiElectra.SubmitBlockRequest)
	if err = UnmarshalSSZFast(electraRequest, input); err == nil {
		r.Version = spec.DataVersionElectra
		r.Electra = electraRequest
		return nil
	}

	denebRequest := new(builderApiDeneb.SubmitBlockRequest)
	if err = denebRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebRequest
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SubmitBlockRequest SSZ")
}

func (r *VersionedSubmitBlockRequest) MarshalJSON() ([]byte, error) {
	switch r.Version { //nolint:exhaustive
	case spec.DataVersionFulu:
		return json.Marshal(r.Fulu)
	case spec.DataVersionElectra:
		return json.Marshal(r.Electra)
	case spec.DataVersionDeneb:
		return json.Marshal(r.Deneb)
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSubmitBlockRequest) UnmarshalJSON(input []byte) error {
	var err error
	if IsFulu {
		fuluRequest := new(builderApiFulu.SubmitBlockRequest)
		if err = json.Unmarshal(input, fuluRequest); err == nil {
			r.Version = spec.DataVersionFulu
			r.Fulu = fuluRequest
			return nil
		}
	}

	electraRequest := new(builderApiElectra.SubmitBlockRequest)
	if err = json.Unmarshal(input, electraRequest); err == nil {
		r.Version = spec.DataVersionElectra
		r.Electra = electraRequest
		return nil
	}

	denebRequest := new(builderApiDeneb.SubmitBlockRequest)
	if err = json.Unmarshal(input, denebRequest); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebRequest
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SubmitBlockRequest ")
}

// ExecutionPayloadExtraData returns the extra data of the payload.
func (r *VersionedSubmitBlockRequest) ExecutionPayloadExtraData() ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil struct")
	}
	switch r.Version {
	case spec.DataVersionFulu:
		if r.Fulu == nil {
			return nil, errors.New("no data")
		}
		if r.Fulu.ExecutionPayload == nil {
			return nil, errors.New("no data execution payload")
		}
		return r.Fulu.ExecutionPayload.ExtraData, nil
	case spec.DataVersionElectra:
		if r.Electra == nil {
			return nil, errors.New("no data")
		}
		if r.Electra.ExecutionPayload == nil {
			return nil, errors.New("no data execution payload")
		}
		return r.Electra.ExecutionPayload.ExtraData, nil
	case spec.DataVersionDeneb:
		if r.Deneb == nil {
			return nil, errors.New("no data")
		}
		if r.Deneb.ExecutionPayload == nil {
			return nil, errors.New("no data execution payload")
		}
		return r.Deneb.ExecutionPayload.ExtraData, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

// ExecutionPayloadLogsBloom returns the logs bloom filter of the payload.
func (r *VersionedSubmitBlockRequest) ExecutionPayloadLogsBloom() ([256]byte, error) {
	if r == nil {
		return [256]byte{}, errors.New("nil struct")
	}
	switch r.Version {
	case spec.DataVersionFulu:
		if r.Fulu == nil {
			return [256]byte{}, errors.New("no data")
		}
		if r.Fulu.ExecutionPayload == nil {
			return [256]byte{}, errors.New("no data execution payload")
		}
		return r.Fulu.ExecutionPayload.LogsBloom, nil

	case spec.DataVersionElectra:
		if r.Electra == nil {
			return [256]byte{}, errors.New("no data")
		}
		if r.Electra.ExecutionPayload == nil {
			return [256]byte{}, errors.New("no data execution payload")
		}
		return r.Electra.ExecutionPayload.LogsBloom, nil

	case spec.DataVersionDeneb:
		if r.Deneb == nil {
			return [256]byte{}, errors.New("no data")
		}
		if r.Deneb.ExecutionPayload == nil {
			return [256]byte{}, errors.New("no data execution payload")
		}
		return r.Deneb.ExecutionPayload.LogsBloom, nil
	default:
		return [256]byte{}, errors.New("unsupported version")
	}
}

// UnmarshalSSZ ssz unmarshals the SubmitBlockRequest object
func UnmarshalSSZFast(s *builderApiElectra.SubmitBlockRequest, buf []byte) error {
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

	// Field (2) 'BlobsBundle'
	{
		buf = tail[o2:o3]
		if s.BlobsBundle == nil {
			s.BlobsBundle = new(apideneb.BlobsBundle)
		}
		if err = UnmarshalBlobsBundleReuse(s.BlobsBundle, buf); err != nil {
			return err
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
	return err
}

func UnmarshalBlobsBundleReuse(b *apideneb.BlobsBundle, buf []byte) error {
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
