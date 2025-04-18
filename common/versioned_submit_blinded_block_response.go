package common

import (
	"fmt"

	builderApi "github.com/attestantio/go-builder-client/api"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

func BuildGetPayloadResponse(payload *VersionedSubmitBlockRequest) (*builderApi.VersionedSubmitBlindedBlockResponse, error) {
	switch payload.Version {
	case spec.DataVersionElectra:
		return &builderApi.VersionedSubmitBlindedBlockResponse{
			Version: spec.DataVersionElectra,
			Electra: &builderApiDeneb.ExecutionPayloadAndBlobsBundle{
				ExecutionPayload: payload.Electra.ExecutionPayload,
				BlobsBundle:      payload.Electra.BlobsBundle,
			},
		}, nil

	case spec.DataVersionDeneb:
		return &builderApi.VersionedSubmitBlindedBlockResponse{
			Version: spec.DataVersionDeneb,
			Deneb: &builderApiDeneb.ExecutionPayloadAndBlobsBundle{
				ExecutionPayload: payload.Deneb.ExecutionPayload,
				BlobsBundle:      payload.Deneb.BlobsBundle,
			},
		}, nil
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		return nil, ErrInvalidVersion
	}
	return nil, ErrEmptyPayload
}

// VersionedSubmitBlindedBlockResponse represents a getPayload response (replaces old GetPayloadResponse)
type VersionedSubmitBlindedBlockResponse struct {
	builderApi.VersionedSubmitBlindedBlockResponse
}

func (r *VersionedSubmitBlindedBlockResponse) MarshalSSZ() ([]byte, error) {
	switch r.Version {
	case spec.DataVersionElectra:
		return r.Electra.MarshalSSZ()
	case spec.DataVersionDeneb:
		return r.Deneb.MarshalSSZ()
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSubmitBlindedBlockResponse) UnmarshalSSZ(input []byte) error {
	var err error

	if IsElectra {
		electraRequest := new(builderApiDeneb.ExecutionPayloadAndBlobsBundle)
		if err = electraRequest.UnmarshalSSZ(input); err == nil {
			r.Version = spec.DataVersionElectra
			r.Electra = electraRequest
			return nil
		}
	}

	denebRequest := new(builderApiDeneb.ExecutionPayloadAndBlobsBundle)
	if err = denebRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebRequest
		return nil
	}

	electraRequest := new(builderApiDeneb.ExecutionPayloadAndBlobsBundle)
	if err = electraRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionElectra
		r.Electra = electraRequest
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SubmitBlockRequest SSZ")
}

func (r *VersionedSubmitBlindedBlockResponse) BlockNumber() (uint64, error) {
	switch r.Version {
	case spec.DataVersionElectra:
		if r.Electra == nil {
			return 0, errors.New("no data")
		}
		if r.Electra.ExecutionPayload == nil {
			return 0, errors.New("no execution payload")
		}
		return r.Electra.ExecutionPayload.BlockNumber, nil
	case spec.DataVersionDeneb:
		if r.Deneb == nil {
			return 0, errors.New("no data")
		}
		if r.Deneb.ExecutionPayload == nil {
			return 0, errors.New("no execution payload")
		}
		return r.Deneb.ExecutionPayload.BlockNumber, nil
	default:
		return 0, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSubmitBlindedBlockResponse) ExtraData() ([]byte, error) {
	switch r.Version {
	case spec.DataVersionElectra:
		if r.Electra == nil {
			return nil, errors.New("no data")
		}
		if r.Electra.ExecutionPayload == nil {
			return nil, errors.New("no execution payload")
		}
		return r.Electra.ExecutionPayload.ExtraData, nil
	case spec.DataVersionDeneb:
		if r.Deneb == nil {
			return nil, errors.New("no data")
		}
		if r.Deneb.ExecutionPayload == nil {
			return nil, errors.New("no execution payload")
		}
		return r.Deneb.ExecutionPayload.ExtraData, nil
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSubmitBlindedBlockResponse) ParentHash() (phase0.Hash32, error) {
	switch r.Version {
	case spec.DataVersionElectra:
		if r.Electra == nil {
			return phase0.Hash32{}, errors.New("no data")
		}
		if r.Electra.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no execution payload")
		}
		return r.Electra.ExecutionPayload.ParentHash, nil
	case spec.DataVersionDeneb:
		if r.Deneb == nil {
			return phase0.Hash32{}, errors.New("no data")
		}
		if r.Deneb.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no execution payload")
		}
		return r.Deneb.ExecutionPayload.ParentHash, nil
	default:
		return phase0.Hash32{}, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSubmitBlindedBlockResponse) GasUsed() (uint64, error) {
	switch r.Version {
	case spec.DataVersionElectra:
		if r.Electra == nil {
			return 0, errors.New("no data")
		}
		if r.Electra.ExecutionPayload == nil {
			return 0, errors.New("no execution payload")
		}
		return r.Electra.ExecutionPayload.GasUsed, nil
	case spec.DataVersionDeneb:
		if r.Deneb == nil {
			return 0, errors.New("no data")
		}
		if r.Deneb.ExecutionPayload == nil {
			return 0, errors.New("no execution payload")
		}
		return r.Deneb.ExecutionPayload.GasUsed, nil
	default:
		return 0, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSubmitBlindedBlockResponse) GasLimit() (uint64, error) {
	switch r.Version {
	case spec.DataVersionElectra:
		if r.Electra == nil {
			return 0, errors.New("no data")
		}
		if r.Electra.ExecutionPayload == nil {
			return 0, errors.New("no execution payload")
		}
		return r.Electra.ExecutionPayload.GasLimit, nil
	case spec.DataVersionDeneb:
		if r.Deneb == nil {
			return 0, errors.New("no data")
		}
		if r.Deneb.ExecutionPayload == nil {
			return 0, errors.New("no execution payload")
		}
		return r.Deneb.ExecutionPayload.GasLimit, nil
	default:
		return 0, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}
