package common

import (
	"fmt"
	builderApi "github.com/attestantio/go-builder-client/api"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

func BuildGetPayloadResponse(payload *VersionedSubmitBlockRequest) (*builderApi.VersionedSubmitBlindedBlockResponse, error) {
	switch payload.Version {
	case spec.DataVersionCapella:
		return &builderApi.VersionedSubmitBlindedBlockResponse{
			Version: spec.DataVersionCapella,
			Capella: payload.Capella.ExecutionPayload,
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
		return nil, errInvalidVersion
	}
	return nil, errEmptyPayload
}

// VersionedSubmitBlindedBlockResponse represents a getPayload response (replaces old GetPayloadResponse)
type VersionedSubmitBlindedBlockResponse struct {
	builderApi.VersionedSubmitBlindedBlockResponse
}

func (r *VersionedSubmitBlindedBlockResponse) MarshalSSZ() ([]byte, error) {
	switch r.Version {
	case spec.DataVersionCapella:
		return r.Capella.MarshalSSZ()
	case spec.DataVersionDeneb:
		return r.Deneb.MarshalSSZ()
	default:
		return nil, errors.Wrap(errInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSubmitBlindedBlockResponse) UnmarshalSSZ(input []byte) error {
	var err error

	denebRequest := new(builderApiDeneb.ExecutionPayloadAndBlobsBundle)
	if err = denebRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebRequest
		return nil
	}

	capellaRequest := new(capella.ExecutionPayload)
	if err = capellaRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionCapella
		r.Capella = capellaRequest
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SubmitBlockRequest SSZ")
}

func (r *VersionedSubmitBlindedBlockResponse) BlockNumber() (uint64, error) {
	switch r.Version {
	case spec.DataVersionCapella:
		if r.Capella == nil {
			return 0, errors.New("no data")
		}
		return r.Capella.BlockNumber, nil
	case spec.DataVersionDeneb:
		if r.Deneb == nil {
			return 0, errors.New("no data")
		}
		if r.Deneb.ExecutionPayload == nil {
			return 0, errors.New("no execution payload")
		}
		return r.Deneb.ExecutionPayload.BlockNumber, nil
	default:
		return 0, errors.Wrap(errInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSubmitBlindedBlockResponse) ExtraData() ([]byte, error) {
	switch r.Version {
	case spec.DataVersionCapella:
		if r.Capella == nil {
			return nil, errors.New("no data")
		}
		return r.Capella.ExtraData, nil
	case spec.DataVersionDeneb:
		if r.Deneb == nil {
			return nil, errors.New("no data")
		}
		if r.Deneb.ExecutionPayload == nil {
			return nil, errors.New("no execution payload")
		}
		return r.Deneb.ExecutionPayload.ExtraData, nil
	default:
		return nil, errors.Wrap(errInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSubmitBlindedBlockResponse) ParentHash() (phase0.Hash32, error) {
	switch r.Version {
	case spec.DataVersionCapella:
		if r.Capella == nil {
			return phase0.Hash32{}, errors.New("no data")
		}
		return r.Capella.ParentHash, nil
	case spec.DataVersionDeneb:
		if r.Deneb == nil {
			return phase0.Hash32{}, errors.New("no data")
		}
		if r.Deneb.ExecutionPayload == nil {
			return phase0.Hash32{}, errors.New("no execution payload")
		}
		return r.Deneb.ExecutionPayload.ParentHash, nil
	default:
		return phase0.Hash32{}, errors.Wrap(errInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSubmitBlindedBlockResponse) GasUsed() (uint64, error) {
	switch r.Version {
	case spec.DataVersionCapella:
		if r.Capella == nil {
			return 0, errors.New("no data")
		}
		return r.Capella.GasUsed, nil
	case spec.DataVersionDeneb:
		if r.Deneb == nil {
			return 0, errors.New("no data")
		}
		if r.Deneb.ExecutionPayload == nil {
			return 0, errors.New("no execution payload")
		}
		return r.Deneb.ExecutionPayload.GasUsed, nil
	default:
		return 0, errors.Wrap(errInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSubmitBlindedBlockResponse) GasLimit() (uint64, error) {
	switch r.Version {
	case spec.DataVersionCapella:
		if r.Capella == nil {
			return 0, errors.New("no data")
		}
		return r.Capella.GasLimit, nil
	case spec.DataVersionDeneb:
		if r.Deneb == nil {
			return 0, errors.New("no data")
		}
		if r.Deneb.ExecutionPayload == nil {
			return 0, errors.New("no execution payload")
		}
		return r.Deneb.ExecutionPayload.GasLimit, nil
	default:
		return 0, errors.Wrap(errInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}
