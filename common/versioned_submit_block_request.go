package common

import (
	"encoding/json"
	"fmt"

	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiElectra "github.com/attestantio/go-builder-client/api/electra"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/pkg/errors"
)

// TODO: import this type from 'bloxroute/mev-boost-relay' repo after it's merged
type VersionedSubmitBlockRequest struct {
	builderSpec.VersionedSubmitBlockRequest
}

func (r *VersionedSubmitBlockRequest) SizeSSZ() int {
	switch r.Version { //nolint:exhaustive
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

	if IsElectra {
		electraRequest := new(builderApiElectra.SubmitBlockRequest)
		if err = electraRequest.UnmarshalSSZ(input); err == nil {
			r.Version = spec.DataVersionElectra
			r.Electra = electraRequest
			return nil
		}
	}
	denebRequest := new(builderApiDeneb.SubmitBlockRequest)
	if err = denebRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebRequest
		return nil
	}

	electraRequest := new(builderApiElectra.SubmitBlockRequest)
	if err = electraRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionElectra
		r.Electra = electraRequest
		return nil
	}

	return errors.Wrap(err, "failed to unmarshal SubmitBlockRequest SSZ")
}

func (r *VersionedSubmitBlockRequest) MarshalJSON() ([]byte, error) {
	switch r.Version { //nolint:exhaustive
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
	if IsElectra {
		electraRequest := new(builderApiElectra.SubmitBlockRequest)
		if err = json.Unmarshal(input, electraRequest); err == nil {
			r.Version = spec.DataVersionElectra
			r.Electra = electraRequest
			return nil
		}
	}
	denebRequest := new(builderApiDeneb.SubmitBlockRequest)
	if err = json.Unmarshal(input, denebRequest); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebRequest
		return nil
	}

	electraRequest := new(builderApiElectra.SubmitBlockRequest)
	if err = json.Unmarshal(input, electraRequest); err == nil {
		r.Version = spec.DataVersionElectra
		r.Electra = electraRequest
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SubmitBlockRequest ")
}
