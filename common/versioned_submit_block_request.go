package common

import (
	"encoding/json"
	"fmt"

	builderApiCapella "github.com/attestantio/go-builder-client/api/capella"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/pkg/errors"
)

// TODO: import this type from 'bloxroute/mev-boost-relay' repo after it's merged
type VersionedSubmitBlockRequest struct {
	builderSpec.VersionedSubmitBlockRequest
}

func (r *VersionedSubmitBlockRequest) MarshalSSZ() ([]byte, error) {
	switch r.Version {
	case spec.DataVersionCapella:
		return r.Capella.MarshalSSZ()
	case spec.DataVersionDeneb:
		return r.Deneb.MarshalSSZ()
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		fallthrough
	default:
		return nil, errors.Wrap(errInvalidVersion, fmt.Sprintf("%d is not supported", r.Version))
	}
}

func (r *VersionedSubmitBlockRequest) UnmarshalSSZ(input []byte) error {
	var err error

	denebRequest := new(builderApiDeneb.SubmitBlockRequest)
	if err = denebRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebRequest
		return nil
	}

	capellaRequest := new(builderApiCapella.SubmitBlockRequest)
	if err = capellaRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionCapella
		r.Capella = capellaRequest
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SubmitBlockRequest SSZ")
}

// TODO: overriding this JSON method may not be necessary
func (r *VersionedSubmitBlockRequest) MarshalJSON() ([]byte, error) {
	switch r.Version {
	case spec.DataVersionCapella:
		return json.Marshal(r.Capella)
	case spec.DataVersionDeneb:
		return json.Marshal(r.Deneb)
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		fallthrough
	default:
		return nil, errors.Wrap(errInvalidVersion, fmt.Sprintf("%d is not supported", r.Version))
	}
}

// TODO: overriding this JSON method may not be necessary
func (r *VersionedSubmitBlockRequest) UnmarshalJSON(input []byte) error {
	var err error

	denebRequest := new(builderApiDeneb.SubmitBlockRequest)
	if err = json.Unmarshal(input, denebRequest); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebRequest
		return nil
	}

	capellaRequest := new(builderApiCapella.SubmitBlockRequest)
	if err = json.Unmarshal(input, capellaRequest); err == nil {
		r.Version = spec.DataVersionCapella
		r.Capella = capellaRequest
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SubmitBlockRequest")
}
