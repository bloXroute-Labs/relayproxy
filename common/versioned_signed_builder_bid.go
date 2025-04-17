package common

import (
	"fmt"

	builderApiCapella "github.com/attestantio/go-builder-client/api/capella"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

// TODO: import this type from 'bloxroute/mev-boost-relay' repo after it's merged
type VersionedSignedBuilderBid struct {
	builderSpec.VersionedSignedBuilderBid
}

func (r *VersionedSignedBuilderBid) MarshalSSZ() ([]byte, error) {
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

func (r *VersionedSignedBuilderBid) UnmarshalSSZ(input []byte) error {
	var err error

	denebRequest := new(builderApiDeneb.SignedBuilderBid)
	if err = denebRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebRequest
		return nil
	}

	capellaRequest := new(builderApiCapella.SignedBuilderBid)
	if err = capellaRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionCapella
		r.Capella = capellaRequest
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SubmitBlockRequest SSZ")
}

func (r *VersionedSignedBuilderBid) WithdrawalsRoot() (phase0.Root, error) {
	switch r.Version {
	case spec.DataVersionCapella:
		if r.Capella == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if r.Capella.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if r.Capella.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}
		return r.Capella.Message.Header.WithdrawalsRoot, nil
	case spec.DataVersionDeneb:
		if r.Deneb == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if r.Deneb.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if r.Deneb.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}
		return r.Deneb.Message.Header.WithdrawalsRoot, nil
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		fallthrough
	default:
		return phase0.Root{}, errors.Wrap(errInvalidVersion, fmt.Sprintf("%d is not supported", r.Version))
	}
}

// TODO: delete if we don't end up using
func (r *VersionedSignedBuilderBid) ExtraData() ([]byte, error) {
	switch r.Version {
	case spec.DataVersionCapella:
		if r.Capella == nil {
			return nil, errors.New("no data")
		}
		if r.Capella.Message == nil {
			return nil, errors.New("no data message")
		}
		if r.Capella.Message.Header == nil {
			return nil, errors.New("no data message header")
		}
		return r.Capella.Message.Header.ExtraData, nil
	case spec.DataVersionDeneb:
		if r.Deneb == nil {
			return nil, errors.New("no data")
		}
		if r.Deneb.Message == nil {
			return nil, errors.New("no data message")
		}
		if r.Deneb.Message.Header == nil {
			return nil, errors.New("no data message header")
		}
		return r.Deneb.Message.Header.ExtraData, nil
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		fallthrough
	default:
		return nil, errors.Wrap(errInvalidVersion, fmt.Sprintf("%d is not supported", r.Version))
	}
}

// TODO: delete if we don't end up using
func (r *VersionedSignedBuilderBid) Bid() (any, error) {
	switch r.Version {
	case spec.DataVersionCapella:
		return r.Capella, nil
	case spec.DataVersionDeneb:
		return r.Deneb, nil
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		fallthrough
	default:
		return nil, errors.Wrap(errInvalidVersion, fmt.Sprintf("%d is not supported", r.Version))
	}
}
