package common

import (
	"fmt"

	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiElectra "github.com/attestantio/go-builder-client/api/electra"
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
	case spec.DataVersionElectra:
		return r.Electra.MarshalSSZ()
	case spec.DataVersionDeneb:
		return r.Deneb.MarshalSSZ()
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSignedBuilderBid) UnmarshalSSZ(input []byte) error {
	var err error
	if IsElectra {
		electraRequest := new(builderApiElectra.SignedBuilderBid)
		if err = electraRequest.UnmarshalSSZ(input); err == nil {
			r.Version = spec.DataVersionElectra
			r.Electra = electraRequest
			return nil
		}
	}
	denebRequest := new(builderApiDeneb.SignedBuilderBid)
	if err = denebRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebRequest
		return nil
	}

	electraRequest := new(builderApiElectra.SignedBuilderBid)
	if err = electraRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionElectra
		r.Electra = electraRequest
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SubmitBlockRequest SSZ")
}

func (r *VersionedSignedBuilderBid) WithdrawalsRoot() (phase0.Root, error) {
	switch r.Version {
	case spec.DataVersionElectra:
		if r.Electra == nil {
			return phase0.Root{}, errors.New("no data")
		}
		if r.Electra.Message == nil {
			return phase0.Root{}, errors.New("no data message")
		}
		if r.Electra.Message.Header == nil {
			return phase0.Root{}, errors.New("no data message header")
		}
		return r.Electra.Message.Header.WithdrawalsRoot, nil
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
	default:
		return phase0.Root{}, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSignedBuilderBid) ExtraData() ([]byte, error) {
	switch r.Version {
	case spec.DataVersionElectra:
		if r.Electra == nil {
			return nil, errors.New("no data")
		}
		if r.Electra.Message == nil {
			return nil, errors.New("no data message")
		}
		if r.Electra.Message.Header == nil {
			return nil, errors.New("no data message header")
		}
		return r.Electra.Message.Header.ExtraData, nil
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
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSignedBuilderBid) Bid() (any, error) {
	switch r.Version {
	case spec.DataVersionElectra:
		return r.Electra, nil
	case spec.DataVersionDeneb:
		return r.Deneb, nil
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}
