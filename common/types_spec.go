package common

import (
	"fmt"

	builderApi "github.com/attestantio/go-builder-client/api"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiElectra "github.com/attestantio/go-builder-client/api/electra"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/pkg/errors"
)

var (
	errMissingRequest   = errors.New("req is nil")
	errEmptyPayload     = errors.New("empty payload")
	errMissingSecretKey = errors.New("secret key is nil")
	errInvalidVersion   = errors.New("invalid version")
)

func BuildGetHeaderResponse(payload *VersionedSubmitBlockRequest) (*builderSpec.VersionedSignedBuilderBid, error) {
	if payload == nil {
		return nil, errMissingRequest
	}

	versionedPayload := &builderApi.VersionedExecutionPayload{Version: payload.Version}
	switch payload.Version {
	case spec.DataVersionElectra:
		versionedPayload.Electra = payload.Electra.ExecutionPayload
		header, err := utils.PayloadToPayloadHeader(versionedPayload)
		if err != nil {
			return nil, err
		}
		signedBuilderBid, err := BuilderBlockRequestToSignedBuilderBid(payload, header)
		if err != nil {
			return nil, err
		}
		return &builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionElectra,
			Electra: signedBuilderBid.Electra,
		}, nil
	case spec.DataVersionDeneb:
		versionedPayload.Deneb = payload.Deneb.ExecutionPayload
		header, err := utils.PayloadToPayloadHeader(versionedPayload)
		if err != nil {
			return nil, err
		}
		signedBuilderBid, err := BuilderBlockRequestToSignedBuilderBid(payload, header)
		if err != nil {
			return nil, err
		}
		return &builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionDeneb,
			Deneb:   signedBuilderBid.Deneb,
		}, nil
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		return nil, errInvalidVersion
	default:
		return nil, errEmptyPayload
	}
}

func BuilderBlockRequestToSignedBuilderBid(payload *VersionedSubmitBlockRequest, header *builderApi.VersionedExecutionPayloadHeader) (*builderSpec.VersionedSignedBuilderBid, error) {
	value, err := payload.Value()
	if err != nil {
		return nil, err
	}

	builderPubkey, err := payload.Builder()
	if err != nil {
		return nil, err
	}

	signature, err := payload.Signature()
	if err != nil {
		return nil, err
	}

	switch payload.Version {
	case spec.DataVersionElectra:
		builderBid := builderApiElectra.BuilderBid{
			Header:             header.Electra,
			BlobKZGCommitments: payload.Electra.BlobsBundle.Commitments,
			Value:              value,
			Pubkey:             builderPubkey,
			ExecutionRequests:  payload.Electra.ExecutionRequests,
		}

		return &builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionElectra,
			Electra: &builderApiElectra.SignedBuilderBid{
				Message:   &builderBid,
				Signature: signature,
			},
		}, nil
	case spec.DataVersionDeneb:
		builderBid := builderApiDeneb.BuilderBid{
			Header:             header.Deneb,
			BlobKZGCommitments: payload.Deneb.BlobsBundle.Commitments,
			Value:              value,
			Pubkey:             builderPubkey,
		}

		return &builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionDeneb,
			Deneb: &builderApiDeneb.SignedBuilderBid{
				Message:   &builderBid,
				Signature: signature,
			},
		}, nil
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		fallthrough
	default:
		return nil, errors.Wrap(errInvalidVersion, fmt.Sprintf("%s is not supported", payload.Version.String()))
	}
}

func ReSignVersionedSignedBuilderBid(versionedSignedBuilderBid *VersionedSignedBuilderBid, sk *bls.SecretKey, resignPubkey *phase0.BLSPubKey, domain phase0.Domain) (*VersionedSignedBuilderBid, error) {
	if versionedSignedBuilderBid == nil {
		return nil, fmt.Errorf("versioned signed builder bid is nil")
	}
	switch versionedSignedBuilderBid.Version {
	case spec.DataVersionElectra:
		newBuilderBid := versionedSignedBuilderBid.Electra.Message
		newBuilderBid.Pubkey = *resignPubkey
		sig, err := ssz.SignMessage(newBuilderBid, domain, sk)
		if err != nil {
			return nil, err
		}
		resignedVersionedSignedBuilderBid := &VersionedSignedBuilderBid{}
		resignedVersionedSignedBuilderBid.VersionedSignedBuilderBid = builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionElectra,
			Electra: &builderApiElectra.SignedBuilderBid{
				Message:   newBuilderBid,
				Signature: sig,
			},
		}
		return resignedVersionedSignedBuilderBid, nil

	case spec.DataVersionDeneb:
		newBuilderBid := versionedSignedBuilderBid.Deneb.Message
		newBuilderBid.Pubkey = *resignPubkey
		sig, err := ssz.SignMessage(newBuilderBid, domain, sk)
		if err != nil {
			return nil, err
		}
		resignedVersionedSignedBuilderBid := &VersionedSignedBuilderBid{}
		resignedVersionedSignedBuilderBid.VersionedSignedBuilderBid = builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionDeneb,
			Deneb: &builderApiDeneb.SignedBuilderBid{
				Message:   newBuilderBid,
				Signature: sig,
			},
		}
		return resignedVersionedSignedBuilderBid, nil
	default:
		return nil, fmt.Errorf("versioned signed builder bid version is not available")
	}
}

// TODO: refactor to combine the following two functions with the two above
func BuildGetHeaderResponseAndSign(payload *VersionedSubmitBlockRequest, sk *bls.SecretKey, pubkey *phase0.BLSPubKey, domain phase0.Domain) (*builderSpec.VersionedSignedBuilderBid, error) {
	if payload == nil {
		return nil, errMissingRequest
	}

	if sk == nil {
		return nil, errMissingSecretKey
	}

	versionedPayload := &builderApi.VersionedExecutionPayload{Version: payload.Version}
	switch payload.Version {
	case spec.DataVersionElectra:
		versionedPayload.Electra = payload.Electra.ExecutionPayload
		header, err := utils.PayloadToPayloadHeader(versionedPayload)
		if err != nil {
			return nil, err
		}
		signedBuilderBid, err := BuilderBlockRequestToSignedBuilderBidAndSign(payload, header, sk, pubkey, domain)
		if err != nil {
			return nil, err
		}
		return &builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionElectra,
			Electra: signedBuilderBid.Electra,
		}, nil
	case spec.DataVersionDeneb:
		versionedPayload.Deneb = payload.Deneb.ExecutionPayload
		header, err := utils.PayloadToPayloadHeader(versionedPayload)
		if err != nil {
			return nil, err
		}
		signedBuilderBid, err := BuilderBlockRequestToSignedBuilderBidAndSign(payload, header, sk, pubkey, domain)
		if err != nil {
			return nil, err
		}
		return &builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionDeneb,
			Deneb:   signedBuilderBid.Deneb,
		}, nil
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		return nil, errInvalidVersion
	default:
		return nil, errEmptyPayload
	}
}

func BuilderBlockRequestToSignedBuilderBidAndSign(payload *VersionedSubmitBlockRequest, header *builderApi.VersionedExecutionPayloadHeader, sk *bls.SecretKey, pubkey *phase0.BLSPubKey, domain phase0.Domain) (*builderSpec.VersionedSignedBuilderBid, error) {
	value, err := payload.Value()
	if err != nil {
		return nil, err
	}

	switch payload.Version { //nolint:exhaustive
	case spec.DataVersionElectra:
		builderBid := builderApiElectra.BuilderBid{
			Header:             header.Electra,
			BlobKZGCommitments: payload.Electra.BlobsBundle.Commitments,
			Value:              value,
			Pubkey:             *pubkey,
			ExecutionRequests:  payload.Electra.ExecutionRequests,
		}

		sig, err := ssz.SignMessage(&builderBid, domain, sk)
		if err != nil {
			return nil, err
		}

		return &builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionElectra,
			Electra: &builderApiElectra.SignedBuilderBid{
				Message:   &builderBid,
				Signature: sig,
			},
		}, nil
	case spec.DataVersionDeneb:
		builderBid := builderApiDeneb.BuilderBid{
			Header:             header.Deneb,
			BlobKZGCommitments: payload.Deneb.BlobsBundle.Commitments,
			Value:              value,
			Pubkey:             *pubkey,
		}

		sig, err := ssz.SignMessage(&builderBid, domain, sk)
		if err != nil {
			return nil, err
		}

		return &builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionDeneb,
			Deneb: &builderApiDeneb.SignedBuilderBid{
				Message:   &builderBid,
				Signature: sig,
			},
		}, nil
	default:
		return nil, errors.Wrap(errInvalidVersion, fmt.Sprintf("%s is not supported", payload.Version))
	}
}
