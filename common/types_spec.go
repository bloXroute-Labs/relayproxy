package common

import (
	"encoding/json"
	"fmt"

	builderApi "github.com/attestantio/go-builder-client/api"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiElectra "github.com/attestantio/go-builder-client/api/electra"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	eth2Api "github.com/attestantio/go-eth2-client/api"
	eth2ApiV1Electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloXroute-Labs/relay-grpc/optimisticv3"
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

func BuildGetHeaderResponseV3(payload *optimisticv3.HeaderSubmissionV3, sk *bls.SecretKey, pubkey *phase0.BLSPubKey, domain phase0.Domain) (*builderSpec.VersionedSignedBuilderBid, error) {
	if payload == nil {
		return nil, errMissingRequest
	}

	if sk == nil {
		return nil, errMissingSecretKey
	}

	switch payload.Submission.Version {
	case spec.DataVersionDeneb:
		signedBuilderBid, err := BuilderBlockRequestToSignedBuilderBidV3(payload, sk, pubkey, domain)
		if err != nil {
			return nil, err
		}
		return &builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionDeneb,
			Deneb:   signedBuilderBid.Deneb,
		}, nil

	case spec.DataVersionElectra:
		signedBuilderBid, err := BuilderBlockRequestToSignedBuilderBidV3(payload, sk, pubkey, domain)
		if err != nil {
			return nil, err
		}
		return &builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionElectra,
			Electra: signedBuilderBid.Electra,
		}, nil

	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		return nil, ErrInvalidVersion
	default:
		return nil, ErrEmptyPayload
	}
}

func BuilderBlockRequestToSignedBuilderBidOld(payload *VersionedSubmitBlockRequest, header *builderApi.VersionedExecutionPayloadHeader, sk *bls.SecretKey, pubkey *phase0.BLSPubKey, domain phase0.Domain) (*builderSpec.VersionedSignedBuilderBid, error) {
	value, err := payload.Value()
	if err != nil {
		return nil, err
	}

	switch payload.Version { //nolint:exhaustive
	case spec.DataVersionElectra:
		builderBid := builderApiElectra.BuilderBid{
			Header:             header.Electra,
			BlobKZGCommitments: payload.Electra.BlobsBundle.Commitments,
			ExecutionRequests:  payload.Electra.ExecutionRequests,
			Value:              value,
			Pubkey:             *pubkey,
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
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", payload.Version))
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

func BuilderBlockRequestToSignedBuilderBidV3(payload *optimisticv3.HeaderSubmissionV3, sk *bls.SecretKey, pubkey *phase0.BLSPubKey, domain phase0.Domain) (*builderSpec.VersionedSignedBuilderBid, error) {
	bidtrace, err := payload.Submission.BidTrace()
	if err != nil {
		return nil, err
	}
	value := bidtrace.Value
	executionPayloadHeader, err := payload.Submission.ExecutionPayloadHeader()
	if err != nil {
		return nil, err
	}
	commitments, err := payload.Submission.Commitments()
	if err != nil {
		return nil, err
	}

	switch payload.Submission.Version { //nolint:exhaustive
	case spec.DataVersionDeneb:
		builderBid := builderApiDeneb.BuilderBid{
			Header:             executionPayloadHeader,
			BlobKZGCommitments: commitments,
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
	case spec.DataVersionElectra:
		executionRequests, err := payload.Submission.ExecutionRequests()
		if err != nil {
			return nil, err
		}
		builderBid := builderApiElectra.BuilderBid{
			Header:             executionPayloadHeader,
			BlobKZGCommitments: commitments,
			Value:              value,
			Pubkey:             *pubkey,
			ExecutionRequests:  executionRequests,
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

	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", payload.Submission.Version))
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

func BuildHeaderSubmissionV3(payload *VersionedSubmitBlockRequest) (*optimisticv3.HeaderSubmissionV3, error) {
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
		return &optimisticv3.HeaderSubmissionV3{
			URL: []byte{},
			Submission: &optimisticv3.VersionedSignedHeaderSubmission{
				Version: spec.DataVersionElectra,
				Electra: &optimisticv3.SignedHeaderSubmissionElectra{
					Message: optimisticv3.HeaderSubmissionElectra{
						BidTrace:               payload.Electra.Message,
						ExecutionPayloadHeader: header.Electra,
						Commitments:            payload.Electra.BlobsBundle.Commitments,
						ExecutionRequests:      payload.Electra.ExecutionRequests,
					},
				},
			},
		}, nil
	case spec.DataVersionDeneb:
		versionedPayload.Deneb = payload.Deneb.ExecutionPayload
		header, err := utils.PayloadToPayloadHeader(versionedPayload)
		if err != nil {
			return nil, err
		}
		return &optimisticv3.HeaderSubmissionV3{
			URL: []byte{},
			Submission: &optimisticv3.VersionedSignedHeaderSubmission{
				Version: spec.DataVersionDeneb,
				Deneb: &optimisticv3.SignedHeaderSubmissionDeneb{
					Message: optimisticv3.HeaderSubmissionDenebV2{
						BidTrace:               payload.Deneb.Message,
						ExecutionPayloadHeader: header.Deneb,
						Commitments:            payload.Deneb.BlobsBundle.Commitments,
					},
				},
			},
		}, nil
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		return nil, errInvalidVersion
	default:
		return nil, errEmptyPayload
	}
}

func BuildGetHeaderResponseAndSign(headerSubmissionV3 *optimisticv3.HeaderSubmissionV3, sk *bls.SecretKey, pubkey *phase0.BLSPubKey, domain phase0.Domain) (*builderSpec.VersionedSignedBuilderBid, error) {
	if headerSubmissionV3 == nil {
		return nil, errMissingRequest
	}

	if sk == nil {
		return nil, errMissingSecretKey
	}
	signedBuilderBid, err := SignExecutionPayloadHeader(headerSubmissionV3, sk, pubkey, domain)
	if err != nil {
		return nil, err
	}

	switch headerSubmissionV3.Submission.Version {
	case spec.DataVersionElectra:
		return &builderSpec.VersionedSignedBuilderBid{
			Version: spec.DataVersionElectra,
			Electra: signedBuilderBid.Electra,
		}, nil
	case spec.DataVersionDeneb:
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

func SignExecutionPayloadHeader(headerSubmissionV3 *optimisticv3.HeaderSubmissionV3, sk *bls.SecretKey, pubkey *phase0.BLSPubKey, domain phase0.Domain) (*builderSpec.VersionedSignedBuilderBid, error) {
	header := headerSubmissionV3.Submission
	switch header.Version { //nolint:exhaustive
	case spec.DataVersionElectra:
		builderBid := builderApiElectra.BuilderBid{
			Header:             header.Electra.Message.ExecutionPayloadHeader,
			BlobKZGCommitments: header.Electra.Message.Commitments,
			Value:              header.Electra.Message.BidTrace.Value,
			Pubkey:             *pubkey,
			ExecutionRequests:  header.Electra.Message.ExecutionRequests,
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
			Header:             header.Deneb.Message.ExecutionPayloadHeader,
			BlobKZGCommitments: header.Deneb.Message.Commitments,
			Value:              header.Deneb.Message.BidTrace.Value,
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
		return nil, errors.Wrap(errInvalidVersion, fmt.Sprintf("%s is not supported", header.Version))
	}
}
func SignedBlindedBeaconBlockToBeaconBlock(signedBlindedBeaconBlock *VersionedSignedBlindedBeaconBlock, blockPayload *builderApi.VersionedSubmitBlindedBlockResponse) (*VersionedSignedProposal, error) {
	signedBeaconBlock := VersionedSignedProposal{
		eth2Api.VersionedSignedProposal{ //nolint:exhaustruct
			Version: signedBlindedBeaconBlock.Version,
		},
	}
	switch signedBlindedBeaconBlock.Version {
	case spec.DataVersionElectra:
		electraBlindedBlock := signedBlindedBeaconBlock.Electra
		if len(electraBlindedBlock.Message.Body.BlobKZGCommitments) != len(blockPayload.Electra.BlobsBundle.Blobs) {
			return nil, errors.New("number of blinded blobs does not match blobs bundle length")
		}

		signedBeaconBlock.Electra = ElectraUnblindSignedBlock(electraBlindedBlock, blockPayload.Electra)
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", signedBlindedBeaconBlock.Version))
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", signedBlindedBeaconBlock.Version))
	}
	return &signedBeaconBlock, nil
}

func ElectraUnblindSignedBlock(blindedBlock *eth2ApiV1Electra.SignedBlindedBeaconBlock, blockPayload *builderApiDeneb.ExecutionPayloadAndBlobsBundle) *eth2ApiV1Electra.SignedBlockContents {
	return &eth2ApiV1Electra.SignedBlockContents{
		SignedBlock: &electra.SignedBeaconBlock{
			Message: &electra.BeaconBlock{
				Slot:          blindedBlock.Message.Slot,
				ProposerIndex: blindedBlock.Message.ProposerIndex,
				ParentRoot:    blindedBlock.Message.ParentRoot,
				StateRoot:     blindedBlock.Message.StateRoot,
				Body: &electra.BeaconBlockBody{
					RANDAOReveal:          blindedBlock.Message.Body.RANDAOReveal,
					ETH1Data:              blindedBlock.Message.Body.ETH1Data,
					Graffiti:              blindedBlock.Message.Body.Graffiti,
					ProposerSlashings:     blindedBlock.Message.Body.ProposerSlashings,
					AttesterSlashings:     blindedBlock.Message.Body.AttesterSlashings,
					Attestations:          blindedBlock.Message.Body.Attestations,
					Deposits:              blindedBlock.Message.Body.Deposits,
					VoluntaryExits:        blindedBlock.Message.Body.VoluntaryExits,
					SyncAggregate:         blindedBlock.Message.Body.SyncAggregate,
					ExecutionPayload:      blockPayload.ExecutionPayload,
					BLSToExecutionChanges: blindedBlock.Message.Body.BLSToExecutionChanges,
					BlobKZGCommitments:    blindedBlock.Message.Body.BlobKZGCommitments,
					ExecutionRequests:     blindedBlock.Message.Body.ExecutionRequests,
				},
			},
			Signature: blindedBlock.Signature,
		},
		KZGProofs: blockPayload.BlobsBundle.Proofs,
		Blobs:     blockPayload.BlobsBundle.Blobs,
	}
}

type VersionedSignedProposal struct {
	eth2Api.VersionedSignedProposal
}

func (r *VersionedSignedProposal) MarshalSSZ() ([]byte, error) {
	switch r.Version { //nolint:exhaustive
	case spec.DataVersionElectra:
		return r.Electra.MarshalSSZ()
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSignedProposal) UnmarshalSSZ(input []byte) error {
	var err error

	electraRequest := new(eth2ApiV1Electra.SignedBlockContents)
	if err = electraRequest.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionElectra
		r.Electra = electraRequest
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SubmitBlockRequest SSZ")
}

func (r *VersionedSignedProposal) MarshalJSON() ([]byte, error) {
	switch r.Version { //nolint:exhaustive
	case spec.DataVersionElectra:
		return json.Marshal(r.Electra)
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", r.Version))
	}
}

func (r *VersionedSignedProposal) UnmarshalJSON(input []byte) error {
	var err error

	electraContents := new(eth2ApiV1Electra.SignedBlockContents)
	if err = electraContents.UnmarshalJSON(input); err == nil {
		r.Version = spec.DataVersionElectra
		r.Electra = electraContents
		return nil
	}
	return errors.Wrap(err, "failed to unmarshal SignedProposal")
}
