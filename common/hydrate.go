package common // TODO: move to different package?

import (
	apideneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiElectra "github.com/attestantio/go-builder-client/api/electra"
	builderApiFulu "github.com/attestantio/go-builder-client/api/fulu"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloXroute-Labs/relay-grpc/bidadjustment"
)

// Extended models - full structures with standard fields + NewItems
type ElectraHydrationBlobItem struct {
	Proof      deneb.KZGProof      `ssz-size:"48"`
	Commitment deneb.KZGCommitment `ssz-size:"48"`
	Blob       deneb.Blob          `ssz-size:"131072"`
}

type ElectraExtendedBlobsBundle struct {
	Commitments []deneb.KZGCommitment      `ssz-max:"4096"     ssz-size:"?,48"`
	Proofs      []deneb.KZGProof           `ssz-max:"33554432" ssz-size:"?,48"`
	Blobs       []deneb.Blob               `ssz-max:"4096"     ssz-size:"?,131072"`
	NewItems    []ElectraHydrationBlobItem `ssz-max:"4096"     ssz-size:"?,131168"`
}

type ElectraExtendedSubmitBlockRequest struct {
	Message           *apiv1.BidTrace
	ExecutionPayload  *deneb.ExecutionPayload
	BlobsBundle       *ElectraExtendedBlobsBundle
	ExecutionRequests *electra.ExecutionRequests
	Signature         phase0.BLSSignature `ssz-size:"96"`
	AdjustmentData    *bidadjustment.AdjustmentData
}

type FuluHydrationBlobItem struct {
	Proofs     []deneb.KZGProof    `ssz-max:"4096" ssz-size:"?,48"`
	Commitment deneb.KZGCommitment `ssz-size:"48"`
	Blob       deneb.Blob          `ssz-size:"131072"`
}

type FuluExtendedBlobsBundle struct {
	Commitments []deneb.KZGCommitment   `ssz-max:"4096" ssz-size:"?,48"`
	Proofs      []deneb.KZGProof        `ssz-max:"4096" ssz-size:"?,48"`
	Blobs       []deneb.Blob            `ssz-max:"4096" ssz-size:"?,131072"`
	NewItems    []FuluHydrationBlobItem `ssz-max:"4096" ssz-size:"?,131168"`
}

type FuluExtendedSubmitBlockRequest struct {
	Message           *apiv1.BidTrace
	ExecutionPayload  *deneb.ExecutionPayload
	BlobsBundle       *FuluExtendedBlobsBundle
	ExecutionRequests *electra.ExecutionRequests
	Signature         phase0.BLSSignature `ssz-size:"96"`
	AdjustmentData    *bidadjustment.AdjustmentData
}

type VersionedExtendedSubmitBlockRequest struct {
	Version consensusspec.DataVersion
	Deneb   *builderApiDeneb.SubmitBlockRequest // No extension for Deneb
	Electra *ElectraExtendedSubmitBlockRequest
	Fulu    *FuluExtendedSubmitBlockRequest
}

func (r *VersionedExtendedSubmitBlockRequest) UnmarshalJSON(payloadBytes []byte) error {
	// TODO: implement JSON unmarshal if needed
	return nil
}

func (r *VersionedExtendedSubmitBlockRequest) UnmarshalSSZ(payloadBytes []byte) error {
	// TODO: implement SSZ unmarshal if needed
	return nil
}

// ConvertToBuilderSpec converts ExtendedVersionedSubmitBlockRequest to common.VersionedSubmitBlockRequest
// NewItems data is lost in this conversion, AdjustmentData is returned separately
func (e *VersionedExtendedSubmitBlockRequest) ConvertToSpec() (*VersionedSubmitBlockRequest, *bidadjustment.AdjustmentData) {
	result := &VersionedSubmitBlockRequest{
		VersionedSubmitBlockRequest: builderSpec.VersionedSubmitBlockRequest{
			Version: e.Version,
		},
	}

	var adjustmentData *bidadjustment.AdjustmentData

	switch e.Version {
	case consensusspec.DataVersionDeneb:
		result.Deneb = e.Deneb
		// No AdjustmentData for Deneb in extended model

	case consensusspec.DataVersionElectra:
		if e.Electra != nil {
			adjustmentData = e.Electra.AdjustmentData
			result.Electra = &builderApiElectra.SubmitBlockRequest{
				Message:           e.Electra.Message,
				ExecutionPayload:  e.Electra.ExecutionPayload,
				ExecutionRequests: e.Electra.ExecutionRequests,
				Signature:         e.Electra.Signature,
			}
			if e.Electra.BlobsBundle != nil {
				result.Electra.BlobsBundle = &apideneb.BlobsBundle{
					Commitments: e.Electra.BlobsBundle.Commitments,
					Proofs:      e.Electra.BlobsBundle.Proofs,
					Blobs:       e.Electra.BlobsBundle.Blobs,
				}
			}
		}

	case consensusspec.DataVersionFulu:
		if e.Fulu != nil {
			adjustmentData = e.Fulu.AdjustmentData
			result.Fulu = &builderApiFulu.SubmitBlockRequest{
				Message:           e.Fulu.Message,
				ExecutionPayload:  e.Fulu.ExecutionPayload,
				ExecutionRequests: e.Fulu.ExecutionRequests,
				Signature:         e.Fulu.Signature,
			}
			if e.Fulu.BlobsBundle != nil {
				result.Fulu.BlobsBundle = &builderApiFulu.BlobsBundle{
					Commitments: e.Fulu.BlobsBundle.Commitments,
					Proofs:      e.Fulu.BlobsBundle.Proofs,
					Blobs:       e.Fulu.BlobsBundle.Blobs,
				}
			}
		}
	}

	return result, adjustmentData
}
