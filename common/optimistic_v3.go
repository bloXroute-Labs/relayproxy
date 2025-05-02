package common

import (
	"errors"

	v1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	relaygrpc "github.com/bloXroute-Labs/relay-grpc"
)

type HeaderSubmissionV3 struct {
	// URL pointing to the builder's server endpoint for retrieving
	// the full block payload if this header is selected.
	URL []byte `json:"url"`
	// The signed header data. Carrying: ExecutionHeader, BidTrace, Signature
	Submission *VersionedSignedHeaderSubmission `json:"submission"`
}

// SignedHeaderSubmission is a placeholder for the actual structure
type VersionedSignedHeaderSubmission struct {
	Version spec.DataVersion
	Deneb   *SignedHeaderSubmissionDeneb   `json:"deneb,omitempty"`
	Electra *SignedHeaderSubmissionElectra `json:"electra,omitempty"`
}
type SignedHeaderSubmissionDeneb struct {
	Message   HeaderSubmissionDenebV2 `json:"message"`
	Signature phase0.BLSSignature     `json:"signature"`
}

type SignedHeaderSubmissionElectra struct {
	Message   HeaderSubmissionElectra `json:"message"`
	Signature phase0.BLSSignature     `json:"signature"`
}

type HeaderSubmissionDenebV2 struct {
	BidTrace               *v1.BidTrace                  `json:"bid_trace"`
	ExecutionPayloadHeader *deneb.ExecutionPayloadHeader `json:"execution_payload_header"`
	Commitments            []deneb.KZGCommitment         `json:"commitments"`
}

type HeaderSubmissionElectra struct {
	BidTrace               *v1.BidTrace                  `json:"bid_trace"`
	ExecutionPayloadHeader *deneb.ExecutionPayloadHeader `json:"execution_payload_header"`
	Commitments            []deneb.KZGCommitment         `json:"commitments"`
	ExecutionRequests      *electra.ExecutionRequests    `json:"execution_requests"`
}

func RelayGrpcHeaderSubmissionToVersioned(header *relaygrpc.StreamHeaderResponse, URL []byte) (*HeaderSubmissionV3, error) {
	if header == nil {
		return nil, errors.New("nil struct")
	}
	if header.BidTrace == nil || header.ExecutionPayloadHeader == nil {
		return nil, errors.New("no bid trace or execution payload header")
	}
	if header.ExecutionRequests != nil {
		if !IsElectra {
			return nil, errors.New("execution requests are only supported in electra")
		}
		electraSubmission, err := relaygrpc.ProtoRequestToElectraHeaderSubmission(header)
		if err != nil {
			return nil, err
		}
		return RelaygrpcElectraHeaderSubmissionToVersioned(electraSubmission, URL), nil
	} else {
		denebSubmission, err := relaygrpc.ProtoRequestToDenebHeaderSubmission(header)
		if err != nil {
			return nil, err
		}
		return RelaygrpcDenebHeaderSubmissionToVersioned(denebSubmission, URL), nil
	}
}
func RelaygrpcDenebHeaderSubmissionToVersioned(grpcSubmission *relaygrpc.SignedHeaderSubmissionDeneb, URL []byte) *HeaderSubmissionV3 {
	submission := &VersionedSignedHeaderSubmission{
		Version: spec.DataVersionDeneb,
		Deneb: &SignedHeaderSubmissionDeneb{
			Message: HeaderSubmissionDenebV2{
				BidTrace:               grpcSubmission.Message.BidTrace,
				ExecutionPayloadHeader: grpcSubmission.Message.ExecutionPayloadHeader,
				Commitments:            grpcSubmission.Message.Commitments,
			},
			Signature: grpcSubmission.Signature,
		},
	}
	return &HeaderSubmissionV3{
		URL:        URL,
		Submission: submission,
	}
}

func RelaygrpcElectraHeaderSubmissionToVersioned(grpcSubmission *relaygrpc.SignedHeaderSubmissionElectra, URL []byte) *HeaderSubmissionV3 {
	submission := &VersionedSignedHeaderSubmission{
		Version: spec.DataVersionElectra,
		Electra: &SignedHeaderSubmissionElectra{
			Message: HeaderSubmissionElectra{
				BidTrace:               grpcSubmission.Message.BidTrace,
				ExecutionPayloadHeader: grpcSubmission.Message.ExecutionPayloadHeader,
				Commitments:            grpcSubmission.Message.Commitments,
				ExecutionRequests:      grpcSubmission.Message.ExecutionRequests,
			},
			Signature: grpcSubmission.Signature,
		},
	}
	return &HeaderSubmissionV3{
		URL:        URL,
		Submission: submission,
	}
}

func (h *VersionedSignedHeaderSubmission) BidTrace() (*v1.BidTrace, error) {
	if h == nil {
		return nil, errors.New("nil struct")
	}
	switch h.Version {
	case spec.DataVersionDeneb:
		if h.Deneb == nil {
			return nil, errors.New("no data")
		}
		return h.Deneb.Message.BidTrace, nil
	case spec.DataVersionElectra:
		if h.Electra == nil {
			return nil, errors.New("no data")
		}
		return h.Electra.Message.BidTrace, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

func (h *VersionedSignedHeaderSubmission) ExecutionPayloadHeader() (*deneb.ExecutionPayloadHeader, error) {
	if h == nil {
		return nil, errors.New("nil struct")
	}
	switch h.Version {
	case spec.DataVersionDeneb:
		if h.Deneb == nil {
			return nil, errors.New("no data")
		}
		return h.Deneb.Message.ExecutionPayloadHeader, nil
	case spec.DataVersionElectra:
		if h.Electra == nil {
			return nil, errors.New("no data")
		}
		return h.Electra.Message.ExecutionPayloadHeader, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

func (h *VersionedSignedHeaderSubmission) Commitments() ([]deneb.KZGCommitment, error) {
	if h == nil {
		return nil, errors.New("nil struct")
	}
	switch h.Version {
	case spec.DataVersionDeneb:
		if h.Deneb == nil {
			return nil, errors.New("no data")
		}
		return h.Deneb.Message.Commitments, nil
	case spec.DataVersionElectra:
		if h.Electra == nil {
			return nil, errors.New("no data")
		}
		return h.Electra.Message.Commitments, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

func (h *VersionedSignedHeaderSubmission) ExecutionRequests() (*electra.ExecutionRequests, error) {
	if h == nil {
		return nil, errors.New("nil struct")
	}
	switch h.Version {
	case spec.DataVersionDeneb:
		return nil, errors.New("no executionRequests in deneb")
	case spec.DataVersionElectra:
		if h.Electra == nil {
			return nil, errors.New("no data")
		}
		return h.Electra.Message.ExecutionRequests, nil
	default:
		return nil, errors.New("unsupported version")
	}
}

func (h *VersionedSignedHeaderSubmission) Signature() (phase0.BLSSignature, error) {
	if h == nil {
		return phase0.BLSSignature{}, errors.New("nil struct")
	}
	switch h.Version {
	case spec.DataVersionDeneb:
		if h.Deneb == nil {
			return phase0.BLSSignature{}, errors.New("no data")
		}
		return h.Deneb.Signature, nil
	case spec.DataVersionElectra:
		if h.Electra == nil {
			return phase0.BLSSignature{}, errors.New("no data")
		}
		return h.Electra.Signature, nil
	default:
		return phase0.BLSSignature{}, errors.New("unsupported version")
	}
}

func (h *VersionedSignedHeaderSubmission) TxRoot() (phase0.Root, error) {
	if h == nil {
		return phase0.Root{}, errors.New("nil struct")
	}
	switch h.Version {
	case spec.DataVersionDeneb:
		if h.Deneb == nil {
			return phase0.Root{}, errors.New("no data")
		}
		return h.Deneb.Message.ExecutionPayloadHeader.TransactionsRoot, nil
	case spec.DataVersionElectra:
		if h.Electra == nil {
			return phase0.Root{}, errors.New("no data")
		}
		return h.Electra.Message.ExecutionPayloadHeader.TransactionsRoot, nil
	default:
		return phase0.Root{}, errors.New("unsupported version")
	}
}

func (h *VersionedSignedHeaderSubmission) WithdrawalsRoot() (phase0.Root, error) {
	if h == nil {
		return phase0.Root{}, errors.New("nil struct")
	}
	switch h.Version {
	case spec.DataVersionDeneb:
		if h.Deneb == nil {
			return phase0.Root{}, errors.New("no data")
		}
		return h.Deneb.Message.ExecutionPayloadHeader.WithdrawalsRoot, nil
	case spec.DataVersionElectra:
		if h.Electra == nil {
			return phase0.Root{}, errors.New("no data")
		}
		return h.Electra.Message.ExecutionPayloadHeader.WithdrawalsRoot, nil
	default:
		return phase0.Root{}, errors.New("unsupported version")
	}
}
