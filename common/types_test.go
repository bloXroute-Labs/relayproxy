package common

import (
	"math/big"
	"testing"
	"time"

	builderApi "github.com/attestantio/go-builder-client/api"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	v1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func NewDenebBuilderSubmitBlockRequest(builderPubKey phase0.BLSPubKey, blockHash common.Hash, bidValue *big.Int, receiveTime time.Time) *builderApiDeneb.SubmitBlockRequest {
	bidBlockHash := phase0.Hash32(blockHash.Bytes())
	value := new(uint256.Int)
	value.SetFromBig(bidValue)

	return &builderApiDeneb.SubmitBlockRequest{
		Signature: phase0.BLSSignature{},
		Message: &v1.BidTrace{
			Slot:                 0,
			ParentHash:           phase0.Hash32{},
			BlockHash:            bidBlockHash,
			BuilderPubkey:        builderPubKey,
			ProposerPubkey:       phase0.BLSPubKey{},
			ProposerFeeRecipient: bellatrix.ExecutionAddress{},
			GasLimit:             0,
			GasUsed:              0,
			Value:                value,
		},
		ExecutionPayload: &deneb.ExecutionPayload{
			ParentHash:    phase0.Hash32{1},
			FeeRecipient:  bellatrix.ExecutionAddress{2},
			StateRoot:     [32]byte{3},
			ReceiptsRoot:  [32]byte{4},
			LogsBloom:     [256]byte{5},
			PrevRandao:    [32]byte{6},
			BlockNumber:   7,
			GasLimit:      8,
			GasUsed:       9,
			Timestamp:     1,
			ExtraData:     nil,
			BaseFeePerGas: uint256.NewInt(10),
			BlockHash:     (phase0.Hash32)(blockHash),
			Transactions:  nil,
			Withdrawals:   []*capella.Withdrawal{},
		},
		BlobsBundle: &builderApiDeneb.BlobsBundle{},
	}
}

func TestPayloadResponseForProxyType(t *testing.T) {
	submitBlockRequest := NewDenebBuilderSubmitBlockRequest(phase0.BLSPubKey{}, common.Hash{}, big.NewInt(0), time.Now())
	payload := VersionedSubmitBlindedBlockResponse{
		VersionedSubmitBlindedBlockResponse: builderApi.VersionedSubmitBlindedBlockResponse{
			Version: spec.DataVersionDeneb,
			Deneb: &builderApiDeneb.ExecutionPayloadAndBlobsBundle{
				ExecutionPayload: submitBlockRequest.ExecutionPayload,
				BlobsBundle:      submitBlockRequest.BlobsBundle,
			},
		},
	}
	p := &PayloadResponseForProxy{
		PayloadResponse: payload,
	}
	require.Equal(t, len(p.MarshalledPayloadResponse), 0)
	marshalledPayload, err := p.GetMarshalledResponse()
	require.NoError(t, err)
	marshalledPayload2, err := payload.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, marshalledPayload, marshalledPayload2)
	require.True(t, len(p.MarshalledPayloadResponse) > 0)
	require.Equal(t, len(p.MarshalledPayloadResponse), len(marshalledPayload))

	p2 := &PayloadResponseForProxy{
		MarshalledPayloadResponse: marshalledPayload,
	}

	slot := uint64(12)
	parentHash := "34"
	blockHash := "56"
	proposerPubkey := "78"
	versionedPayloadInfo1, err := p.BuildVersionedPayloadInfo(slot, parentHash, blockHash, proposerPubkey)
	require.NoError(t, err)

	versionedPayloadInfo2, err := p2.BuildVersionedPayloadInfo(slot, parentHash, blockHash, proposerPubkey)
	require.NoError(t, err)

	require.Equal(t, versionedPayloadInfo1.Response, versionedPayloadInfo2.Response)
	require.Equal(t, versionedPayloadInfo1.Slot, versionedPayloadInfo2.Slot)
	require.Equal(t, versionedPayloadInfo1.ParentHash, versionedPayloadInfo2.ParentHash)
	require.Equal(t, versionedPayloadInfo1.BlockHash, versionedPayloadInfo2.BlockHash)
	require.Equal(t, versionedPayloadInfo1.Pubkey, versionedPayloadInfo2.Pubkey)

}
