package common

import (
	"math/big"
	"testing"
	"time"

	builderApi "github.com/attestantio/go-builder-client/api"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestPayloadResponseForProxyType(t *testing.T) {
	blockHash := GenerateRandomEthHash()
	builderPubkey := GenerateRandomPublicKey()
	parentHash := GenerateRandomEthHash()
	proposerPubkey := GenerateRandomPublicKey()

	blockValue := big.NewInt(1)
	submitBlockRequest := NewElectraBuilderSubmitBlockRequest(1, proposerPubkey, builderPubkey, parentHash, blockHash, blockValue, bellatrix.ExecutionAddress{27}, []byte{10})

	payload := VersionedSubmitBlindedBlockResponse{
		VersionedSubmitBlindedBlockResponse: builderApi.VersionedSubmitBlindedBlockResponse{
			Version: spec.DataVersionElectra,
			Electra: &builderApiDeneb.ExecutionPayloadAndBlobsBundle{
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
	versionedPayloadInfo1, err := p.BuildVersionedPayloadInfo(slot, parentHash.String(), blockHash.String(), proposerPubkey.String())
	require.NoError(t, err)

	versionedPayloadInfo2, err := p2.BuildVersionedPayloadInfo(slot, parentHash.String(), blockHash.String(), proposerPubkey.String())
	require.NoError(t, err)

	require.Equal(t, versionedPayloadInfo1.Response, versionedPayloadInfo2.Response)
	require.Equal(t, versionedPayloadInfo1.Slot, versionedPayloadInfo2.Slot)
	require.Equal(t, versionedPayloadInfo1.ParentHash, versionedPayloadInfo2.ParentHash)
	require.Equal(t, versionedPayloadInfo1.BlockHash, versionedPayloadInfo2.BlockHash)
	require.Equal(t, versionedPayloadInfo1.Pubkey, versionedPayloadInfo2.Pubkey)

}

func TestCheckElectraEpochFork(t *testing.T) {
	//holesky
	require.False(t, IsElectra)
	mockTime := time.Date(2025, time.February, 24, 21, 55, 0, 0, time.UTC).Add(-1 * time.Second)
	CheckElectraEpochFork(mockTime, 1695902400, 12, 32, ElectraForkEpochHolesky, zerolog.Logger{})
	require.False(t, IsElectra)

	mockTime2 := time.Date(2025, time.February, 24, 21, 55, 0, 0, time.UTC)
	CheckElectraEpochFork(mockTime2, 1695902400, 12, 32, ElectraForkEpochHolesky, zerolog.Logger{})
	require.True(t, mockTime.Before(mockTime2))
	require.True(t, IsElectra)

	mockTime3 := time.Date(2025, time.February, 24, 21, 55, 6, 0, time.UTC)
	CheckElectraEpochFork(mockTime3, 1695902400, 12, 32, ElectraForkEpochHolesky, zerolog.Logger{})
	require.True(t, mockTime2.Before(mockTime3))
	require.True(t, IsElectra)

	mockTime4 := time.Date(2025, time.February, 24, 21, 55, 12, 0, time.UTC).Add(1 * time.Second)
	CheckElectraEpochFork(mockTime4, 1695902400, 12, 32, ElectraForkEpochHolesky, zerolog.Logger{})
	require.True(t, mockTime3.Before(mockTime4))
	require.True(t, IsElectra)
}
