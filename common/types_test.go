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

func TestSafeSplitSemicolonSeparatedCSV(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
		failed   bool
	}{
		{"", []string{}, false},
		{"ip1", []string{"ip1"}, false},
		{"ip1;1", []string{"ip1"}, false},
		{"ip1;2", []string{"ip1", "ip1"}, false},
		{"a,b;2,c", []string{"a", "b", "b", "c"}, false},
		{"a;1;2,b,c", nil, true},
		{"a;,b,c", nil, true},
		{"a;5", []string{"a", "a", "a", "a", "a"}, false},
	}

	for _, test := range tests {
		result, err := SafeSplitSemicolonSeparatedCSV(test.input)
		if test.failed {
			require.Error(t, err)
			require.Nil(t, result)
			continue
		}
		require.NoError(t, err)
		require.Equal(t, test.expected, result)
	}
}

func TestReplaceBid(t *testing.T) {

	oldBid := &Bid{
		Value:      new(big.Int).SetUint64(1000).Bytes(),
		ReceivedAt: time.Now(),
	}

	newBidSoonAndBetter := &Bid{
		Value:      new(big.Int).SetUint64(1100).Bytes(),
		ReceivedAt: time.Now().Add(50 * time.Millisecond),
	}

	newBidSoonAndWorse := &Bid{
		Value:      new(big.Int).SetUint64(900).Bytes(),
		ReceivedAt: time.Now().Add(50 * time.Millisecond),
	}

	newBidMuchLaterAndBetter := &Bid{
		Value:      new(big.Int).SetUint64(1200).Bytes(),
		ReceivedAt: time.Now().Add(200 * time.Millisecond),
	}

	newBidMuchLaterAndWorse := &Bid{
		Value:      new(big.Int).SetUint64(800).Bytes(),
		ReceivedAt: time.Now().Add(200 * time.Millisecond),
	}

	newBidEarlierAndWorse := &Bid{
		Value:      new(big.Int).SetUint64(900).Bytes(),
		ReceivedAt: time.Now().Add(-50 * time.Millisecond),
	}

	newBidEarlierAndBetter := &Bid{
		Value:      new(big.Int).SetUint64(1100).Bytes(),
		ReceivedAt: time.Now().Add(-50 * time.Millisecond),
	}

	newBidSoonAndEqual := &Bid{
		Value:      new(big.Int).SetUint64(1000).Bytes(),
		ReceivedAt: time.Now().Add(10 * time.Millisecond),
	}

	newBidSoonAndMinus1 := &Bid{
		Value:      new(big.Int).SetUint64(999).Bytes(),
		ReceivedAt: time.Now().Add(10 * time.Millisecond),
	}
	require.True(t, ReplaceBid(newBidSoonAndBetter, oldBid), "Should replace bid that is better and received soon")
	require.False(t, ReplaceBid(newBidSoonAndWorse, oldBid), "Should not replace bid that is worse and received soon")
	require.True(t, ReplaceBid(newBidMuchLaterAndBetter, oldBid), "Should replace bid that is better and received much later")
	require.True(t, ReplaceBid(newBidMuchLaterAndWorse, oldBid), "Should replace bid that is worse and received much later")

	require.False(t, ReplaceBid(newBidEarlierAndWorse, oldBid), "Should not replace bid that is worse and received earlier")
	require.False(t, ReplaceBid(newBidEarlierAndBetter, oldBid), "Should replace bid that is better and received earlier")

	require.True(t, ReplaceBid(newBidSoonAndEqual, oldBid), "Should replace bid that is equal in value and received soon")
	require.False(t, ReplaceBid(newBidSoonAndMinus1, oldBid), "Should not replace bid that is -1 in value and received soon")
}
