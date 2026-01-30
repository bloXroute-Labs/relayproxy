package common

import (
	"math/big"
	"testing"

	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	relayGRPC "github.com/bloXroute-Labs/relay-grpc"
	"github.com/bloXroute-Labs/relay-grpc/bidadjustment"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func init() {
	// Set IsFulu to true for tests
	IsFulu = true
}

// TestConvertToSpec_FullFuluBlock tests conversion from VersionedExtendedSubmitBlockRequest to builderSpec
func TestConvertToSpec_FullFuluBlock(t *testing.T) {
	// Create extended request with full blobs
	blockHash := GenerateRandomEthHash()
	builderPubkey := GenerateRandomPublicKey()
	parentHash := GenerateRandomEthHash()
	proposerPubkey := GenerateRandomPublicKey()
	feeRecipient := bellatrix.ExecutionAddress{10, 11, 12}

	commitment1 := deneb.KZGCommitment{}
	commitment1[0] = 0x11
	proof1 := deneb.KZGProof{}
	proof1[0] = 0x22
	blob1 := deneb.Blob{}
	blob1[0] = 0x33

	commitment2 := deneb.KZGCommitment{}
	commitment2[0] = 0x44
	proof2 := deneb.KZGProof{}
	proof2[0] = 0x55
	blob2 := deneb.Blob{}
	blob2[0] = 0x66

	adjustmentData := &bidadjustment.AdjustmentData{
		StateRoot:        [32]byte{0x01},
		TransactionsRoot: [32]byte{0x02},
		BuilderAddress:   [20]byte{0x03},
	}

	extendedRequest := &VersionedExtendedSubmitBlockRequest{
		Version: consensusspec.DataVersionFulu,
		Fulu: &FuluExtendedSubmitBlockRequest{
			Message: &apiv1.BidTrace{
				Slot:                 999,
				ParentHash:           phase0.Hash32(parentHash.Bytes()),
				BlockHash:            phase0.Hash32(blockHash.Bytes()),
				BuilderPubkey:        builderPubkey,
				ProposerPubkey:       proposerPubkey,
				ProposerFeeRecipient: feeRecipient,
				GasLimit:             30000000,
				GasUsed:              15000000,
				Value:                uint256.NewInt(5000000),
			},
			ExecutionPayload: &deneb.ExecutionPayload{
				ParentHash:   phase0.Hash32(parentHash.Bytes()),
				BlockHash:    phase0.Hash32(blockHash.Bytes()),
				FeeRecipient: feeRecipient,
				BlockNumber:  12345,
				GasLimit:     30000000,
				GasUsed:      15000000,
				Timestamp:    1234567890,
				Transactions: []bellatrix.Transaction{{0x01, 0x02}, {0x03, 0x04}},
			},
			BlobsBundle: &FuluExtendedBlobsBundle{
				Commitments: []deneb.KZGCommitment{commitment1, commitment2},
				Proofs:      []deneb.KZGProof{proof1, proof2},
				Blobs:       []deneb.Blob{blob1, blob2},
				NewItems:    []*FuluHydrationBlobItem{}, // Empty NewItems (standard format)
			},
			ExecutionRequests: &electra.ExecutionRequests{
				Deposits:       []*electra.DepositRequest{},
				Withdrawals:    []*electra.WithdrawalRequest{},
				Consolidations: []*electra.ConsolidationRequest{},
			},
			Signature:      phase0.BLSSignature{0x99},
			AdjustmentData: adjustmentData,
		},
	}

	// Convert to spec
	specRequest, err := extendedRequest.ConvertToSpec()
	require.NoError(t, err)
	require.NotNil(t, specRequest)

	// Verify version
	require.Equal(t, consensusspec.DataVersionFulu, specRequest.Version)

	// Verify Fulu block
	require.NotNil(t, specRequest.Fulu)
	require.NotNil(t, specRequest.Fulu.Message)
	require.NotNil(t, specRequest.Fulu.ExecutionPayload)
	require.NotNil(t, specRequest.Fulu.BlobsBundle)
	require.NotNil(t, specRequest.Fulu.ExecutionRequests)

	// Verify Message fields
	require.Equal(t, uint64(999), specRequest.Fulu.Message.Slot)
	require.Equal(t, builderPubkey, specRequest.Fulu.Message.BuilderPubkey)
	require.Equal(t, proposerPubkey, specRequest.Fulu.Message.ProposerPubkey)
	require.Equal(t, phase0.Hash32(blockHash.Bytes()), specRequest.Fulu.Message.BlockHash)
	require.Equal(t, phase0.Hash32(parentHash.Bytes()), specRequest.Fulu.Message.ParentHash)

	// Verify ExecutionPayload fields
	require.Equal(t, uint64(12345), specRequest.Fulu.ExecutionPayload.BlockNumber)
	require.Equal(t, uint64(30000000), specRequest.Fulu.ExecutionPayload.GasLimit)
	require.Equal(t, uint64(15000000), specRequest.Fulu.ExecutionPayload.GasUsed)
	require.Len(t, specRequest.Fulu.ExecutionPayload.Transactions, 2)

	// Verify BlobsBundle - NewItems should be lost in conversion
	require.Len(t, specRequest.Fulu.BlobsBundle.Commitments, 2)
	require.Len(t, specRequest.Fulu.BlobsBundle.Proofs, 2)
	require.Len(t, specRequest.Fulu.BlobsBundle.Blobs, 2)
	require.Equal(t, commitment1, specRequest.Fulu.BlobsBundle.Commitments[0])
	require.Equal(t, commitment2, specRequest.Fulu.BlobsBundle.Commitments[1])
	require.Equal(t, proof1, specRequest.Fulu.BlobsBundle.Proofs[0])
	require.Equal(t, proof2, specRequest.Fulu.BlobsBundle.Proofs[1])
	require.Equal(t, blob1, specRequest.Fulu.BlobsBundle.Blobs[0])
	require.Equal(t, blob2, specRequest.Fulu.BlobsBundle.Blobs[1])

	// Verify Signature
	require.Equal(t, phase0.BLSSignature{0x99}, specRequest.Fulu.Signature)

	// Note: AdjustmentData is returned separately via GetAdjustmentData(), not in the spec request
}

// TestConvertToSpec_NilFuluRequest tests error handling when Fulu is nil
func TestConvertToSpec_NilFuluRequest(t *testing.T) {
	extendedRequest := &VersionedExtendedSubmitBlockRequest{
		Version: consensusspec.DataVersionFulu,
		Fulu:    nil,
	}

	specRequest, err := extendedRequest.ConvertToSpec()
	require.Error(t, err)
	require.Nil(t, specRequest)
	require.Contains(t, err.Error(), "fulu request is nil")
}

// TestConvertToSpec_UnsupportedVersion tests error handling for unsupported versions
func TestConvertToSpec_UnsupportedVersion(t *testing.T) {
	extendedRequest := &VersionedExtendedSubmitBlockRequest{
		Version: consensusspec.DataVersionDeneb, // Unsupported
	}

	specRequest, err := extendedRequest.ConvertToSpec()
	require.Error(t, err)
	require.Nil(t, specRequest)
	require.Contains(t, err.Error(), "unsupported version")
}

// TestProtoRequestToVersionedExtendedRequest_StandardFormat tests conversion from gRPC to extended request
func TestProtoRequestToVersionedExtendedRequest_StandardFormat(t *testing.T) {
	// Create gRPC request with standard blobs bundle
	builderPubkey := GenerateRandomPublicKey()
	proposerPubkey := GenerateRandomPublicKey()
	parentHash := GenerateRandomEthHash()
	blockHash := GenerateRandomEthHash()

	tx1 := []byte{0x01, 0x02, 0x03, 0x04}
	tx2 := []byte{0x05, 0x06, 0x07, 0x08}

	commitment1 := make([]byte, kzgCommitmentSize)
	commitment1[0] = 0xAA
	commitment2 := make([]byte, kzgCommitmentSize)
	commitment2[0] = 0xBB

	proof1 := make([]byte, kzgProofSize)
	proof1[0] = 0xCC
	proof2 := make([]byte, kzgProofSize)
	proof2[0] = 0xDD

	blob1 := make([]byte, blobSize)
	blob1[0] = 0xEE
	blob2 := make([]byte, blobSize)
	blob2[0] = 0xFF

	protoRequest := &relayGRPC.SubmitBlockRequest{
		BidTrace: &relayGRPC.BidTrace{
			Slot:                 1000,
			ParentHash:           parentHash.Bytes(),
			BlockHash:            blockHash.Bytes(),
			BuilderPubkey:        builderPubkey[:],
			ProposerPubkey:       proposerPubkey[:],
			ProposerFeeRecipient: []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
			GasLimit:             25000000,
			GasUsed:              12500000,
			Value:                "0x" + big.NewInt(7000000).Text(16),
		},
		ExecutionPayload: &relayGRPC.ExecutionPayload{
			ParentHash:    parentHash.Bytes(),
			StateRoot:     make([]byte, 32),
			ReceiptsRoot:  make([]byte, 32),
			LogsBloom:     make([]byte, 256),
			PrevRandao:    make([]byte, 32),
			BaseFeePerGas: big.NewInt(1000).Bytes(),
			FeeRecipient:  []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
			BlockHash:     blockHash.Bytes(),
			ExtraData:     []byte{0x20, 0x21},
			BlockNumber:   54321,
			GasLimit:      25000000,
			Timestamp:     9876543210,
			GasUsed:       12500000,
			Transactions: []*relayGRPC.CompressTx{
				{RawData: tx1},
				{RawData: tx2},
			},
			Withdrawals:   []*relayGRPC.Withdrawal{},
			BlobGasUsed:   blobSize,
			ExcessBlobGas: 0,
		},
		BlobsBundle: &relayGRPC.BlobsBundle{
			Commitments: [][]byte{commitment1, commitment2},
			Proofs:      [][]byte{proof1, proof2},
			Blobs:       [][]byte{blob1, blob2},
			NewItems:    []*relayGRPC.HydrateBlobItem{}, // Empty for standard format
		},
		ExecutionRequests: &relayGRPC.ExecutionRequests{
			Deposits:       []*relayGRPC.DepositRequest{},
			Withdrawals:    []*relayGRPC.WithdrawalRequest{},
			Consolidations: []*relayGRPC.ConsolidationRequest{},
		},
		Signature:      make([]byte, 96),
		AdjustmentData: []byte{}, // Empty
	}

	// Convert to extended request
	extendedRequest, err := ProtoRequestToVersionedExtendedRequest(protoRequest)
	require.NoError(t, err)
	require.NotNil(t, extendedRequest)

	// Verify version
	require.Equal(t, consensusspec.DataVersionFulu, extendedRequest.Version)

	// Verify Fulu block
	require.NotNil(t, extendedRequest.Fulu)
	require.NotNil(t, extendedRequest.Fulu.Message)
	require.NotNil(t, extendedRequest.Fulu.ExecutionPayload)
	require.NotNil(t, extendedRequest.Fulu.BlobsBundle)
	require.NotNil(t, extendedRequest.Fulu.ExecutionRequests)

	// Verify BidTrace conversion
	require.Equal(t, uint64(1000), extendedRequest.Fulu.Message.Slot)
	require.Equal(t, builderPubkey, extendedRequest.Fulu.Message.BuilderPubkey)
	require.Equal(t, proposerPubkey, extendedRequest.Fulu.Message.ProposerPubkey)
	require.Equal(t, uint64(25000000), extendedRequest.Fulu.Message.GasLimit)
	require.Equal(t, uint64(12500000), extendedRequest.Fulu.Message.GasUsed)
	require.Equal(t, uint256.NewInt(7000000), extendedRequest.Fulu.Message.Value)

	// Verify ExecutionPayload conversion
	require.Equal(t, uint64(54321), extendedRequest.Fulu.ExecutionPayload.BlockNumber)
	require.Equal(t, uint64(25000000), extendedRequest.Fulu.ExecutionPayload.GasLimit)
	require.Equal(t, uint64(12500000), extendedRequest.Fulu.ExecutionPayload.GasUsed)
	require.Equal(t, uint64(9876543210), extendedRequest.Fulu.ExecutionPayload.Timestamp)
	require.Len(t, extendedRequest.Fulu.ExecutionPayload.Transactions, 2)
	require.Equal(t, bellatrix.Transaction(tx1), extendedRequest.Fulu.ExecutionPayload.Transactions[0])
	require.Equal(t, bellatrix.Transaction(tx2), extendedRequest.Fulu.ExecutionPayload.Transactions[1])

	// Verify BlobsBundle conversion
	require.Len(t, extendedRequest.Fulu.BlobsBundle.Commitments, 2)
	require.Len(t, extendedRequest.Fulu.BlobsBundle.Proofs, 2)
	require.Len(t, extendedRequest.Fulu.BlobsBundle.Blobs, 2)
	require.Empty(t, extendedRequest.Fulu.BlobsBundle.NewItems)

	// Verify commitment, proof, blob conversions
	var expectedCommitment1, expectedCommitment2 deneb.KZGCommitment
	copy(expectedCommitment1[:], commitment1)
	copy(expectedCommitment2[:], commitment2)
	require.Equal(t, expectedCommitment1, extendedRequest.Fulu.BlobsBundle.Commitments[0])
	require.Equal(t, expectedCommitment2, extendedRequest.Fulu.BlobsBundle.Commitments[1])

	var expectedProof1, expectedProof2 deneb.KZGProof
	copy(expectedProof1[:], proof1)
	copy(expectedProof2[:], proof2)
	require.Equal(t, expectedProof1, extendedRequest.Fulu.BlobsBundle.Proofs[0])
	require.Equal(t, expectedProof2, extendedRequest.Fulu.BlobsBundle.Proofs[1])

	var expectedBlob1, expectedBlob2 deneb.Blob
	copy(expectedBlob1[:], blob1)
	copy(expectedBlob2[:], blob2)
	require.Equal(t, expectedBlob1, extendedRequest.Fulu.BlobsBundle.Blobs[0])
	require.Equal(t, expectedBlob2, extendedRequest.Fulu.BlobsBundle.Blobs[1])

	// Verify AdjustmentData is nil when empty
	require.Nil(t, extendedRequest.Fulu.AdjustmentData)
}

// TestProtoRequestToVersionedExtendedRequest_WithNewItems tests conversion with NewItems for hydration
func TestProtoRequestToVersionedExtendedRequest_WithNewItems(t *testing.T) {
	builderPubkey := GenerateRandomPublicKey()
	proposerPubkey := GenerateRandomPublicKey()
	parentHash := GenerateRandomEthHash()
	blockHash := GenerateRandomEthHash()

	commitment1 := make([]byte, kzgCommitmentSize)
	commitment1[0] = 0x11
	commitment2 := make([]byte, kzgCommitmentSize)
	commitment2[0] = 0x22

	// Create NewItems with proofs arrays
	proof1_1 := make([]byte, kzgProofSize)
	proof1_1[0] = 0x33
	proof1_2 := make([]byte, kzgProofSize)
	proof1_2[0] = 0x44

	proof2_1 := make([]byte, kzgProofSize)
	proof2_1[0] = 0x55

	blob1 := make([]byte, blobSize)
	blob1[0] = 0x66
	blob2 := make([]byte, blobSize)
	blob2[0] = 0x77

	protoRequest := &relayGRPC.SubmitBlockRequest{
		BidTrace: &relayGRPC.BidTrace{
			Slot:                 2000,
			ParentHash:           parentHash.Bytes(),
			BlockHash:            blockHash.Bytes(),
			BuilderPubkey:        builderPubkey[:],
			ProposerPubkey:       proposerPubkey[:],
			ProposerFeeRecipient: make([]byte, 20),
			GasLimit:             30000000,
			GasUsed:              15000000,
			Value:                "0x" + big.NewInt(8000000).Text(16),
		},
		ExecutionPayload: &relayGRPC.ExecutionPayload{
			ParentHash:    parentHash.Bytes(),
			StateRoot:     make([]byte, 32),
			ReceiptsRoot:  make([]byte, 32),
			LogsBloom:     make([]byte, 256),
			PrevRandao:    make([]byte, 32),
			BaseFeePerGas: big.NewInt(2000).Bytes(),
			FeeRecipient:  make([]byte, 20),
			BlockHash:     blockHash.Bytes(),
			ExtraData:     []byte{0x30},
			BlockNumber:   99999,
			GasLimit:      30000000,
			Timestamp:     1111111111,
			GasUsed:       15000000,
			Transactions:  []*relayGRPC.CompressTx{{RawData: []byte{0x88}}},
			Withdrawals:   []*relayGRPC.Withdrawal{},
			BlobGasUsed:   262144,
			ExcessBlobGas: 0,
		},
		BlobsBundle: &relayGRPC.BlobsBundle{
			Commitments: [][]byte{commitment1, commitment2},
			Proofs:      [][]byte{}, // Empty for dehydrated
			Blobs:       [][]byte{}, // Empty for dehydrated
			NewItems: []*relayGRPC.HydrateBlobItem{
				{
					Commitment: commitment1,
					Proofs:     [][]byte{proof1_1, proof1_2},
					Blob:       blob1,
				},
				{
					Commitment: commitment2,
					Proofs:     [][]byte{proof2_1},
					Blob:       blob2,
				},
			},
		},
		ExecutionRequests: &relayGRPC.ExecutionRequests{
			Deposits:       []*relayGRPC.DepositRequest{},
			Withdrawals:    []*relayGRPC.WithdrawalRequest{},
			Consolidations: []*relayGRPC.ConsolidationRequest{},
		},
		Signature:      make([]byte, 96),
		AdjustmentData: []byte{}, // Empty
	}

	// Convert to extended request
	extendedRequest, err := ProtoRequestToVersionedExtendedRequest(protoRequest)
	require.NoError(t, err)
	require.NotNil(t, extendedRequest)

	// Verify BlobsBundle with NewItems
	require.Len(t, extendedRequest.Fulu.BlobsBundle.Commitments, 2)
	require.Empty(t, extendedRequest.Fulu.BlobsBundle.Proofs)
	require.Empty(t, extendedRequest.Fulu.BlobsBundle.Blobs)
	require.Len(t, extendedRequest.Fulu.BlobsBundle.NewItems, 2)

	// Verify NewItems conversion
	item1 := extendedRequest.Fulu.BlobsBundle.NewItems[0]
	var expectedCommitment1 deneb.KZGCommitment
	copy(expectedCommitment1[:], commitment1)
	require.Equal(t, expectedCommitment1, item1.Commitment)
	require.Len(t, item1.Proof, 2)

	var expectedProof1_1, expectedProof1_2 deneb.KZGProof
	copy(expectedProof1_1[:], proof1_1)
	copy(expectedProof1_2[:], proof1_2)
	require.Equal(t, expectedProof1_1, item1.Proof[0])
	require.Equal(t, expectedProof1_2, item1.Proof[1])

	var expectedBlob1 deneb.Blob
	copy(expectedBlob1[:], blob1)
	require.Equal(t, expectedBlob1, item1.Blob)

	item2 := extendedRequest.Fulu.BlobsBundle.NewItems[1]
	var expectedCommitment2 deneb.KZGCommitment
	copy(expectedCommitment2[:], commitment2)
	require.Equal(t, expectedCommitment2, item2.Commitment)
	require.Len(t, item2.Proof, 1)

	var expectedProof2_1 deneb.KZGProof
	copy(expectedProof2_1[:], proof2_1)
	require.Equal(t, expectedProof2_1, item2.Proof[0])

	var expectedBlob2 deneb.Blob
	copy(expectedBlob2[:], blob2)
	require.Equal(t, expectedBlob2, item2.Blob)
}

// TestProtoRequestToVersionedExtendedRequest_WithAdjustmentData tests conversion with AdjustmentData
func TestProtoRequestToVersionedExtendedRequest_WithAdjustmentData(t *testing.T) {
	builderPubkey := GenerateRandomPublicKey()
	proposerPubkey := GenerateRandomPublicKey()
	parentHash := GenerateRandomEthHash()
	blockHash := GenerateRandomEthHash()

	// Create AdjustmentData
	adjustmentData := &bidadjustment.AdjustmentData{
		StateRoot:           [32]byte{0xAA},
		TransactionsRoot:    [32]byte{0xBB},
		ReceiptsRoot:        [32]byte{0xCC},
		BuilderAddress:      [20]byte{0xDD},
		FeeRecipientAddress: [20]byte{0xEE},
		FeePayerAddress:     [20]byte{0xFF},
		BuilderProof:        [][]byte{{0x11}},
		FeeRecipientProof:   [][]byte{{0x22}},
		FeePayerProof:       [][]byte{{0x33}},
		PlaceholderTxProof:  [][]byte{{0x44}},
	}
	adjustmentSSZ, err := adjustmentData.MarshalSSZ()
	require.NoError(t, err)

	protoRequest := &relayGRPC.SubmitBlockRequest{
		BidTrace: &relayGRPC.BidTrace{
			Slot:                 3000,
			ParentHash:           parentHash.Bytes(),
			BlockHash:            blockHash.Bytes(),
			BuilderPubkey:        builderPubkey[:],
			ProposerPubkey:       proposerPubkey[:],
			ProposerFeeRecipient: make([]byte, 20),
			GasLimit:             35000000,
			GasUsed:              17500000,
			Value:                "0x" + big.NewInt(9000000).Text(16),
		},
		ExecutionPayload: &relayGRPC.ExecutionPayload{
			ParentHash:    parentHash.Bytes(),
			StateRoot:     make([]byte, 32),
			ReceiptsRoot:  make([]byte, 32),
			LogsBloom:     make([]byte, 256),
			PrevRandao:    make([]byte, 32),
			BaseFeePerGas: big.NewInt(3000).Bytes(),
			FeeRecipient:  make([]byte, 20),
			BlockHash:     blockHash.Bytes(),
			ExtraData:     []byte{0x40},
			BlockNumber:   88888,
			GasLimit:      35000000,
			Timestamp:     2222222222,
			GasUsed:       17500000,
			Transactions:  []*relayGRPC.CompressTx{{RawData: []byte{0x99}}},
			Withdrawals:   []*relayGRPC.Withdrawal{},
			BlobGasUsed:   blobSize,
			ExcessBlobGas: 0,
		},
		BlobsBundle: &relayGRPC.BlobsBundle{
			Commitments: [][]byte{},
			Proofs:      [][]byte{},
			Blobs:       [][]byte{},
			NewItems:    []*relayGRPC.HydrateBlobItem{},
		},
		ExecutionRequests: &relayGRPC.ExecutionRequests{
			Deposits:       []*relayGRPC.DepositRequest{},
			Withdrawals:    []*relayGRPC.WithdrawalRequest{},
			Consolidations: []*relayGRPC.ConsolidationRequest{},
		},
		Signature:      make([]byte, 96),
		AdjustmentData: adjustmentSSZ,
	}

	// Convert to extended request
	extendedRequest, err := ProtoRequestToVersionedExtendedRequest(protoRequest)
	require.NoError(t, err)
	require.NotNil(t, extendedRequest)

	// Verify AdjustmentData was unmarshaled
	require.NotNil(t, extendedRequest.Fulu.AdjustmentData)
	require.Equal(t, adjustmentData.StateRoot, extendedRequest.Fulu.AdjustmentData.StateRoot)
	require.Equal(t, adjustmentData.TransactionsRoot, extendedRequest.Fulu.AdjustmentData.TransactionsRoot)
	require.Equal(t, adjustmentData.ReceiptsRoot, extendedRequest.Fulu.AdjustmentData.ReceiptsRoot)
	require.Equal(t, adjustmentData.BuilderAddress, extendedRequest.Fulu.AdjustmentData.BuilderAddress)
	require.Equal(t, adjustmentData.FeeRecipientAddress, extendedRequest.Fulu.AdjustmentData.FeeRecipientAddress)
	require.Equal(t, adjustmentData.FeePayerAddress, extendedRequest.Fulu.AdjustmentData.FeePayerAddress)
}

// TestProtoRequestToVersionedExtendedRequest_InvalidValue tests error handling for invalid bid value
func TestProtoRequestToVersionedExtendedRequest_InvalidValue(t *testing.T) {
	builderPubkey := GenerateRandomPublicKey()
	proposerPubkey := GenerateRandomPublicKey()

	protoRequest := &relayGRPC.SubmitBlockRequest{
		BidTrace: &relayGRPC.BidTrace{
			Slot:                 4000,
			ParentHash:           make([]byte, 32),
			BlockHash:            make([]byte, 32),
			BuilderPubkey:        builderPubkey[:],
			ProposerPubkey:       proposerPubkey[:],
			ProposerFeeRecipient: make([]byte, 20),
			GasLimit:             30000000,
			GasUsed:              15000000,
			Value:                "invalid-hex-value", // Invalid
		},
		ExecutionPayload: &relayGRPC.ExecutionPayload{
			ParentHash:    make([]byte, 32),
			StateRoot:     make([]byte, 32),
			ReceiptsRoot:  make([]byte, 32),
			LogsBloom:     make([]byte, 256),
			PrevRandao:    make([]byte, 32),
			BaseFeePerGas: big.NewInt(1000).Bytes(),
			FeeRecipient:  make([]byte, 20),
			BlockHash:     make([]byte, 32),
			ExtraData:     []byte{},
			BlockNumber:   12345,
			GasLimit:      30000000,
			Timestamp:     1234567890,
			GasUsed:       15000000,
			Transactions:  []*relayGRPC.CompressTx{},
			Withdrawals:   []*relayGRPC.Withdrawal{},
			BlobGasUsed:   0,
			ExcessBlobGas: 0,
		},
		BlobsBundle: &relayGRPC.BlobsBundle{
			Commitments: [][]byte{},
			Proofs:      [][]byte{},
			Blobs:       [][]byte{},
			NewItems:    []*relayGRPC.HydrateBlobItem{},
		},
		ExecutionRequests: &relayGRPC.ExecutionRequests{
			Deposits:       []*relayGRPC.DepositRequest{},
			Withdrawals:    []*relayGRPC.WithdrawalRequest{},
			Consolidations: []*relayGRPC.ConsolidationRequest{},
		},
		Signature:      make([]byte, 96),
		AdjustmentData: []byte{},
	}

	// Convert should fail due to invalid value
	extendedRequest, err := ProtoRequestToVersionedExtendedRequest(protoRequest)
	require.Error(t, err)
	require.Nil(t, extendedRequest)
	require.Contains(t, err.Error(), "failed to convert fulu block value")
}

// TestProtoRequestToVersionedExtendedRequest_InvalidAdjustmentData tests error handling for invalid AdjustmentData
func TestProtoRequestToVersionedExtendedRequest_InvalidAdjustmentData(t *testing.T) {
	builderPubkey := GenerateRandomPublicKey()
	proposerPubkey := GenerateRandomPublicKey()

	protoRequest := &relayGRPC.SubmitBlockRequest{
		BidTrace: &relayGRPC.BidTrace{
			Slot:                 5000,
			ParentHash:           make([]byte, 32),
			BlockHash:            make([]byte, 32),
			BuilderPubkey:        builderPubkey[:],
			ProposerPubkey:       proposerPubkey[:],
			ProposerFeeRecipient: make([]byte, 20),
			GasLimit:             30000000,
			GasUsed:              15000000,
			Value:                "0x" + big.NewInt(1000000).Text(16),
		},
		ExecutionPayload: &relayGRPC.ExecutionPayload{
			ParentHash:    make([]byte, 32),
			StateRoot:     make([]byte, 32),
			ReceiptsRoot:  make([]byte, 32),
			LogsBloom:     make([]byte, 256),
			PrevRandao:    make([]byte, 32),
			BaseFeePerGas: big.NewInt(1000).Bytes(),
			FeeRecipient:  make([]byte, 20),
			BlockHash:     make([]byte, 32),
			ExtraData:     []byte{},
			BlockNumber:   12345,
			GasLimit:      30000000,
			Timestamp:     1234567890,
			GasUsed:       15000000,
			Transactions:  []*relayGRPC.CompressTx{},
			Withdrawals:   []*relayGRPC.Withdrawal{},
			BlobGasUsed:   0,
			ExcessBlobGas: 0,
		},
		BlobsBundle: &relayGRPC.BlobsBundle{
			Commitments: [][]byte{},
			Proofs:      [][]byte{},
			Blobs:       [][]byte{},
			NewItems:    []*relayGRPC.HydrateBlobItem{},
		},
		ExecutionRequests: &relayGRPC.ExecutionRequests{
			Deposits:       []*relayGRPC.DepositRequest{},
			Withdrawals:    []*relayGRPC.WithdrawalRequest{},
			Consolidations: []*relayGRPC.ConsolidationRequest{},
		},
		Signature:      make([]byte, 96),
		AdjustmentData: []byte{0x01, 0x02, 0x03}, // Invalid SSZ data
	}

	// Convert should fail due to invalid AdjustmentData
	extendedRequest, err := ProtoRequestToVersionedExtendedRequest(protoRequest)
	require.Error(t, err)
	require.Nil(t, extendedRequest)
	require.Contains(t, err.Error(), "failed to unmarshal adjustment data")
}
