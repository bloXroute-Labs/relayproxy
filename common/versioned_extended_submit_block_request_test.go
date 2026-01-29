package common

import (
	"encoding/binary"
	"math/big"
	"testing"

	builderApiFulu "github.com/attestantio/go-builder-client/api/fulu"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	relayGRPC "github.com/bloXroute-Labs/relay-grpc"
	"github.com/bloXroute-Labs/relay-grpc/bidadjustment"
	ssz "github.com/ferranbt/fastssz"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func init() {
	// Set IsFulu to true for tests
	IsFulu = true
}

// TestBlockSubmissionSSZFastUnmarshaller_StandardFormat tests unmarshaling of a standard Fulu block
// with full BlobsBundle (Commitments, Proofs, Blobs) and no NewItems (12-byte header)
func TestBlockSubmissionSSZFastUnmarshaller_StandardFormat(t *testing.T) {
	// Setup
	unmarshaller := NewBlockSubmissionSSZFastUnmarshaller()

	// Create a standard Fulu block submission
	blockHash := GenerateRandomEthHash()
	builderPubkey := GenerateRandomPublicKey()
	parentHash := GenerateRandomEthHash()
	proposerPubkey := GenerateRandomPublicKey()
	blockValue := big.NewInt(1000000)
	feeRecipient := bellatrix.ExecutionAddress{1, 2, 3}

	// Create standard request with blobs
	standardRequest := NewFuluBuilderSubmitBlockRequest(
		123, // slot
		proposerPubkey,
		builderPubkey,
		parentHash,
		blockHash,
		blockValue,
		feeRecipient,
		[]byte{0x01, 0x02, 0x03},
	)

	// Add 2 blobs with commitments and proofs
	commitment1 := deneb.KZGCommitment{}
	for i := range commitment1 {
		commitment1[i] = byte(i % 256)
	}
	commitment2 := deneb.KZGCommitment{}
	for i := range commitment2 {
		commitment2[i] = byte((i + 10) % 256)
	}

	proof1 := deneb.KZGProof{}
	for i := range proof1 {
		proof1[i] = byte((i + 20) % 256)
	}
	proof2 := deneb.KZGProof{}
	for i := range proof2 {
		proof2[i] = byte((i + 30) % 256)
	}

	blob1 := deneb.Blob{}
	for i := range blob1 {
		blob1[i] = byte(i % 256)
	}
	blob2 := deneb.Blob{}
	for i := range blob2 {
		blob2[i] = byte((i + 100) % 256)
	}

	standardRequest.BlobsBundle = &builderApiFulu.BlobsBundle{
		Commitments: []deneb.KZGCommitment{commitment1, commitment2},
		Proofs:      []deneb.KZGProof{proof1, proof2},
		Blobs:       []deneb.Blob{blob1, blob2},
	}

	// Marshal to SSZ
	sszData, err := standardRequest.MarshalSSZ()
	require.NoError(t, err)
	require.NotEmpty(t, sszData)

	// Verify this is standard format (no AdjustmentData, 344-byte header)
	require.Greater(t, len(sszData), 344)
	// First offset should point to ExecutionPayload at position 344 (after 236-byte Message + 4 offsets + 96-byte Signature)
	o1 := ssz.ReadOffset(sszData[236:240])
	require.Equal(t, uint64(344), o1, "Standard format should have ExecutionPayload at offset 344")

	// Unmarshal using fast unmarshaller
	result := &VersionedExtendedSubmitBlockRequest{}
	err = unmarshaller.UnmarshalSSZ(sszData, result)
	require.NoError(t, err)

	// Verify the result
	require.NotNil(t, result.Fulu)
	require.NotNil(t, result.Fulu.Message)
	require.NotNil(t, result.Fulu.ExecutionPayload)
	require.NotNil(t, result.Fulu.BlobsBundle)
	require.NotNil(t, result.Fulu.ExecutionRequests)
	require.Nil(t, result.Fulu.AdjustmentData, "Standard format should not have AdjustmentData")

	// Verify Message
	require.Equal(t, uint64(123), result.Fulu.Message.Slot)
	require.Equal(t, proposerPubkey, result.Fulu.Message.ProposerPubkey)
	require.Equal(t, builderPubkey, result.Fulu.Message.BuilderPubkey)

	// Verify BlobsBundle
	require.Len(t, result.Fulu.BlobsBundle.Commitments, 2)
	require.Len(t, result.Fulu.BlobsBundle.Proofs, 2)
	require.Len(t, result.Fulu.BlobsBundle.Blobs, 2)
	require.Empty(t, result.Fulu.BlobsBundle.NewItems, "Standard format should not have NewItems")

	require.Equal(t, commitment1, result.Fulu.BlobsBundle.Commitments[0])
	require.Equal(t, commitment2, result.Fulu.BlobsBundle.Commitments[1])
	require.Equal(t, proof1, result.Fulu.BlobsBundle.Proofs[0])
	require.Equal(t, proof2, result.Fulu.BlobsBundle.Proofs[1])
	require.Equal(t, blob1, result.Fulu.BlobsBundle.Blobs[0])
	require.Equal(t, blob2, result.Fulu.BlobsBundle.Blobs[1])

	// Test cache hit - unmarshal again and verify it uses cached blobs bundle
	result2 := &VersionedExtendedSubmitBlockRequest{}
	err = unmarshaller.UnmarshalSSZ(sszData, result2)
	require.NoError(t, err)

	// Verify cache hit - should be same pointer
	require.True(t, result.Fulu.BlobsBundle == result2.Fulu.BlobsBundle, "Second unmarshal should reuse cached BlobsBundle pointer")
}

// TestBlockSubmissionSSZFastUnmarshaller_DehydratedFormat tests unmarshaling of a dehydrated Fulu block
// with BlobsBundle containing only Commitments and NewItems (8-byte header), no Proofs/Blobs
func TestBlockSubmissionSSZFastUnmarshaller_DehydratedFormat(t *testing.T) {
	// Setup
	unmarshaller := NewBlockSubmissionSSZFastUnmarshaller()

	// Create extended request with dehydrated blobs bundle
	blockHash := GenerateRandomEthHash()
	builderPubkey := GenerateRandomPublicKey()
	parentHash := GenerateRandomEthHash()
	proposerPubkey := GenerateRandomPublicKey()
	blockValue := big.NewInt(2000000)
	feeRecipient := bellatrix.ExecutionAddress{4, 5, 6}

	// Create base request
	baseRequest := NewFuluBuilderSubmitBlockRequest(
		456, // slot
		proposerPubkey,
		builderPubkey,
		parentHash,
		blockHash,
		blockValue,
		feeRecipient,
		[]byte{0x04, 0x05, 0x06},
	)

	// Create dehydrated blobs bundle with NewItems
	commitment1 := deneb.KZGCommitment{}
	for i := range commitment1 {
		commitment1[i] = byte((i + 50) % 256)
	}
	commitment2 := deneb.KZGCommitment{}
	for i := range commitment2 {
		commitment2[i] = byte((i + 60) % 256)
	}

	// Create NewItems with proofs array (maxProofsPerBlob proofs per item)
	newItem1 := FuluHydrationBlobItem{
		Commitment: commitment1,
		Proof:      make([]deneb.KZGProof, maxProofsPerBlob),
		Blob:       deneb.Blob{},
	}
	for i := range newItem1.Proof {
		for j := range newItem1.Proof[i] {
			newItem1.Proof[i][j] = byte((i + j) % 256)
		}
	}
	for i := range newItem1.Blob {
		newItem1.Blob[i] = byte((i + 200) % 256)
	}

	newItem2 := FuluHydrationBlobItem{
		Commitment: commitment2,
		Proof:      make([]deneb.KZGProof, maxProofsPerBlob),
		Blob:       deneb.Blob{},
	}
	for i := range newItem2.Proof {
		for j := range newItem2.Proof[i] {
			newItem2.Proof[i][j] = byte((i + j + 50) % 256)
		}
	}
	for i := range newItem2.Blob {
		newItem2.Blob[i] = byte((i + 150) % 256)
	}

	extendedBlobsBundle := &FuluExtendedBlobsBundle{
		Commitments: []deneb.KZGCommitment{commitment1, commitment2},
		Proofs:      []deneb.KZGProof{}, // Empty for dehydrated
		Blobs:       []deneb.Blob{},     // Empty for dehydrated
		NewItems:    []*FuluHydrationBlobItem{&newItem1, &newItem2},
	}

	// Manually construct SSZ for dehydrated format
	// We need to build the full request SSZ with dehydrated blobs bundle

	// First, marshal the components
	messageSSZ, err := baseRequest.Message.MarshalSSZ()
	require.NoError(t, err)
	require.Equal(t, 236, len(messageSSZ))

	execPayloadSSZ, err := baseRequest.ExecutionPayload.MarshalSSZ()
	require.NoError(t, err)

	execRequestsSSZ, err := baseRequest.ExecutionRequests.MarshalSSZ()
	require.NoError(t, err)

	// Marshal dehydrated blobs bundle
	blobsBundleSSZ := marshalDehydratedBlobsBundle(t, extendedBlobsBundle)

	// Debug: print sizes
	t.Logf("BlobsBundle SSZ size: %d", len(blobsBundleSSZ))
	t.Logf("ExecPayload SSZ size: %d", len(execPayloadSSZ))
	t.Logf("ExecRequests SSZ size: %d", len(execRequestsSSZ))

	// Build the full SSZ structure (344-byte header for standard, no AdjustmentData)
	// Layout: Message(236) + 3 offsets(12) + Signature(96) + variable data
	totalSize := 236 + 12 + 96 + len(execPayloadSSZ) + len(blobsBundleSSZ) + len(execRequestsSSZ)
	sszData := make([]byte, totalSize)

	// Copy Message (0-236)
	copy(sszData[0:236], messageSSZ)

	// Calculate offsets
	headerEnd := uint64(344) // 236 + 16 + 96
	o1 := headerEnd          // ExecutionPayload starts after header
	o2 := o1 + uint64(len(execPayloadSSZ))
	o3 := o2 + uint64(len(blobsBundleSSZ))

	// Write offsets (236-252)
	binary.LittleEndian.PutUint32(sszData[236:240], uint32(o1))
	binary.LittleEndian.PutUint32(sszData[240:244], uint32(o2))
	binary.LittleEndian.PutUint32(sszData[244:248], uint32(o3))
	// o4 (AdjustmentData) not present in standard format

	t.Logf("Request offsets: o1=%d, o2=%d, o3=%d, total=%d", o1, o2, o3, len(sszData))
	t.Logf("BlobsBundle will be read from [%d:%d] = %d bytes", o2, o3, o3-o2)

	// Copy Signature (248-344)
	copy(sszData[248:344], baseRequest.Signature[:])

	// Copy variable data
	copy(sszData[o1:o2], execPayloadSSZ)
	copy(sszData[o2:o3], blobsBundleSSZ)
	copy(sszData[o3:], execRequestsSSZ)

	// Verify dehydrated format in blobs bundle
	blobsO0 := ssz.ReadOffset(blobsBundleSSZ[0:4])
	require.Equal(t, uint64(8), blobsO0, "Dehydrated format should have 8-byte header")
	blobsO3 := ssz.ReadOffset(blobsBundleSSZ[4:8])
	t.Logf("Blobs bundle o0=%d, o3=%d, total size=%d", blobsO0, blobsO3, len(blobsBundleSSZ))

	// Unmarshal using fast unmarshaller
	result := &VersionedExtendedSubmitBlockRequest{}
	err = unmarshaller.UnmarshalSSZ(sszData, result)
	require.NoError(t, err)

	// Verify the result
	require.NotNil(t, result.Fulu)
	require.NotNil(t, result.Fulu.Message)
	require.NotNil(t, result.Fulu.ExecutionPayload)
	require.NotNil(t, result.Fulu.BlobsBundle)
	require.NotNil(t, result.Fulu.ExecutionRequests)
	require.Nil(t, result.Fulu.AdjustmentData, "No AdjustmentData in this test")

	// Verify Message
	require.Equal(t, uint64(456), result.Fulu.Message.Slot)
	require.Equal(t, proposerPubkey, result.Fulu.Message.ProposerPubkey)
	require.Equal(t, builderPubkey, result.Fulu.Message.BuilderPubkey)

	// Verify BlobsBundle - dehydrated format
	require.Len(t, result.Fulu.BlobsBundle.Commitments, 2)
	require.Empty(t, result.Fulu.BlobsBundle.Proofs, "Dehydrated format should have empty Proofs")
	require.Empty(t, result.Fulu.BlobsBundle.Blobs, "Dehydrated format should have empty Blobs")
	require.Len(t, result.Fulu.BlobsBundle.NewItems, 2, "Dehydrated format should have NewItems")

	require.Equal(t, commitment1, result.Fulu.BlobsBundle.Commitments[0])
	require.Equal(t, commitment2, result.Fulu.BlobsBundle.Commitments[1])

	// Verify NewItems
	require.Equal(t, commitment1, result.Fulu.BlobsBundle.NewItems[0].Commitment)
	require.Equal(t, commitment2, result.Fulu.BlobsBundle.NewItems[1].Commitment)
	require.Len(t, result.Fulu.BlobsBundle.NewItems[0].Proof, maxProofsPerBlob)
	require.Len(t, result.Fulu.BlobsBundle.NewItems[1].Proof, maxProofsPerBlob)
	require.Equal(t, newItem1.Blob, result.Fulu.BlobsBundle.NewItems[0].Blob)
	require.Equal(t, newItem2.Blob, result.Fulu.BlobsBundle.NewItems[1].Blob)

	// Verify proofs match
	for i := 0; i < maxProofsPerBlob; i++ {
		require.Equal(t, newItem1.Proof[i], result.Fulu.BlobsBundle.NewItems[0].Proof[i])
		require.Equal(t, newItem2.Proof[i], result.Fulu.BlobsBundle.NewItems[1].Proof[i])
	}

	// Test cache hit - unmarshal again and verify it uses cached blobs bundle
	result2 := &VersionedExtendedSubmitBlockRequest{}
	err = unmarshaller.UnmarshalSSZ(sszData, result2)
	require.NoError(t, err)

	// Verify cache hit - should be same pointer
	require.True(t, result.Fulu.BlobsBundle == result2.Fulu.BlobsBundle, "Second unmarshal should reuse cached BlobsBundle pointer")
}

// TestBlockSubmissionSSZFastUnmarshaller_WithAdjustmentData tests unmarshaling with AdjustmentData
func TestBlockSubmissionSSZFastUnmarshaller_WithAdjustmentData(t *testing.T) {
	// Setup
	unmarshaller := NewBlockSubmissionSSZFastUnmarshaller()

	blockHash := GenerateRandomEthHash()
	builderPubkey := GenerateRandomPublicKey()
	parentHash := GenerateRandomEthHash()
	proposerPubkey := GenerateRandomPublicKey()
	blockValue := big.NewInt(3000000)
	feeRecipient := bellatrix.ExecutionAddress{7, 8, 9}

	baseRequest := NewFuluBuilderSubmitBlockRequest(
		789, // slot
		proposerPubkey,
		builderPubkey,
		parentHash,
		blockHash,
		blockValue,
		feeRecipient,
		[]byte{0x07, 0x08, 0x09},
	)

	// Add simple blobs
	commitment1 := deneb.KZGCommitment{}
	commitment1[0] = 0xAA
	proof1 := deneb.KZGProof{}
	proof1[0] = 0xBB
	blob1 := deneb.Blob{}
	blob1[0] = 0xCC

	baseRequest.BlobsBundle = &builderApiFulu.BlobsBundle{
		Commitments: []deneb.KZGCommitment{commitment1},
		Proofs:      []deneb.KZGProof{proof1},
		Blobs:       []deneb.Blob{blob1},
	}

	// Create AdjustmentData with proper structure
	adjustmentData := &bidadjustment.AdjustmentData{
		StateRoot:           [32]byte{0x01},
		TransactionsRoot:    [32]byte{0x02},
		ReceiptsRoot:        [32]byte{0x03},
		BuilderAddress:      [20]byte{0x04},
		FeeRecipientAddress: [20]byte{0x05},
		FeePayerAddress:     [20]byte{0x06},
		BuilderProof:        [][]byte{{0x07}},
		FeeRecipientProof:   [][]byte{{0x08}},
		FeePayerProof:       [][]byte{{0x09}},
		PlaceholderTxProof:  [][]byte{{0x0A}},
	}
	adjustmentSSZ, err := adjustmentData.MarshalSSZ()
	require.NoError(t, err)

	// Marshal components
	messageSSZ, err := baseRequest.Message.MarshalSSZ()
	require.NoError(t, err)

	execPayloadSSZ, err := baseRequest.ExecutionPayload.MarshalSSZ()
	require.NoError(t, err)

	blobsBundleSSZ, err := baseRequest.BlobsBundle.MarshalSSZ()
	require.NoError(t, err)

	execRequestsSSZ, err := baseRequest.ExecutionRequests.MarshalSSZ()
	require.NoError(t, err)

	// Build SSZ with AdjustmentData (348-byte header)
	// Layout: Message(236) + 3 offsets(12) + Signature(96) + 1 offset(4) + variable data
	totalSize := 236 + 12 + 96 + 4 + len(execPayloadSSZ) + len(blobsBundleSSZ) + len(execRequestsSSZ) + len(adjustmentSSZ)
	sszData := make([]byte, totalSize)

	copy(sszData[0:236], messageSSZ)

	headerEnd := uint64(348) // 236 + 12 + 96 + 4
	o1 := headerEnd
	o2 := o1 + uint64(len(execPayloadSSZ))
	o3 := o2 + uint64(len(blobsBundleSSZ))
	o5 := o3 + uint64(len(execRequestsSSZ))

	// Write first 3 offsets
	binary.LittleEndian.PutUint32(sszData[236:240], uint32(o1))
	binary.LittleEndian.PutUint32(sszData[240:244], uint32(o2))
	binary.LittleEndian.PutUint32(sszData[244:248], uint32(o3))

	// Signature at [248:344]
	copy(sszData[248:344], baseRequest.Signature[:])

	// AdjustmentData offset at [344:348]
	binary.LittleEndian.PutUint32(sszData[344:348], uint32(o5))

	// Copy variable data
	copy(sszData[o1:o2], execPayloadSSZ)
	copy(sszData[o2:o3], blobsBundleSSZ)
	copy(sszData[o3:o5], execRequestsSSZ)
	copy(sszData[o5:], adjustmentSSZ)

	// Verify o1 indicates AdjustmentData present (>= 348)
	o1Check := ssz.ReadOffset(sszData[236:240])
	require.Equal(t, uint64(348), o1Check, "With AdjustmentData, first offset should be 348")

	// Unmarshal
	result := &VersionedExtendedSubmitBlockRequest{}
	err = unmarshaller.UnmarshalSSZ(sszData, result)
	require.NoError(t, err)

	// Verify AdjustmentData is present
	require.NotNil(t, result.Fulu.AdjustmentData)
	require.Equal(t, adjustmentData.StateRoot, result.Fulu.AdjustmentData.StateRoot)
	require.Equal(t, adjustmentData.TransactionsRoot, result.Fulu.AdjustmentData.TransactionsRoot)
	require.Equal(t, adjustmentData.BuilderAddress, result.Fulu.AdjustmentData.BuilderAddress)

	// Verify other fields
	require.Equal(t, uint64(789), result.Fulu.Message.Slot)
	require.Len(t, result.Fulu.BlobsBundle.Commitments, 1)
}

// marshalDehydratedBlobsBundle manually constructs SSZ for dehydrated blobs bundle
// Format: 8-byte header (2 offsets) + Commitments + NewItems
func marshalDehydratedBlobsBundle(t *testing.T, bundle *FuluExtendedBlobsBundle) []byte {
	require.Empty(t, bundle.Proofs, "Dehydrated bundle should have empty Proofs")
	require.Empty(t, bundle.Blobs, "Dehydrated bundle should have empty Blobs")
	require.NotEmpty(t, bundle.NewItems, "Dehydrated bundle should have NewItems")

	// Calculate sizes
	commitmentsSize := len(bundle.Commitments) * kzgCommitmentSize
	newItemsSize := len(bundle.NewItems) * fuluHydrationItemMaxSize

	// Total size: 8 (header) + commitmentsSize + newItemsSize
	totalSize := 8 + commitmentsSize + newItemsSize
	data := make([]byte, totalSize)

	// Write offsets (8-byte header)
	o0 := uint64(8)                    // Commitments start after 8-byte header
	o3 := o0 + uint64(commitmentsSize) // NewItems start after Commitments

	binary.LittleEndian.PutUint32(data[0:4], uint32(o0))
	binary.LittleEndian.PutUint32(data[4:8], uint32(o3))

	// Write Commitments
	for i, commitment := range bundle.Commitments {
		copy(data[o0+uint64(i*kzgCommitmentSize):o0+uint64((i+1)*kzgCommitmentSize)], commitment[:])
	}

	// Write NewItems
	for i, item := range bundle.NewItems {
		itemSSZ, err := item.MarshalSSZ()
		require.NoError(t, err)
		require.Equal(t, fuluHydrationItemMaxSize, len(itemSSZ))
		copy(data[o3+uint64(i*fuluHydrationItemMaxSize):o3+uint64((i+1)*fuluHydrationItemMaxSize)], itemSSZ)
	}

	return data
}

// MarshalSSZ for HydrateBlobItem
func (item *FuluHydrationBlobItem) MarshalSSZ() ([]byte, error) {
	// Fixed part: offset(4) + Commitment(48) + Blob(131072) = fuluHydrationItemFixedSize
	// Variable part: Proofs = len(Proof)*kzgProofSize
	// Total: fuluHydrationItemFixedSize + len(Proof)*kzgProofSize
	proofsSize := len(item.Proof) * kzgProofSize
	totalSize := fuluHydrationItemFixedSize + proofsSize
	buf := make([]byte, totalSize)

	// Offset for Proof field (points to where variable data starts)
	o0 := uint32(fuluHydrationItemFixedSize)
	binary.LittleEndian.PutUint32(buf[0:4], o0)

	// Commitment at [4:52]
	copy(buf[4:4+kzgCommitmentSize], item.Commitment[:])

	// Blob at [52:fuluHydrationItemFixedSize]
	copy(buf[4+kzgCommitmentSize:fuluHydrationItemFixedSize], item.Blob[:])

	// Proofs at [fuluHydrationItemFixedSize:]
	for i, proof := range item.Proof {
		copy(buf[fuluHydrationItemFixedSize+i*kzgProofSize:fuluHydrationItemFixedSize+(i+1)*kzgProofSize], proof[:])
	}

	return buf, nil
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

// TestBlockSubmissionSSZFastUnmarshaller_WithTxRootOnly tests unmarshaling with only TxRoot=Some (no AdjustmentData)
// Expected offset: 377 (344 + 1 selector + 32 bytes)
func TestBlockSubmissionSSZFastUnmarshaller_WithTxRootOnly(t *testing.T) {
	unmarshaller := NewBlockSubmissionSSZFastUnmarshaller()

	blockHash := GenerateRandomEthHash()
	builderPubkey := GenerateRandomPublicKey()
	parentHash := GenerateRandomEthHash()
	proposerPubkey := GenerateRandomPublicKey()
	blockValue := big.NewInt(5000000)
	feeRecipient := bellatrix.ExecutionAddress{11, 12, 13}

	baseRequest := NewFuluBuilderSubmitBlockRequest(
		999, // slot
		proposerPubkey,
		builderPubkey,
		parentHash,
		blockHash,
		blockValue,
		feeRecipient,
		[]byte{0x11, 0x12, 0x13},
	)

	// Add simple blob
	commitment1 := deneb.KZGCommitment{}
	commitment1[0] = 0xDD
	proof1 := deneb.KZGProof{}
	proof1[0] = 0xEE
	blob1 := deneb.Blob{}
	blob1[0] = 0xFF

	baseRequest.BlobsBundle = &builderApiFulu.BlobsBundle{
		Commitments: []deneb.KZGCommitment{commitment1},
		Proofs:      []deneb.KZGProof{proof1},
		Blobs:       []deneb.Blob{blob1},
	}

	// Marshal components
	messageSSZ, err := baseRequest.Message.MarshalSSZ()
	require.NoError(t, err)

	execPayloadSSZ, err := baseRequest.ExecutionPayload.MarshalSSZ()
	require.NoError(t, err)

	blobsBundleSSZ, err := baseRequest.BlobsBundle.MarshalSSZ()
	require.NoError(t, err)

	execRequestsSSZ, err := baseRequest.ExecutionRequests.MarshalSSZ()
	require.NoError(t, err)

	// Create TxRoot
	txRoot := [32]byte{}
	for i := range txRoot {
		txRoot[i] = byte(i + 50)
	}

	// Build SSZ with TxRoot=Some but no AdjustmentData (377-byte header)
	// Layout: Message(236) + 3 offsets(12) + Signature(96) + TxRoot(1 selector + 32 bytes) + variable data
	totalSize := 236 + 12 + 96 + 33 + len(execPayloadSSZ) + len(blobsBundleSSZ) + len(execRequestsSSZ)
	sszData := make([]byte, totalSize)

	copy(sszData[0:236], messageSSZ)

	headerEnd := uint64(377) // 236 + 12 + 96 + 33
	o1 := headerEnd
	o2 := o1 + uint64(len(execPayloadSSZ))
	o3 := o2 + uint64(len(blobsBundleSSZ))

	// Write 3 offsets
	binary.LittleEndian.PutUint32(sszData[236:240], uint32(o1))
	binary.LittleEndian.PutUint32(sszData[240:244], uint32(o2))
	binary.LittleEndian.PutUint32(sszData[244:248], uint32(o3))

	// Signature at [248:344]
	copy(sszData[248:344], baseRequest.Signature[:])

	// TxRoot at [344:377] - selector byte (1) + 32 bytes
	sszData[344] = 1 // selector = Some
	copy(sszData[345:377], txRoot[:])

	// Copy variable data
	copy(sszData[o1:o2], execPayloadSSZ)
	copy(sszData[o2:o3], blobsBundleSSZ)
	copy(sszData[o3:], execRequestsSSZ)

	// Verify o1 indicates TxRoot=Some present (377)
	o1Check := ssz.ReadOffset(sszData[236:240])
	require.Equal(t, uint64(377), o1Check, "With TxRoot=Some only, first offset should be 377")

	// Unmarshal
	result := &VersionedExtendedSubmitBlockRequest{}
	err = unmarshaller.UnmarshalSSZ(sszData, result)
	require.NoError(t, err)

	// Verify TxRoot is present and correct
	require.NotNil(t, result.Fulu.TxRoot, "TxRoot should not be nil")
	require.Equal(t, txRoot, *result.Fulu.TxRoot)

	// Verify AdjustmentData is nil
	require.Nil(t, result.Fulu.AdjustmentData)

	// Verify other fields
	require.Equal(t, uint64(999), result.Fulu.Message.Slot)
	require.Len(t, result.Fulu.BlobsBundle.Commitments, 1)
}

// TestBlockSubmissionSSZFastUnmarshaller_WithTxRootAndAdjustmentData tests unmarshaling with both TxRoot=Some and AdjustmentData
// Expected offset: 381 (344 + 1 selector + 32 bytes + 4 offset)
func TestBlockSubmissionSSZFastUnmarshaller_WithTxRootAndAdjustmentData(t *testing.T) {
	unmarshaller := NewBlockSubmissionSSZFastUnmarshaller()

	blockHash := GenerateRandomEthHash()
	builderPubkey := GenerateRandomPublicKey()
	parentHash := GenerateRandomEthHash()
	proposerPubkey := GenerateRandomPublicKey()
	blockValue := big.NewInt(7000000)
	feeRecipient := bellatrix.ExecutionAddress{21, 22, 23}

	baseRequest := NewFuluBuilderSubmitBlockRequest(
		1234, // slot
		proposerPubkey,
		builderPubkey,
		parentHash,
		blockHash,
		blockValue,
		feeRecipient,
		[]byte{0x21, 0x22, 0x23},
	)

	// Add simple blob
	commitment1 := deneb.KZGCommitment{}
	commitment1[0] = 0x99
	proof1 := deneb.KZGProof{}
	proof1[0] = 0x88
	blob1 := deneb.Blob{}
	blob1[0] = 0x77

	baseRequest.BlobsBundle = &builderApiFulu.BlobsBundle{
		Commitments: []deneb.KZGCommitment{commitment1},
		Proofs:      []deneb.KZGProof{proof1},
		Blobs:       []deneb.Blob{blob1},
	}

	// Create AdjustmentData
	adjustmentData := &bidadjustment.AdjustmentData{
		StateRoot:           [32]byte{0x11},
		TransactionsRoot:    [32]byte{0x22},
		ReceiptsRoot:        [32]byte{0x33},
		BuilderAddress:      [20]byte{0x44},
		FeeRecipientAddress: [20]byte{0x55},
		FeePayerAddress:     [20]byte{0x66},
		BuilderProof:        [][]byte{{0x77}},
		FeeRecipientProof:   [][]byte{{0x88}},
		FeePayerProof:       [][]byte{{0x99}},
		PlaceholderTxProof:  [][]byte{{0xAA}},
	}
	adjustmentSSZ, err := adjustmentData.MarshalSSZ()
	require.NoError(t, err)

	// Marshal components
	messageSSZ, err := baseRequest.Message.MarshalSSZ()
	require.NoError(t, err)

	execPayloadSSZ, err := baseRequest.ExecutionPayload.MarshalSSZ()
	require.NoError(t, err)

	blobsBundleSSZ, err := baseRequest.BlobsBundle.MarshalSSZ()
	require.NoError(t, err)

	execRequestsSSZ, err := baseRequest.ExecutionRequests.MarshalSSZ()
	require.NoError(t, err)

	// Create TxRoot
	txRoot := [32]byte{}
	for i := range txRoot {
		txRoot[i] = byte(i + 100)
	}

	// Build SSZ with both TxRoot=Some and AdjustmentData (381-byte header)
	// Layout: Message(236) + 3 offsets(12) + Signature(96) + TxRoot(1 selector + 32 bytes) + AdjustmentData offset(4) + variable data
	totalSize := 236 + 12 + 96 + 33 + 4 + len(execPayloadSSZ) + len(blobsBundleSSZ) + len(execRequestsSSZ) + len(adjustmentSSZ)
	sszData := make([]byte, totalSize)

	copy(sszData[0:236], messageSSZ)

	headerEnd := uint64(381) // 236 + 12 + 96 + 33 + 4
	o1 := headerEnd
	o2 := o1 + uint64(len(execPayloadSSZ))
	o3 := o2 + uint64(len(blobsBundleSSZ))
	o5 := o3 + uint64(len(execRequestsSSZ))

	// Write first 3 offsets
	binary.LittleEndian.PutUint32(sszData[236:240], uint32(o1))
	binary.LittleEndian.PutUint32(sszData[240:244], uint32(o2))
	binary.LittleEndian.PutUint32(sszData[244:248], uint32(o3))

	// Signature at [248:344]
	copy(sszData[248:344], baseRequest.Signature[:])

	// TxRoot at [344:377] - selector byte (1) + 32 bytes
	sszData[344] = 1 // selector = Some
	copy(sszData[345:377], txRoot[:])

	// AdjustmentData offset at [377:381]
	binary.LittleEndian.PutUint32(sszData[377:381], uint32(o5))

	// Copy variable data
	copy(sszData[o1:o2], execPayloadSSZ)
	copy(sszData[o2:o3], blobsBundleSSZ)
	copy(sszData[o3:o5], execRequestsSSZ)
	copy(sszData[o5:], adjustmentSSZ)

	// Verify o1 indicates both TxRoot=Some and AdjustmentData present (381)
	o1Check := ssz.ReadOffset(sszData[236:240])
	require.Equal(t, uint64(381), o1Check, "With TxRoot=Some and AdjustmentData, first offset should be 381")

	// Unmarshal
	result := &VersionedExtendedSubmitBlockRequest{}
	err = unmarshaller.UnmarshalSSZ(sszData, result)
	require.NoError(t, err)

	// Verify TxRoot is present and correct
	require.NotNil(t, result.Fulu.TxRoot, "TxRoot should not be nil")
	require.Equal(t, txRoot, *result.Fulu.TxRoot)

	// Verify AdjustmentData is present and correct
	require.NotNil(t, result.Fulu.AdjustmentData)
	require.Equal(t, adjustmentData.StateRoot, result.Fulu.AdjustmentData.StateRoot)
	require.Equal(t, adjustmentData.TransactionsRoot, result.Fulu.AdjustmentData.TransactionsRoot)
	require.Equal(t, adjustmentData.BuilderAddress, result.Fulu.AdjustmentData.BuilderAddress)

	// Verify other fields
	require.Equal(t, uint64(1234), result.Fulu.Message.Slot)
	require.Len(t, result.Fulu.BlobsBundle.Commitments, 1)
}

// TestBlockSubmissionSSZFastUnmarshaller_InvalidOffset tests error handling for invalid offset values
func TestBlockSubmissionSSZFastUnmarshaller_InvalidOffset(t *testing.T) {
	unmarshaller := NewBlockSubmissionSSZFastUnmarshaller()

	blockHash := GenerateRandomEthHash()
	builderPubkey := GenerateRandomPublicKey()
	parentHash := GenerateRandomEthHash()
	proposerPubkey := GenerateRandomPublicKey()
	blockValue := big.NewInt(2000000)
	feeRecipient := bellatrix.ExecutionAddress{41, 42, 43}

	baseRequest := NewFuluBuilderSubmitBlockRequest(
		777, // slot
		proposerPubkey,
		builderPubkey,
		parentHash,
		blockHash,
		blockValue,
		feeRecipient,
		[]byte{0x41, 0x42, 0x43},
	)

	// Marshal to get a valid base
	sszData, err := baseRequest.MarshalSSZ()
	require.NoError(t, err)

	tests := []struct {
		name        string
		o1Value     uint32
		expectError bool
	}{
		{
			name:        "Invalid offset 346 - between valid values",
			o1Value:     346,
			expectError: true,
		},
		{
			name:        "Invalid offset 350 - between valid values",
			o1Value:     350,
			expectError: true,
		},
		{
			name:        "Invalid offset 370 - between valid values",
			o1Value:     370,
			expectError: true,
		},
		{
			name:        "Invalid offset 378 - between valid values",
			o1Value:     378,
			expectError: true,
		},
		{
			name:        "Invalid offset 100 - way off",
			o1Value:     100,
			expectError: true,
		},
		{
			name:        "Invalid offset 500 - too large",
			o1Value:     500,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Modify the offset in the SSZ data
			testData := make([]byte, len(sszData))
			copy(testData, sszData)
			binary.LittleEndian.PutUint32(testData[236:240], tt.o1Value)

			result := &VersionedExtendedSubmitBlockRequest{}
			err := unmarshaller.UnmarshalSSZ(testData, result)

			if tt.expectError {
				require.Error(t, err, "Expected error for offset %d", tt.o1Value)
			} else {
				require.NoError(t, err, "Expected no error for offset %d", tt.o1Value)
			}
		})
	}
}

// TestBlockSubmissionSSZFastUnmarshaller_TxRootZeroValue tests that TxRoot is nil when not present
func TestBlockSubmissionSSZFastUnmarshaller_TxRootZeroValue(t *testing.T) {
	unmarshaller := NewBlockSubmissionSSZFastUnmarshaller()

	blockHash := GenerateRandomEthHash()
	builderPubkey := GenerateRandomPublicKey()
	parentHash := GenerateRandomEthHash()
	proposerPubkey := GenerateRandomPublicKey()
	blockValue := big.NewInt(2000000)
	feeRecipient := bellatrix.ExecutionAddress{31, 32, 33}

	baseRequest := NewFuluBuilderSubmitBlockRequest(
		555, // slot
		proposerPubkey,
		builderPubkey,
		parentHash,
		blockHash,
		blockValue,
		feeRecipient,
		[]byte{0x31, 0x32, 0x33},
	)

	// Standard format - no TxRoot
	sszData, err := baseRequest.MarshalSSZ()
	require.NoError(t, err)

	// Unmarshal
	result := &VersionedExtendedSubmitBlockRequest{}
	err = unmarshaller.UnmarshalSSZ(sszData, result)
	require.NoError(t, err)

	// Verify TxRoot is nil
	require.Nil(t, result.Fulu.TxRoot, "TxRoot should be nil when not present")

	// Verify other fields work correctly
	require.Equal(t, uint64(555), result.Fulu.Message.Slot)
}

// TestBlockSubmissionSSZFastUnmarshaller_WithTxRootNone tests unmarshaling with TxRoot=None (selector=0, 1 byte)
// Expected offset: 345 (344 + 1 selector byte)
func TestBlockSubmissionSSZFastUnmarshaller_WithTxRootNone(t *testing.T) {
	unmarshaller := NewBlockSubmissionSSZFastUnmarshaller()

	blockHash := GenerateRandomEthHash()
	builderPubkey := GenerateRandomPublicKey()
	parentHash := GenerateRandomEthHash()
	proposerPubkey := GenerateRandomPublicKey()
	blockValue := big.NewInt(3000000)
	feeRecipient := bellatrix.ExecutionAddress{51, 52, 53}

	baseRequest := NewFuluBuilderSubmitBlockRequest(
		888, // slot
		proposerPubkey,
		builderPubkey,
		parentHash,
		blockHash,
		blockValue,
		feeRecipient,
		[]byte{0x51, 0x52, 0x53},
	)

	// Add simple blob
	commitment1 := deneb.KZGCommitment{}
	commitment1[0] = 0xAA
	proof1 := deneb.KZGProof{}
	proof1[0] = 0xBB
	blob1 := deneb.Blob{}
	blob1[0] = 0xCC

	baseRequest.BlobsBundle = &builderApiFulu.BlobsBundle{
		Commitments: []deneb.KZGCommitment{commitment1},
		Proofs:      []deneb.KZGProof{proof1},
		Blobs:       []deneb.Blob{blob1},
	}

	// Marshal components
	messageSSZ, err := baseRequest.Message.MarshalSSZ()
	require.NoError(t, err)

	execPayloadSSZ, err := baseRequest.ExecutionPayload.MarshalSSZ()
	require.NoError(t, err)

	blobsBundleSSZ, err := baseRequest.BlobsBundle.MarshalSSZ()
	require.NoError(t, err)

	execRequestsSSZ, err := baseRequest.ExecutionRequests.MarshalSSZ()
	require.NoError(t, err)

	// Build SSZ with TxRoot=None (345-byte header)
	// Layout: Message(236) + 3 offsets(12) + Signature(96) + TxRoot selector(1) + variable data
	totalSize := 236 + 12 + 96 + 1 + len(execPayloadSSZ) + len(blobsBundleSSZ) + len(execRequestsSSZ)
	sszData := make([]byte, totalSize)

	copy(sszData[0:236], messageSSZ)

	headerEnd := uint64(345) // 236 + 12 + 96 + 1
	o1 := headerEnd
	o2 := o1 + uint64(len(execPayloadSSZ))
	o3 := o2 + uint64(len(blobsBundleSSZ))

	// Write 3 offsets
	binary.LittleEndian.PutUint32(sszData[236:240], uint32(o1))
	binary.LittleEndian.PutUint32(sszData[240:244], uint32(o2))
	binary.LittleEndian.PutUint32(sszData[244:248], uint32(o3))

	// Signature at [248:344]
	copy(sszData[248:344], baseRequest.Signature[:])

	// TxRoot at [344:345] - selector byte only (0 = None)
	sszData[344] = 0 // selector = None

	// Copy variable data
	copy(sszData[o1:o2], execPayloadSSZ)
	copy(sszData[o2:o3], blobsBundleSSZ)
	copy(sszData[o3:], execRequestsSSZ)

	// Verify o1 indicates TxRoot=None present (345)
	o1Check := ssz.ReadOffset(sszData[236:240])
	require.Equal(t, uint64(345), o1Check, "With TxRoot=None, first offset should be 345")

	// Unmarshal
	result := &VersionedExtendedSubmitBlockRequest{}
	err = unmarshaller.UnmarshalSSZ(sszData, result)
	require.NoError(t, err)

	// Verify TxRoot is nil (None)
	require.Nil(t, result.Fulu.TxRoot, "TxRoot should be nil when selector=0")

	// Verify AdjustmentData is nil
	require.Nil(t, result.Fulu.AdjustmentData)

	// Verify other fields
	require.Equal(t, uint64(888), result.Fulu.Message.Slot)
	require.Len(t, result.Fulu.BlobsBundle.Commitments, 1)
}

// TestBlockSubmissionSSZFastUnmarshaller_WithTxRootNoneAndAdjustmentData tests TxRoot=None + AdjustmentData
// Expected offset: 349 (344 + 1 selector + 4 offset)
func TestBlockSubmissionSSZFastUnmarshaller_WithTxRootNoneAndAdjustmentData(t *testing.T) {
	unmarshaller := NewBlockSubmissionSSZFastUnmarshaller()

	blockHash := GenerateRandomEthHash()
	builderPubkey := GenerateRandomPublicKey()
	parentHash := GenerateRandomEthHash()
	proposerPubkey := GenerateRandomPublicKey()
	blockValue := big.NewInt(4000000)
	feeRecipient := bellatrix.ExecutionAddress{61, 62, 63}

	baseRequest := NewFuluBuilderSubmitBlockRequest(
		2222, // slot
		proposerPubkey,
		builderPubkey,
		parentHash,
		blockHash,
		blockValue,
		feeRecipient,
		[]byte{0x61, 0x62, 0x63},
	)

	// Add simple blob
	commitment1 := deneb.KZGCommitment{}
	commitment1[0] = 0xEE
	proof1 := deneb.KZGProof{}
	proof1[0] = 0xDD
	blob1 := deneb.Blob{}
	blob1[0] = 0xCC

	baseRequest.BlobsBundle = &builderApiFulu.BlobsBundle{
		Commitments: []deneb.KZGCommitment{commitment1},
		Proofs:      []deneb.KZGProof{proof1},
		Blobs:       []deneb.Blob{blob1},
	}

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

	// Marshal components
	messageSSZ, err := baseRequest.Message.MarshalSSZ()
	require.NoError(t, err)

	execPayloadSSZ, err := baseRequest.ExecutionPayload.MarshalSSZ()
	require.NoError(t, err)

	blobsBundleSSZ, err := baseRequest.BlobsBundle.MarshalSSZ()
	require.NoError(t, err)

	execRequestsSSZ, err := baseRequest.ExecutionRequests.MarshalSSZ()
	require.NoError(t, err)

	// Build SSZ with TxRoot=None + AdjustmentData (349-byte header)
	// Layout: Message(236) + 3 offsets(12) + Signature(96) + TxRoot selector(1) + AdjustmentData offset(4) + variable data
	totalSize := 236 + 12 + 96 + 1 + 4 + len(execPayloadSSZ) + len(blobsBundleSSZ) + len(execRequestsSSZ) + len(adjustmentSSZ)
	sszData := make([]byte, totalSize)

	copy(sszData[0:236], messageSSZ)

	headerEnd := uint64(349) // 236 + 12 + 96 + 1 + 4
	o1 := headerEnd
	o2 := o1 + uint64(len(execPayloadSSZ))
	o3 := o2 + uint64(len(blobsBundleSSZ))
	o5 := o3 + uint64(len(execRequestsSSZ))

	// Write first 3 offsets
	binary.LittleEndian.PutUint32(sszData[236:240], uint32(o1))
	binary.LittleEndian.PutUint32(sszData[240:244], uint32(o2))
	binary.LittleEndian.PutUint32(sszData[244:248], uint32(o3))

	// Signature at [248:344]
	copy(sszData[248:344], baseRequest.Signature[:])

	// TxRoot at [344:345] - selector byte only (0 = None)
	sszData[344] = 0 // selector = None

	// AdjustmentData offset at [345:349]
	binary.LittleEndian.PutUint32(sszData[345:349], uint32(o5))

	// Copy variable data
	copy(sszData[o1:o2], execPayloadSSZ)
	copy(sszData[o2:o3], blobsBundleSSZ)
	copy(sszData[o3:o5], execRequestsSSZ)
	copy(sszData[o5:], adjustmentSSZ)

	// Verify o1 indicates TxRoot=None + AdjustmentData (349)
	o1Check := ssz.ReadOffset(sszData[236:240])
	require.Equal(t, uint64(349), o1Check, "With TxRoot=None and AdjustmentData, first offset should be 349")

	// Unmarshal
	result := &VersionedExtendedSubmitBlockRequest{}
	err = unmarshaller.UnmarshalSSZ(sszData, result)
	require.NoError(t, err)

	// Verify TxRoot is nil (None)
	require.Nil(t, result.Fulu.TxRoot, "TxRoot should be nil when selector=0")

	// Verify AdjustmentData is present and correct
	require.NotNil(t, result.Fulu.AdjustmentData)
	require.Equal(t, adjustmentData.StateRoot, result.Fulu.AdjustmentData.StateRoot)
	require.Equal(t, adjustmentData.TransactionsRoot, result.Fulu.AdjustmentData.TransactionsRoot)
	require.Equal(t, adjustmentData.BuilderAddress, result.Fulu.AdjustmentData.BuilderAddress)

	// Verify other fields
	require.Equal(t, uint64(2222), result.Fulu.Message.Slot)
	require.Len(t, result.Fulu.BlobsBundle.Commitments, 1)
}

// TestDecodeHexPayload allows pasting a hex payload to explore its decoded structure
// func TestDecodeHexPayload(t *testing.T) {
// 	// Paste hex payload here (without 0x prefix)
// 	hexPayload := "f0d9220000000000596d55e0aaa504f18de9d26118b0c13b6a26532378a49860bb3d486f04600a8363238499ca482659cce05e489e16719756e7899c0d101b1d1ac8e9664d6db0daabf8cd171567b94fe9b8ca6b516bfcffa9e5f2cbfe1e703c4429e1b0488e4e8011e3b77098dfad273fa8d1eb72cd7d3194d06ac65f4b8a1a27333d1413af1ca242e54c6d1fdcda419e3ea9138f51c36b3856b38789613d972c7c323373b1936c670b24610df99b1685aeac0dfd5307b92e0cf4d70087930300000000081d88000000000001000000000000000000000000000000000000000000000000000000000000005c0100001e2800002628000094acd781cc61ccd04d1bbcaa380c68665f10e3245c48ff2deea87f973a1ec479e22bd272a12de91ff259debd4a7a198309ef36f80a04ae65fc3e7d879c4676b05bcc0fbcbaffc671f2b32be2ade9b253ed4eaad2eb913d8660633dd8a40753ee32280000596d55e0aaa504f18de9d26118b0c13b6a26532378a49860bb3d486f04600a83148914866080716b10d686f5570631fbb2207002e14b3a0ed9509beb0c9d89d65f853841959805429cdbb92e7285044766b51e245f1946cabbe935ee5efd17e7ac770521d5078df8c2033810a39756a234c46711000000000000004000220000001400800104000000020400000000308000000000008002040000100000000080001000400040020000002002601800002000000001001000000000003000881000040801000080000820000000014000000018000000200200004000088000000c08000200000012000002000480100000000000000400104400000100000000000501000000000000000000000020810000000a00000410001000810001003000250b0040000000028000000430800080800002000002000500000000500050000300008000000001000000000440500020000034004820000010000000010010000080000290024000080000080404008000a7ac8ddaea3963bdba3e04d739b36ed250e24e96d19fd163b1ea31024479bc0d93652000000000000087930300000000081d88000000000058487a6900000000100200008e88b5400000000000000000000000000000000000000000000000000000000063238499ca482659cce05e489e16719756e7899c0d101b1d1ac8e9664d6db0da280200000224000000002800000000009554630e00000000546974616e2028746974616e6275696c6465722e78797a29940000004b01000003020000b902000056030000ed030000c7060000a10900007b0c00004e100000e9100000841100001f120000ba12000055130000f01300008b14000026150000c11500005c160000f7160000921700002d180000c818000063190000fe190000991a0000341b0000cf1b00006a1c0000221d0000d91d0000901e0000471f0000fe1f0000b52000006c21000002f8b483088bb081da84773594008477359400830a11c1941d150609ee9edcc6143506ba55a4faaedd562cd980b84400f714ce00000000000000000000000000000000000000000000000000005af3107a4000000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeec080a0b36310166eb92c845adb87513ec6f7b41283494672a42242b0ef9a3fe63d0dcaa05ffb54969c16fb1ee1599eb7fd379b0c1fd2f4d26c76494352d7ebe7d048846302f8b583088bb0820ba1847735940084773594008309d478941d150609ee9edcc6143506ba55a4faaedd562cd980b844ddd5e1b20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fabd5dcb856f6cf94b43cf3a4ddca52272757233c080a0eb71b57ea219bbfaac7872549f0d0408bf0194100e118328e8b1ebcaea229059a04dc0cfe799638382242401de8f372e98b47359aa30c385f24db30a6c5e269a8002f8b383088bb036847735940084773594008309d478941d150609ee9edcc6143506ba55a4faaedd562cd980b844ddd5e1b20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e37243039ddd9c64f272d6bc523ade25e483335dc080a0a7a11330ae1c0b5d43a36bc0b6d1798818a3a26a2b7afb033e53e19dea497780a07f2d528e1d266518bc10bf3a1cabee3f338706d51cf9eb2eec86d2c2afcd5ca902f89a83088bb08270a9847735940084773594008307fcba949e2ddb3386d5dce991a2595e8bc44756f864c6e3872386f26fc10000a45358fbda0000000000000000000000000000000000000000000000000000000000000000c0019fbd48609dc58c167129fd02de457beb1da1f389bd3b15413732af864198ef32a00d587104ee79f605a5abcad7a20a9d83080fef207075f75ace2cc98b4ac70b2cf8958302781184474e3e008307fcba949e2ddb3386d5dce991a2595e8bc44756f864c6e38765fcb9af342f98a45358fbda000000000000000000000000000000000000000000000000000000000000000083111784a09fb358e577584246458a7a0572b979ec6b9a6528f8ffce952303f45b13d371aaa050d1af993299800e4b9e44a2911fb4c49d19d5cd98781805dc3bc81c925572bd02f902d683088bb08211b384039ce22b8476aadd75830c18ae9491cb447bafc6e0ea0f4fe056f5a9b1f14bb06e5d80b9026496051d560000000000000000000000007da81eeee97cc08485a72674baec396cec92c6350000000000000000000000000000000000000000000000000000000000206591038e3107ea4f2f867d65fe0ad13b98b3f33cc6e857997eb09ad9397fad5edb1c08ceaf53b5cef70cfe0f88d13b4eb79404c44227442542a09e10991e0f6a37fd00000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000002402b602acddeff10c8b00ad1e2459cdc3fdbe60fe351d76931a2b2deb6f2e0f7e121762a89038a48ea4093716a41743041fa9c947ba476356fa1d95b77b79c11c80e353e080c27c78dbaa2c32dd84818bb9fcc08075f711c03fc24de1c3e1e76340ab15e6e4db8f2405a808244f1f7840beae0dd31b44e6a5e6b86a03f7e9922b80159cd876c12df739396943ca2df294982678ccab1bd22788c68c60ee5d17dbe21e2138906db661f52a1d1c1265981c941663e19c8ea79d30cbebcf3d3d1b58515e2f1090332e8e6edb722ba8a0fe1806ad049d5fffec7d8f122b397708aa3eb02fa6f4f8a9d20e073e4ea707fd5bc5d58c496ebfe080562d504e9e2f4715aac00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000e737573616e6c6f70657a373134330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c001a060d536f7d4dcf1a0085cdb3f39b4723303271251b82f5013b46d37d91a662d35a07c7a3c1e67f7e944194bfd140dcccafc18d244773540725306a0de437ef0798a02f902d683088bb082111b84039ce22b848507f347830c18a29491cb447bafc6e0ea0f4fe056f5a9b1f14bb06e5d80b9026496051d5600000000000000000000000080c8e3bd8cfaf0e44fd02d61fce3e93100959f5600000000000000000000000000000000000000000000000000000000002065928338a876dc0307f16f52d83d7661b14e1b209d13ea4b354d83e718ec07d9bbee596d55e0aaa504f18de9d26118b0c13b6a26532378a49860bb3d486f04600a8300000000000000000000000000000000000000000000000000000000000001c0000000000000000000000000000000000000000000000000000000000000024007104f907ade6dc093e0e504c465108e14795261192b18153be1b02f4463f3e929063a25f2b940dd8f890fc00d60e9d8cc91e852c23ecd266cf77ad57cef3f3d1addca75b67723fc9f128aa951b1d9d9889c1720718edea4f03389df6673b94127ce3b97ff4708afff294d758f6dc28095e062b2c32d3d3f10b1a6deba2e0b3d127c2adea4a575055fcb1b521ce906d754dc2771c71f8ee1db236b17cf4e677b18fdd438dc2bc0322e465e72f8fffec348d09cebe9c77da638da59580e96a1f729711bdf0f51151cf3852d216c949b8627ee21b410b62673976075ac62ad598716093d984b48b14200280f514fd34a17a1d06f1d0d9af9c165a956dfd71aa9fa00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000f6465626f7261687068696c6c69707300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c080a0c4b2bb3166b958895679873c20b082e120dae20eb1ccaf8b2b3abb7f784dc486a055a9a352100b31426f5939daf1e29f3d752f4962cc9afc95c07471ee09ed48c302f902d683088bb082750d84039ce22b8476aadd75830be3699491cb447bafc6e0ea0f4fe056f5a9b1f14bb06e5d80b9026496051d560000000000000000000000000e2c8e888a94a1ba294eca53a1986717df4f985700000000000000000000000000000000000000000000000000000000002065916a80686ae7da7b459565143d082ddd6cc0c2cf5b3c00c0c824b8e9a51be4bd3008ceaf53b5cef70cfe0f88d13b4eb79404c44227442542a09e10991e0f6a37fd00000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000240061c25147d5e8c23452e34e7d933b847c61ceb215a04cc71c1908d1a004322122d13203125a4d4d275af08441dff13e112a54f31f6834490c0b88aa46b923cfe18a85aee56fc37536408a344887121c2f136e097d4c68126de2894a8e0363927065f2218e149a5ba7a2b7aa9fceb3393da55447421ca961b363d922ec5257bd60723e830629dfa52031b45f8c977b7cebc4692ef7459d017bd98ba873594da0f0cc948fb9948392863aff59eb0bba97907e2c2523dcd11cdd149e4d0608fd0521077b0da8c54da346adbb1f960febfb173035dec25b783da866509fc188e46b30454d2528067a4ff21db9874c866bf3ba689d79d1510a3cec0d73dd044f462e400000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000c637261696767616d6538343100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c080a06df3df2a55cc47d07468e4d5deb1bb149e4a5eb7ce8c7c7f79c6599247f655d8a0170d08e8f1dc7b768161476f652b2775bb6e05d3ce0291029686564a74fb2aa7f903d0830144b1844a4ffb1d83042e9f9487cd431f160e88ec34fa48ec6f6cf7f2c0e8248c80b90364ab21739a61612d729fc4d267f6a0d0ff9e68f8f0a625c746ba12e82469a04c087fde767e000000000000000000000000041af25fce2413570aaa0029d36dea1efdeff0830000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000001c0247862832a936f895f4a4873a33f178114a0e7761b1680d522cbb40a0937b4d9288558bf1175c058947e234b446bf90ddfe491a19610137ca20c81630835bcca0aa231b46665cbec0222e68f099f8c637f4f11b96820025b7f837f0725cc98fa1841d40f57b9e5862b33a281b18e13fa7fe6b88ce25c6cefba72cea7e496c82b1f59bdb194cf1b25720ea22d1b0e48c39ab75b8cec09a3cd59beeffe6159746a1721bbab45f3b3747b0fecdf51ae26c27b1fc5525ba8e8d552b8650cdb37063a0000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000000000026000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012c09ff39971e9be929cf51b38b50d96b5cd9f00e8d19f2f16f81c06966f06a8d2770da4a62c9e4dd1c863514802e158cc008d7d3994f02577e63cf80f288b5e7000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000083111784a0d6832f2a53cdceab37438929da3e6aa7bcc1cd584173770e58010c4cef2d4d84a03bbec550f2220de03320cf5be965d1e2f373bcf43d6b7e8e47c447b26646a71f03f89883088bb08301975384773594008505d21dba0082520894308bd7f852c4f76454d4067b066bf83b2080d4808080c0843b9aca00e1a001d98b29d26fc2624733b1ba31ffff16312f7ddc5fb440b58356ddaa99e94f5101a0816974c9502bfbd92ce028b6520ec9a58c4eef055c88c5b5b10a1ae7de468e91a07621ac975288e37010a74a413c18225249bee985a586c7eecca540749e54f9d803f89883088bb0830199ec84773594008505d21dba00825208943926256d82f1c28efc2f39c62643c1fc05df80ca8080c0843b9aca00e1a0013774b8ba80e734cd7a159acd9194a4a34e90eb6bc860405db8aa15b863819280a0a3e175fbc1f0f98b29fa9ac53e6b7f672dd4107882bb11fa3d1667bd3277157ea04cc62c90b45bb700fc7489b80bdad9ed6aa043c5d93bfb84617a14387b6106a003f89883088bb083019a5984773594008505d21dba008252089419b4e900a7fc84ca4ae87ddae6b28d2f997ad5b08080c0843b9aca00e1a001e62686f513c05693f9f153f421f0c5dfa5e8a62ae78003c89e264f92b5fa1c80a06aebacb087db4fc7b488acaa174f9b5a26ce76243d973ddd2431de4687a05b05a039e6d97075099c2004ee13f43235db3128aec021b451b1ebb2ad9d8ca957c45f03f89883088bb0830195f884773594008505d21dba0082520894ee0ff342d45b1731e2709bf8a14465316b6e6e608080c0843b9aca00e1a0010ffa54c58fdb41d09c6b034b61e5206a734e42aac8057ce39325eea833024480a016be9be5e42e590013c69f660624ed856d1be0cefa30df82c917410ec67889d0a014bd85a66d20f91fda96a5446b1f49c2b96448626649955e180a671cdecfd23903f89883088bb0830196e084773594008505d21dba00825208945edc98fcfd333053ddda240aba0a2d770f2453ac8080c0843b9aca00e1a001e90367b66602adae594bc85c8ad0e54c1bcee18c60b4a46ebbc3974450225f80a02ac534644f2d70eb18f5ab4da32bd8d4d6444a8bc92da6dcdddc5f66ae0bdb06a002f93427a4c52bf5bb9ee51045a6586085e94049bf7e6ca2bd882abbd57d893203f89883088bb08301970784773594008505d21dba0082520894f035407a58616be05b73d2fdcd755d290ec470648080c0843b9aca00e1a0010611ceebb78314e62236d9d15a971cad2f8a2a2cbaed8c72d3544d29a35bfa01a0d2eb6b29a1721fde257f572945c9e295015181724f457af676107f061961fde6a00ce8f7652757713844c34db1113290099a12c51ecc701e8fd259ccb1e0dfb03a03f89883088bb083019a2784773594008505d21dba0082520894b924d6b6aedf2c50c6f4e0a02668680586bf5d698080c0843b9aca00e1a0012f76ee9e1f1a9931a614ddb88c7beed0335444d8d64e1e15fd94cb0e6bf09780a01a4268422f7b6b6cd255e66be759712857d777c7848d31d08009c1002c73bb91a07184011f3ffa4e79c68791b825612b41f9daeaadb5c6c470d51006889177045a03f89883088bb08301944584773594008505d21dba008252089493db17eb21f1d5673000a8dcde4c847183ff1f688080c0843b9aca00e1a001ec130b1f1563434b5433e05ddf3eeeddc8c7a14f360af4eb410a1922f1db6d80a087da2f543ee760ed55cd746db847950be88e80425fc2effb70025d8dc9ff240ca00974796cfa0087fb3f775afd05a59089759f2b9aa4f4a28cdc6322325931b8c503f89883088bb08301989484773594008505d21dba00825208947aba431a7d58d1318b630cc9491701df12f02c958080c0843b9aca00e1a001b583cebd32da301836ebda79bd391ae801150c31f71e02e06bbcabcfadcdf980a02d23c5acced26ac0941ee9cc0c46169d6707c983e31ac037338c1549e6d3db11a037a8460b42c55303f68c23c8dceffceb66d10642d305e55c075ff034d1696c8203f89883088bb0830197f384773594008505d21dba0082520894272fe4e34c1b7ba796baf95dbe8f173cdd0404108080c0843b9aca00e1a00164cbdf9fdbf00e2ebe9efad05546b0aa6fb6f00b635cbccaf28ad381cca85980a08895cf1c2a349a923ee6019995cf901ab0b3562966f73587a4e57cec42bec5baa048cfcf28483142d38491fdf5103c5e1ffbbb7ff40774e1345ae093e27c9a479103f89883088bb08301989484773594008505d21dba0082520894397aa532b1bd8822e44e05a419b07a8ed2da5e8b8080c0843b9aca00e1a0017987ace705b9deaf6a8ccb770843c415977c1c6b346f14df29ecd0ce65581c80a04e571dfc5756e895ea2977151073107e13134bea636721e78e55aea15e6eb900a01af2c1906b0776e3e5ae302c3118aea08e9e63a46b235846dbc1d6f753f3393503f89883088bb08301951384773594008505d21dba0082520894d84aeebdbb8dcce573f4b2c09d3607a159938a6d8080c0843b9aca00e1a001a57e4adf04dd577286c0caac413353a2b709a81cac93244cb0203ed24d2a1080a0846031c583b3e34220b5f54370791929e43673b5ab915066a6b2433dbe6e8ae8a06117eb802baa654d86549e851dbfeff88ca4fb5550c0d4dc572d7b75ef4b5d2e03f89883088bb08301935084773594008505d21dba0082520894ee26ee05e3cfb68ebb1577f7b03ac3b037a64a7a8080c0843b9aca00e1a0018d81e1b8c83c48c8bda5e3f251066e4a968be59de6023ef3a831c5d2e691fe01a0c78e28051fc736e75a51edc02468115d148b81416d89cf876feeff2fa673cf23a06b2dcb0213ee8e6d9bab1c6d1a7ea5d5b055facd6755055df42719b1f7274dc803f89883088bb08301999084773594008505d21dba00825208942656ad4f15a8ce0b9a4b040b43e1b580c2f79dd48080c0843b9aca00e1a001c568d7e15d59f73e9ee310395fd7ccdb6de2687315f56272abaac22aed5ea480a0cf1c0de899ce0bb1abd1f739ceb70819ab71d90066631cd83205d7d5661a9474a056c349e02f0abb721c2415460a295b4b9fd861f6f323191df8a3fc5f973a624703f89883088bb08301987e84773594008505d21dba00825208946b55e13fd51eb72268df2dafbb229d0a1fa516e38080c0843b9aca00e1a0019165b77021b03210a5ee226526a4111ebfb2dc87f761bf692d630b332bf4f080a0a9ce6693245dc904a13a07ab4dd08823ee83124ca815c7740e38af8353424012a047b5e397b44456cda5992c72b2c0df82d5f486201a1634bed4383ae3eb2169b403f89883088bb08301892084773594008505d21dba008252089463194d5c144027884538a616023b340b647724798080c0843b9aca00e1a001003f6011b6080836a0dc9461e4cf779ab8f4acb5b06c3e38c3f738527fe3da01a01275e08c20dc2a73da92376880461fa520faa1baecd8db60063c9d4745492556a0051ada6f0488d92eba2dad182357e9f078d11f05dd4e5bc91ef8a25120757ed703f89883088bb0830198b884773594008505d21dba0082520894d18fa5f0b4cbf9f7f8db888865a8b00f16f0f1e58080c0843b9aca00e1a00127b3324c65bb61cbff6174425e9868a743ef011789a996e217aa442ece484b80a006603b5addb1ec0022e335b438e7e1f6fbc302420d5b180f4f5961295f0a65e1a02c124cad0b1dbaa37b23ee9702f2661a1d512231441d18fc58777ce0b49ef37103f89883088bb08301953a84773594008505d21dba008252089470d48db7c0a45d2c889b64d2577a429d326d661d8080c0843b9aca00e1a0013549592307333d6897e6ea17fb21aab402f5e9a7b9403504509341f91ca19f01a0467c1fb37a9178f6f97f900bbd4b9b6c500e8c21e0e5431417732eaa318436a1a04afcefeeee85de80a81001a8881a5054f1a2529ea3352537e379885afe112ee203f89883088bb08301997484773594008505d21dba008252089475f0165617a111faac1303e4d7b135231d8d875d8080c0843b9aca00e1a0014a4f98790de1097de745923a0b08d1e2f0ffad01f651bd1a190b9000c43a4c80a0e24f05de13fa57411e50732547899f9229b665389dbb10c30c7e6cbc43adeec9a0333246ab2efb3d285e1ee87ae83a3108e74c93b29c23a94a05e2c4d94ee5630603f89883088bb08301946984773594008505d21dba008252089453b344eef7db18321078d62bc8157a6ec4e0944f8080c0843b9aca00e1a00102cba4bc226934e901e62908b9a327b7c52a30efee139a00deb93f9e3aa64901a0a169a0e11f36d02aae27edfb9b4964c44e4b7bd43c45575a9bfe6b89000100dfa041cace8baacbf63269c517752e04dbb1f7a835de5665b9c5660ff6d8244ed79f02f8b583088bb082a9d78401ec31a6847d04a4788309eb10941d150609ee9edcc6143506ba55a4faaedd562cd980b84400f714ce00000000000000000000000000000000000000000000000000005af3107a4000000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeec080a00a9fc093fe63f1ccec64f25e3ef5e0bc78b20cbb0e21e1b780068ad6082812e5a0582e0db67c8a034c47d6f34dace5f3e1ce778e02a501483caca0c083aa706efb02f8b483088bb081b78401ec31a6847d04a4788309eb10941d150609ee9edcc6143506ba55a4faaedd562cd980b844ddd5e1b200000000000000000000000000000000000000000000000000000000000000000000000000000000000000004359f83a786f525682d76330e8b99ba22cc86f81c080a0713d15b793719fc84d8433e31277834f91c711ec791794083292a8d130945bb7a0746db32088de3448a07e43ca9f1f40c956b4654dce6e266e62eb019aa046811902f8b483088bb081e08401ec31a6847d04a4788309eb10941d150609ee9edcc6143506ba55a4faaedd562cd980b844ddd5e1b20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000062376415fdbf4d92b240266e0fb4da0b020807ec001a0049731f5459f6e806011f7ce7204792f63ef819d2194100d2640a56e6e3e1e6aa001804936fa2b0baa0a581599eca40ae881f81a6f23664b7f083b22e0b2c6157f02f8b483088bb081cf8401ec31a6847d04a4788309eb10941d150609ee9edcc6143506ba55a4faaedd562cd980b844ddd5e1b20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000168b023cbc6a676ec37c345c2988e977c6878735c080a0052cfcb4d9c937c8d884d73c67885353f51760eb36db836606b6151b942d498ca079f5b7ddc6e6d92dd0ea95133896d4d4c3e3a87fc0fe949de5c0d41ef6b488a402f8b483088bb081cc8401ec31a6847d04a4788309eb10941d150609ee9edcc6143506ba55a4faaedd562cd980b844ddd5e1b20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000941fbcb4641553cf79141116011e47fb15f18569c080a0e67066ecfcd23d1d72c4e44eef46e793ab442c2e4dc6bfead09888dca271739da057f575d8f18421871f326f1ec1fceb626faeb3ac11c08532cdb3ff742eb0c90202f8b483088bb081bb8401ec31a6847d04a4788309eb10941d150609ee9edcc6143506ba55a4faaedd562cd980b844ddd5e1b20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a07ee4539de9a33c1bd7a25853d6bd273684416cc001a00ebb245296c76de98c626872b9590982df994b00a820b9f916bdd9a9681459e1a04001313ce6a47e91b96c6f5a55e1c6d96e97f3be2628e585fafd3a5fb03fb1e002f8b483088bb081ac8401ec31a6847d04a4788309eb10941d150609ee9edcc6143506ba55a4faaedd562cd980b844ddd5e1b2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000037f36ec2887b49a571164ae511ba46af69a4472fc080a0fc5f86b42a197fed4f21d38aa1353381287635d5e9841054a2092c662c682beea0700f4d7a6be0b9229836253d9bbb2b34244f5647975810ca0177addf40ef537f02f86b83088bb0823038808440b5888e82520894670b24610df99b1685aeac0dfd5307b92e0cf4d70180c080a0cff87b15abdcf42b752cf4effb07a57801a3aa2e16b5945e3025135f9cc7f829a02a091a185306a3297c05fbb5a52a91a3ca5080df5f1e9174e72d819e4cdf07584c9b030200000000d9f11000000000009b491f043189af6d31d3d4b1a7ca1cf72f40c52ae7b73300000000004d9b030200000000daf11000000000009b491f043189af6d31d3d4b1a7ca1cf72f40c52ab27c3300000000004e9b030200000000dbf11000000000009b491f043189af6d31d3d4b1a7ca1cf72f40c52a14af3300000000004f9b030200000000dcf11000000000009b491f043189af6d31d3d4b1a7ca1cf72f40c52ad9a0330000000000509b030200000000ddf11000000000009b491f043189af6d31d3d4b1a7ca1cf72f40c52ab685330000000000519b030200000000def11000000000009b491f043189af6d31d3d4b1a7ca1cf72f40c52a2e82330000000000529b030200000000dff11000000000009b491f043189af6d31d3d4b1a7ca1cf72f40c52a3dfd330000000000539b030200000000e0f11000000000009b491f043189af6d31d3d4b1a7ca1cf72f40c52a4f98330000000000549b030200000000e1f11000000000009b491f043189af6d31d3d4b1a7ca1cf72f40c52afe8d330000000000559b030200000000e2f11000000000009b491f043189af6d31d3d4b1a7ca1cf72f40c52aa97f330000000000569b030200000000e3f11000000000009b491f043189af6d31d3d4b1a7ca1cf72f40c52a51cc330000000000579b030200000000e4f11000000000009b491f043189af6d31d3d4b1a7ca1cf72f40c52ad1d6330000000000589b030200000000e5f11000000000009b491f043189af6d31d3d4b1a7ca1cf72f40c52addbf330000000000599b030200000000e6f11000000000009b491f043189af6d31d3d4b1a7ca1cf72f40c52aa6773300000000005a9b030200000000e7f11000000000009b491f043189af6d31d3d4b1a7ca1cf72f40c52ae1cc3300000000005b9b030200000000e8f11000000000009b491f043189af6d31d3d4b1a7ca1cf72f40c52a7dbb33000000000008000000080000000c0000000c0000000c00000000"

// 	if hexPayload == "" {
// 		t.Skip("No hex payload provided - paste hex string to test")
// 	}

// 	payloadBytes, err := hex.DecodeString(hexPayload)
// 	require.NoError(t, err, "failed to decode hex string")

// 	t.Logf("Payload size: %d bytes", len(payloadBytes))

// 	// Read key offsets to understand structure
// 	if len(payloadBytes) >= 240 {
// 		o1 := ssz.ReadOffset(payloadBytes[236:240])
// 		o2 := ssz.ReadOffset(payloadBytes[240:244])
// 		o3 := ssz.ReadOffset(payloadBytes[244:248])

// 		t.Logf("Offset o1 (ExecutionPayload): %d", o1)
// 		t.Logf("Offset o2 (BlobsBundle): %d", o2)
// 		t.Logf("Offset o3 (ExecutionRequests): %d", o3)

// 		// Determine layout
// 		switch o1 {
// 		case 344:
// 			t.Logf("Layout: No optional fields")
// 		case 345:
// 			t.Logf("Layout: TxRoot=None (1 byte)")
// 		case 348:
// 			t.Logf("Layout: AdjustmentData offset only (legacy)")
// 		case 349:
// 			t.Logf("Layout: TxRoot=None + AdjustmentData offset")
// 		case 377:
// 			t.Logf("Layout: TxRoot=Some (33 bytes)")
// 		case 381:
// 			t.Logf("Layout: TxRoot=Some + AdjustmentData offset")
// 		default:
// 			t.Logf("Layout: Unknown (o1=%d)", o1)
// 		}
// 	}

// 	// Unmarshal the payload
// 	unmarshaller := NewBlockSubmissionSSZFastUnmarshaller()
// 	result := &VersionedExtendedSubmitBlockRequest{}
// 	err = unmarshaller.UnmarshalSSZ(payloadBytes, result)

// 	if err != nil {
// 		t.Logf("Unmarshal error: %v", err)
// 		t.FailNow()
// 	}

// 	require.NoError(t, err, "failed to unmarshal payload")
// 	require.NotNil(t, result.Fulu)

// 	// Log decoded structure
// 	t.Logf("\n=== Decoded Structure ===")
// 	t.Logf("Slot: %d", result.Fulu.Message.Slot)
// 	t.Logf("BlockHash: %x", result.Fulu.Message.BlockHash)
// 	t.Logf("ParentHash: %x", result.Fulu.Message.ParentHash)
// 	t.Logf("BuilderPubkey: %x", result.Fulu.Message.BuilderPubkey)
// 	t.Logf("ProposerPubkey: %x", result.Fulu.Message.ProposerPubkey)
// 	t.Logf("Value: %s", result.Fulu.Message.Value.Dec())

// 	t.Logf("\nExecutionPayload:")
// 	t.Logf("  BlockNumber: %d", result.Fulu.ExecutionPayload.BlockNumber)
// 	t.Logf("  GasLimit: %d", result.Fulu.ExecutionPayload.GasLimit)
// 	t.Logf("  GasUsed: %d", result.Fulu.ExecutionPayload.GasUsed)
// 	t.Logf("  Transactions: %d", len(result.Fulu.ExecutionPayload.Transactions))
// 	t.Logf("  Withdrawals: %d", len(result.Fulu.ExecutionPayload.Withdrawals))

// 	t.Logf("\nBlobsBundle:")
// 	t.Logf("  Commitments: %d", len(result.Fulu.BlobsBundle.Commitments))
// 	t.Logf("  Proofs: %d", len(result.Fulu.BlobsBundle.Proofs))
// 	t.Logf("  Blobs: %d", len(result.Fulu.BlobsBundle.Blobs))
// 	t.Logf("  NewItems (hydration): %d", len(result.Fulu.BlobsBundle.NewItems))

// 	t.Logf("\nExecutionRequests:")
// 	t.Logf("  Deposits: %d", len(result.Fulu.ExecutionRequests.Deposits))
// 	t.Logf("  Withdrawals: %d", len(result.Fulu.ExecutionRequests.Withdrawals))
// 	t.Logf("  Consolidations: %d", len(result.Fulu.ExecutionRequests.Consolidations))

// 	if result.Fulu.TxRoot != nil {
// 		t.Logf("\nTxRoot: %x", *result.Fulu.TxRoot)
// 	} else {
// 		t.Logf("\nTxRoot: nil")
// 	}

// 	if result.Fulu.AdjustmentData != nil {
// 		t.Logf("\nAdjustmentData: present")
// 		t.Logf("  StateRoot: %x", result.Fulu.AdjustmentData.StateRoot)
// 		t.Logf("  TransactionsRoot: %x", result.Fulu.AdjustmentData.TransactionsRoot)
// 		t.Logf("  BuilderAddress: %x", result.Fulu.AdjustmentData.BuilderAddress)
// 	} else {
// 		t.Logf("\nAdjustmentData: nil")
// 	}
// }
