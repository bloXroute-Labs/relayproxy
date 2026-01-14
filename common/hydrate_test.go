package common

import (
	"encoding/binary"
	"math/big"
	"testing"

	builderApiFulu "github.com/attestantio/go-builder-client/api/fulu"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/bloXroute-Labs/relay-grpc/bidadjustment"
	ssz "github.com/ferranbt/fastssz"
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

	// Create NewItems with proofs array (128 proofs per item)
	newItem1 := FuluHydrationBlobItem{
		Commitment: commitment1,
		Proof:      make([]deneb.KZGProof, 128),
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
		Proof:      make([]deneb.KZGProof, 128),
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
		NewItems:    []FuluHydrationBlobItem{newItem1, newItem2},
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
	require.Len(t, result.Fulu.BlobsBundle.NewItems[0].Proof, 128)
	require.Len(t, result.Fulu.BlobsBundle.NewItems[1].Proof, 128)
	require.Equal(t, newItem1.Blob, result.Fulu.BlobsBundle.NewItems[0].Blob)
	require.Equal(t, newItem2.Blob, result.Fulu.BlobsBundle.NewItems[1].Blob)

	// Verify proofs match
	for i := 0; i < 128; i++ {
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
	commitmentsSize := len(bundle.Commitments) * 48
	newItemsSize := len(bundle.NewItems) * 137268 // Fixed size per item (4 + 48 + 131072 + 128*48 = 137268)

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
		copy(data[o0+uint64(i*48):o0+uint64((i+1)*48)], commitment[:])
	}

	// Write NewItems
	for i, item := range bundle.NewItems {
		itemSSZ, err := item.MarshalSSZ()
		require.NoError(t, err)
		require.Equal(t, 137268, len(itemSSZ))
		copy(data[o3+uint64(i*137268):o3+uint64((i+1)*137268)], itemSSZ)
	}

	return data
}

// MarshalSSZ for FuluHydrationBlobItem
func (item *FuluHydrationBlobItem) MarshalSSZ() ([]byte, error) {
	// Fixed part: offset(4) + Commitment(48) + Blob(131072) = 131124
	// Variable part: Proofs = len(Proof)*48
	// Total: 131124 + len(Proof)*48
	proofsSize := len(item.Proof) * 48
	totalSize := 131124 + proofsSize
	buf := make([]byte, totalSize)

	// Offset for Proof field (points to where variable data starts)
	o0 := uint32(131124)
	binary.LittleEndian.PutUint32(buf[0:4], o0)

	// Commitment at [4:52]
	copy(buf[4:52], item.Commitment[:])

	// Blob at [52:131124]
	copy(buf[52:131124], item.Blob[:])

	// Proofs at [131124:]
	for i, proof := range item.Proof {
		copy(buf[131124+i*48:131124+(i+1)*48], proof[:])
	}

	return buf, nil
}
