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

// MarshalSSZ for HydrateBlobItem
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
				NewItems:    []FuluHydrationBlobItem{}, // Empty NewItems (standard format)
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

	commitment1 := make([]byte, 48)
	commitment1[0] = 0xAA
	commitment2 := make([]byte, 48)
	commitment2[0] = 0xBB

	proof1 := make([]byte, 48)
	proof1[0] = 0xCC
	proof2 := make([]byte, 48)
	proof2[0] = 0xDD

	blob1 := make([]byte, 131072)
	blob1[0] = 0xEE
	blob2 := make([]byte, 131072)
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
			BlobGasUsed:   131072,
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

	commitment1 := make([]byte, 48)
	commitment1[0] = 0x11
	commitment2 := make([]byte, 48)
	commitment2[0] = 0x22

	// Create NewItems with proofs arrays
	proof1_1 := make([]byte, 48)
	proof1_1[0] = 0x33
	proof1_2 := make([]byte, 48)
	proof1_2[0] = 0x44

	proof2_1 := make([]byte, 48)
	proof2_1[0] = 0x55

	blob1 := make([]byte, 131072)
	blob1[0] = 0x66
	blob2 := make([]byte, 131072)
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
			BlobGasUsed:   131072,
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
