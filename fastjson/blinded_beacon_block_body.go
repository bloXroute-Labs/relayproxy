package fastjson

import (
	"bytes"
	"encoding/hex"
	"strings"

	capellaapi "github.com/attestantio/go-eth2-client/api/v1/capella"
	"github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/api/v1/electra"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/capella"
	deneb2 "github.com/attestantio/go-eth2-client/spec/deneb"
	electraspec "github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"github.com/valyala/fastjson"
)

func UnmarshalToBlindedBeaconBlockBodyCapella(body *fastjson.Value) (*capellaapi.BlindedBeaconBlockBody, error) {
	randaoReveal, err := convertTo96ByteArray(body.GetStringBytes(jsonRandaoReveal))
	if err != nil {
		return nil, err
	}

	eth1Data := body.Get(jsonETH1Data)

	depositRoot, err := convertTo32ByteArray(eth1Data.GetStringBytes(jsonDepositRoot))
	if err != nil {
		return nil, err
	}

	depositCount, err := convertToUint64(eth1Data.GetStringBytes(jsonDepositCount))
	if err != nil {
		return nil, err
	}

	graffiti, err := convertTo32ByteArray(body.GetStringBytes(jsonGraffiti))
	if err != nil {
		return nil, err
	}

	// unmarshal ProposerSlashing slice
	proposerSlashingsValues := body.GetArray(jsonProposerSlashings)
	proposerSlashings := make([]*phase0.ProposerSlashing, len(proposerSlashingsValues))
	for i, proposerSlashingValue := range proposerSlashingsValues {
		signedHeader1, err := unmarshalToSignedBeaconBlockHeader(proposerSlashingValue.Get(jsonSignedHeader1))
		if err != nil {
			return nil, err
		}

		signedHeader2, err := unmarshalToSignedBeaconBlockHeader(proposerSlashingValue.Get(jsonSignedHeader2))
		if err != nil {
			return nil, err
		}

		proposerSlashings[i] = &phase0.ProposerSlashing{
			SignedHeader1: signedHeader1,
			SignedHeader2: signedHeader2,
		}
	}

	// unmarshal AttesterSlashing slice
	attesterSlashingsValues := body.GetArray(jsonAttesterSlashings)
	attesterSlashings := make([]*phase0.AttesterSlashing, len(attesterSlashingsValues))
	for i, attesterSlashingValue := range attesterSlashingsValues {
		attestation1, err := unmarshalToIndexedAttestation(attesterSlashingValue.Get(jsonAttestation1))
		if err != nil {
			return nil, err
		}

		attestation2, err := unmarshalToIndexedAttestation(attesterSlashingValue.Get(jsonAttestation2))
		if err != nil {
			return nil, err
		}

		attesterSlashings[i] = &phase0.AttesterSlashing{
			Attestation1: attestation1,
			Attestation2: attestation2,
		}
	}

	// unmarshal Attestation slice
	attestationsValues := body.GetArray(jsonAttestations)
	attestations := make([]*phase0.Attestation, len(attestationsValues))
	for i, attestationValue := range attestationsValues {
		data, err := unmarshalToAttestationData(attestationValue.Get(jsonData))
		if err != nil {
			return nil, err
		}

		signature, err := convertTo96ByteArray(attestationValue.GetStringBytes(jsonSignature))
		if err != nil {
			return nil, err
		}

		attestations[i] = &phase0.Attestation{
			AggregationBits: convertToBytes(attestationValue.GetStringBytes(jsonAggregationBits)),
			Data:            data,
			Signature:       signature,
		}
	}

	// unmarshal Deposit slice
	depositsValues := body.GetArray(jsonDeposits)
	deposits := make([]*phase0.Deposit, len(depositsValues))
	for i, depositValue := range depositsValues {
		proofValues := depositValue.GetArray(jsonProof)
		proof := make([][]byte, len(proofValues))
		for i, proofValue := range proofValues {
			proofBytes, err := proofValue.StringBytes()
			if err != nil {
				return nil, err
			}

			proof[i] = convertToBytes(proofBytes)
		}

		data := depositValue.Get(jsonData)

		publicKey, err := convertTo48ByteArray(data.GetStringBytes(jsonPublicKey))
		if err != nil {
			return nil, err
		}

		amount, err := convertToUint64(data.GetStringBytes(jsonAmount))
		if err != nil {
			return nil, err
		}

		signature, err := convertTo96ByteArray(data.GetStringBytes(jsonSignature))
		if err != nil {
			return nil, err
		}

		deposits[i] = &phase0.Deposit{
			Proof: proof,
			Data: &phase0.DepositData{
				PublicKey:             publicKey,
				WithdrawalCredentials: convertToBytes(data.GetStringBytes(jsonWithdrawalCredentials)),
				Amount:                phase0.Gwei(amount),
				Signature:             signature,
			},
		}
	}

	// unmarshal SignedVoluntaryExit slice
	voluntaryExitsValues := body.GetArray(jsonVoluntaryExits)
	voluntaryExits := make([]*phase0.SignedVoluntaryExit, len(voluntaryExitsValues))
	for i, voluntaryExitValue := range voluntaryExitsValues {
		message := voluntaryExitValue.Get(jsonMessage)

		epoch, err := convertToUint64(message.GetStringBytes(jsonEpoch))
		if err != nil {
			return nil, err
		}

		validatorIndex, err := convertToUint64(message.GetStringBytes(jsonValidatorIndex))
		if err != nil {
			return nil, err
		}

		signature, err := convertTo96ByteArray(voluntaryExitValue.GetStringBytes(jsonSignature))
		if err != nil {
			return nil, err
		}

		voluntaryExits[i] = &phase0.SignedVoluntaryExit{
			Message: &phase0.VoluntaryExit{
				Epoch:          phase0.Epoch(epoch),
				ValidatorIndex: phase0.ValidatorIndex(validatorIndex),
			},
			Signature: signature,
		}
	}

	// unmarshal SyncAggregate
	syncAggregate := body.Get(jsonSyncAggregate)

	syncCommitteeSignature, err := convertTo96ByteArray(syncAggregate.GetStringBytes(jsonSyncCommitteeSignature))
	if err != nil {
		return nil, err
	}

	// unmarshal ExecutionPayloadHeader
	executionPayloadHeader := body.Get(jsonExecutionPayloadHeader)

	parentHash, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonParentHash))
	if err != nil {
		return nil, err
	}

	feeRecipient, err := convertTo20ByteArray(executionPayloadHeader.GetStringBytes(jsonFeeRecipient))
	if err != nil {
		return nil, err
	}

	executionPayloadHeaderStateRoot, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonStateRoot))
	if err != nil {
		return nil, err
	}

	receiptsRoot, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonReceiptsRoot))
	if err != nil {
		return nil, err
	}

	logsBloom, err := convertTo256ByteArray(executionPayloadHeader.GetStringBytes(jsonLogsBloom))
	if err != nil {
		return nil, err
	}

	prevRandao, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonPrevRandao))
	if err != nil {
		return nil, err
	}

	blockNumber, err := convertToUint64(executionPayloadHeader.GetStringBytes(jsonBlockNumber))
	if err != nil {
		return nil, err
	}

	gasLimit, err := convertToUint64(executionPayloadHeader.GetStringBytes(jsonGasLimit))
	if err != nil {
		return nil, err
	}

	gasUsed, err := convertToUint64(executionPayloadHeader.GetStringBytes(jsonGasUsed))
	if err != nil {
		return nil, err
	}

	timestamp, err := convertToUint64(executionPayloadHeader.GetStringBytes(jsonTimestamp))
	if err != nil {
		return nil, err
	}

	baseFeePerGas, err := convertBaseFeePerGas(executionPayloadHeader.GetStringBytes(jsonBaseFeePerGas))
	if err != nil {
		return nil, err
	}

	blockHash, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonBlockHash))
	if err != nil {
		return nil, err
	}

	transactionsRoot, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonTransactionsRoot))
	if err != nil {
		return nil, err
	}

	withdrawalsRoot, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonWithdrawalsRoot))
	if err != nil {
		return nil, err
	}

	// unmarshal BLSToExecutionChanges slice
	blsToExecutionChangesValues := body.GetArray(jsonBLSToExecutionChanges)
	blsToExecutionChanges := make([]*capella.SignedBLSToExecutionChange, len(blsToExecutionChangesValues))
	for i, blsToExecutionChangeValue := range blsToExecutionChangesValues {
		message := blsToExecutionChangeValue.Get(jsonMessage)

		validatorIndex, err := convertToUint64(message.GetStringBytes(jsonValidatorIndex))
		if err != nil {
			return nil, err
		}

		fromBLSPubkey, err := convertTo48ByteArray(message.GetStringBytes(jsonFromBLSPubkey))
		if err != nil {
			return nil, err
		}

		toExecutionAddress, err := convertTo20ByteArray(message.GetStringBytes(jsonToExecutionAddress))
		if err != nil {
			return nil, err
		}

		signature, err := convertTo96ByteArray(blsToExecutionChangeValue.GetStringBytes(jsonSignature))
		if err != nil {
			return nil, err
		}

		blsToExecutionChanges[i] = &capella.SignedBLSToExecutionChange{
			Message: &capella.BLSToExecutionChange{
				ValidatorIndex:     phase0.ValidatorIndex(validatorIndex),
				FromBLSPubkey:      fromBLSPubkey,
				ToExecutionAddress: toExecutionAddress,
			},
			Signature: signature,
		}
	}

	return &capellaapi.BlindedBeaconBlockBody{
		RANDAOReveal: randaoReveal,
		ETH1Data: &phase0.ETH1Data{
			DepositRoot:  depositRoot,
			DepositCount: depositCount,
			BlockHash:    convertToBytes(eth1Data.GetStringBytes(jsonBlockHash)),
		},
		Graffiti:          graffiti,
		ProposerSlashings: proposerSlashings,
		AttesterSlashings: attesterSlashings,
		Attestations:      attestations,
		Deposits:          deposits,
		VoluntaryExits:    voluntaryExits,
		SyncAggregate: &altair.SyncAggregate{
			SyncCommitteeBits:      convertToBytes(syncAggregate.GetStringBytes(jsonSyncCommitteeBits)),
			SyncCommitteeSignature: syncCommitteeSignature,
		},
		ExecutionPayloadHeader: &capella.ExecutionPayloadHeader{
			ParentHash:       parentHash,
			FeeRecipient:     feeRecipient,
			StateRoot:        executionPayloadHeaderStateRoot,
			ReceiptsRoot:     receiptsRoot,
			LogsBloom:        logsBloom,
			PrevRandao:       prevRandao,
			BlockNumber:      blockNumber,
			GasLimit:         gasLimit,
			GasUsed:          gasUsed,
			Timestamp:        timestamp,
			ExtraData:        convertToBytes(executionPayloadHeader.GetStringBytes(jsonExtraData)),
			BaseFeePerGas:    baseFeePerGas,
			BlockHash:        blockHash,
			TransactionsRoot: transactionsRoot,
			WithdrawalsRoot:  withdrawalsRoot,
		},
		BLSToExecutionChanges: blsToExecutionChanges,
	}, nil
}

func UnmarshalToBlindedBeaconBlockBodyDeneb(body *fastjson.Value) (*deneb.BlindedBeaconBlockBody, error) {
	randaoReveal, err := convertTo96ByteArray(body.GetStringBytes(jsonRandaoReveal))
	if err != nil {
		return nil, err
	}

	eth1Data := body.Get(jsonETH1Data)

	depositRoot, err := convertTo32ByteArray(eth1Data.GetStringBytes(jsonDepositRoot))
	if err != nil {
		return nil, err
	}

	depositCount, err := convertToUint64(eth1Data.GetStringBytes(jsonDepositCount))
	if err != nil {
		return nil, err
	}

	graffiti, err := convertTo32ByteArray(body.GetStringBytes(jsonGraffiti))
	if err != nil {
		return nil, err
	}

	// unmarshal ProposerSlashing slice
	proposerSlashingsValues := body.GetArray(jsonProposerSlashings)
	proposerSlashings := make([]*phase0.ProposerSlashing, len(proposerSlashingsValues))
	for i, proposerSlashingValue := range proposerSlashingsValues {
		signedHeader1, err := unmarshalToSignedBeaconBlockHeader(proposerSlashingValue.Get(jsonSignedHeader1))
		if err != nil {
			return nil, err
		}

		signedHeader2, err := unmarshalToSignedBeaconBlockHeader(proposerSlashingValue.Get(jsonSignedHeader2))
		if err != nil {
			return nil, err
		}

		proposerSlashings[i] = &phase0.ProposerSlashing{
			SignedHeader1: signedHeader1,
			SignedHeader2: signedHeader2,
		}
	}

	// unmarshal AttesterSlashing slice
	attesterSlashingsValues := body.GetArray(jsonAttesterSlashings)
	attesterSlashings := make([]*phase0.AttesterSlashing, len(attesterSlashingsValues))
	for i, attesterSlashingValue := range attesterSlashingsValues {
		attestation1, err := unmarshalToIndexedAttestation(attesterSlashingValue.Get(jsonAttestation1))
		if err != nil {
			return nil, err
		}

		attestation2, err := unmarshalToIndexedAttestation(attesterSlashingValue.Get(jsonAttestation2))
		if err != nil {
			return nil, err
		}

		attesterSlashings[i] = &phase0.AttesterSlashing{
			Attestation1: attestation1,
			Attestation2: attestation2,
		}
	}

	// unmarshal Attestation slice
	attestationsValues := body.GetArray(jsonAttestations)
	attestations := make([]*phase0.Attestation, len(attestationsValues))
	for i, attestationValue := range attestationsValues {
		data, err := unmarshalToAttestationData(attestationValue.Get(jsonData))
		if err != nil {
			return nil, err
		}

		signature, err := convertTo96ByteArray(attestationValue.GetStringBytes(jsonSignature))
		if err != nil {
			return nil, err
		}

		attestations[i] = &phase0.Attestation{
			AggregationBits: convertToBytes(attestationValue.GetStringBytes(jsonAggregationBits)),
			Data:            data,
			Signature:       signature,
		}
	}

	// unmarshal Deposit slice
	depositsValues := body.GetArray(jsonDeposits)
	deposits := make([]*phase0.Deposit, len(depositsValues))
	for i, depositValue := range depositsValues {
		proofValues := depositValue.GetArray(jsonProof)
		proof := make([][]byte, len(proofValues))
		for i, proofValue := range proofValues {
			proofBytes, err := proofValue.StringBytes()
			if err != nil {
				return nil, err
			}

			proof[i] = convertToBytes(proofBytes)
		}

		data := depositValue.Get(jsonData)

		publicKey, err := convertTo48ByteArray(data.GetStringBytes(jsonPublicKey))
		if err != nil {
			return nil, err
		}

		amount, err := convertToUint64(data.GetStringBytes(jsonAmount))
		if err != nil {
			return nil, err
		}

		signature, err := convertTo96ByteArray(data.GetStringBytes(jsonSignature))
		if err != nil {
			return nil, err
		}

		deposits[i] = &phase0.Deposit{
			Proof: proof,
			Data: &phase0.DepositData{
				PublicKey:             publicKey,
				WithdrawalCredentials: convertToBytes(data.GetStringBytes(jsonWithdrawalCredentials)),
				Amount:                phase0.Gwei(amount),
				Signature:             signature,
			},
		}
	}

	// unmarshal SignedVoluntaryExit slice
	voluntaryExitsValues := body.GetArray(jsonVoluntaryExits)
	voluntaryExits := make([]*phase0.SignedVoluntaryExit, len(voluntaryExitsValues))
	for i, voluntaryExitValue := range voluntaryExitsValues {
		message := voluntaryExitValue.Get(jsonMessage)

		epoch, err := convertToUint64(message.GetStringBytes(jsonEpoch))
		if err != nil {
			return nil, err
		}

		validatorIndex, err := convertToUint64(message.GetStringBytes(jsonValidatorIndex))
		if err != nil {
			return nil, err
		}

		signature, err := convertTo96ByteArray(voluntaryExitValue.GetStringBytes(jsonSignature))
		if err != nil {
			return nil, err
		}

		voluntaryExits[i] = &phase0.SignedVoluntaryExit{
			Message: &phase0.VoluntaryExit{
				Epoch:          phase0.Epoch(epoch),
				ValidatorIndex: phase0.ValidatorIndex(validatorIndex),
			},
			Signature: signature,
		}
	}

	// unmarshal SyncAggregate
	syncAggregate := body.Get(jsonSyncAggregate)

	syncCommitteeSignature, err := convertTo96ByteArray(syncAggregate.GetStringBytes(jsonSyncCommitteeSignature))
	if err != nil {
		return nil, err
	}

	// unmarshal ExecutionPayloadHeader
	executionPayloadHeader := body.Get(jsonExecutionPayloadHeader)

	parentHash, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonParentHash))
	if err != nil {
		return nil, err
	}

	feeRecipient, err := convertTo20ByteArray(executionPayloadHeader.GetStringBytes(jsonFeeRecipient))
	if err != nil {
		return nil, err
	}

	executionPayloadHeaderStateRoot, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonStateRoot))
	if err != nil {
		return nil, err
	}

	receiptsRoot, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonReceiptsRoot))
	if err != nil {
		return nil, err
	}

	logsBloom, err := convertTo256ByteArray(executionPayloadHeader.GetStringBytes(jsonLogsBloom))
	if err != nil {
		return nil, err
	}

	prevRandao, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonPrevRandao))
	if err != nil {
		return nil, err
	}

	blockNumber, err := convertToUint64(executionPayloadHeader.GetStringBytes(jsonBlockNumber))
	if err != nil {
		return nil, err
	}

	gasLimit, err := convertToUint64(executionPayloadHeader.GetStringBytes(jsonGasLimit))
	if err != nil {
		return nil, err
	}

	gasUsed, err := convertToUint64(executionPayloadHeader.GetStringBytes(jsonGasUsed))
	if err != nil {
		return nil, err
	}

	timestamp, err := convertToUint64(executionPayloadHeader.GetStringBytes(jsonTimestamp))
	if err != nil {
		return nil, err
	}

	var baseFeePerGas *uint256.Int
	tmpBytes := bytes.Trim(executionPayloadHeader.GetStringBytes(jsonBaseFeePerGas), `"`)
	if bytes.HasPrefix(tmpBytes, []byte{'0', 'x'}) {
		baseFeePerGas, err = uint256.FromHex(string(tmpBytes))
	} else {
		baseFeePerGas, err = uint256.FromDecimal(string(tmpBytes))
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to set Deneb base fee per gas")
	}

	blockHash, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonBlockHash))
	if err != nil {
		return nil, err
	}

	transactionsRoot, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonTransactionsRoot))
	if err != nil {
		return nil, err
	}

	withdrawalsRoot, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonWithdrawalsRoot))
	if err != nil {
		return nil, err
	}

	// blobGasUsed may be left out of Deneb blinded beacon block body,
	// so we check for its existence before converting to uint64
	var blobGasUsed uint64
	if executionPayloadHeader.Exists(jsonBlobGasUsed) {
		blobGasUsed, err = convertToUint64(executionPayloadHeader.GetStringBytes(jsonBlobGasUsed))
		if err != nil {
			return nil, err
		}
	}

	// excessBlobGas may be left out of Deneb blinded beacon block body,
	// so we check for its existence before converting to uint64
	var excessBlobGas uint64
	if executionPayloadHeader.Exists(jsonExcessBlobGas) {
		excessBlobGas, err = convertToUint64(executionPayloadHeader.GetStringBytes(jsonExcessBlobGas))
		if err != nil {
			return nil, err
		}
	}

	// unmarshal BLSToExecutionChanges slice
	blsToExecutionChangesValues := body.GetArray(jsonBLSToExecutionChanges)
	blsToExecutionChanges := make([]*capella.SignedBLSToExecutionChange, len(blsToExecutionChangesValues))
	for i, blsToExecutionChangeValue := range blsToExecutionChangesValues {
		message := blsToExecutionChangeValue.Get(jsonMessage)

		validatorIndex, err := convertToUint64(message.GetStringBytes(jsonValidatorIndex))
		if err != nil {
			return nil, err
		}

		fromBLSPubkey, err := convertTo48ByteArray(message.GetStringBytes(jsonFromBLSPubkey))
		if err != nil {
			return nil, err
		}

		toExecutionAddress, err := convertTo20ByteArray(message.GetStringBytes(jsonToExecutionAddress))
		if err != nil {
			return nil, err
		}

		signature, err := convertTo96ByteArray(blsToExecutionChangeValue.GetStringBytes(jsonSignature))
		if err != nil {
			return nil, err
		}

		blsToExecutionChanges[i] = &capella.SignedBLSToExecutionChange{
			Message: &capella.BLSToExecutionChange{
				ValidatorIndex:     phase0.ValidatorIndex(validatorIndex),
				FromBLSPubkey:      fromBLSPubkey,
				ToExecutionAddress: toExecutionAddress,
			},
			Signature: signature,
		}
	}

	// unmarshal BlobKZGCommitments slice
	rawBlobKZGCommitments := body.Get(jsonBlobKZGCommitments)
	if rawBlobKZGCommitments == nil {
		return nil, errors.New("blob KZG commitments missing")
	}

	if rawBlobKZGCommitments.Type() != fastjson.TypeArray {
		return nil, errors.New("invalid type for blob KZG commitment")
	}

	blobKZGCommitmentsValues := body.GetArray(jsonBlobKZGCommitments)
	blobKZGCommitments := make([]deneb2.KZGCommitment, len(blobKZGCommitmentsValues))
	for i, blobKZGCommitment := range blobKZGCommitmentsValues {
		blobKZGCommitmentBytes, err := blobKZGCommitment.StringBytes()
		if err != nil {
			return nil, err
		}

		blobKZGCommitmentBytesString := string(blobKZGCommitmentBytes)
		_, err = hex.DecodeString(strings.TrimPrefix(blobKZGCommitmentBytesString, "0x"))
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse blob KZG commitment")
		}

		if len(blobKZGCommitmentBytes) != kzgCommitmentJSONBytesLength {
			return nil, errors.New("incorrect length for blob KZG commitment")
		}

		commitment, err := convertTo48ByteArray(blobKZGCommitmentBytes)
		if err != nil {
			return nil, err
		}

		blobKZGCommitments[i] = commitment
	}

	return &deneb.BlindedBeaconBlockBody{
		RANDAOReveal: randaoReveal,
		ETH1Data: &phase0.ETH1Data{
			DepositRoot:  depositRoot,
			DepositCount: depositCount,
			BlockHash:    convertToBytes(eth1Data.GetStringBytes(jsonBlockHash)),
		},
		Graffiti:          graffiti,
		ProposerSlashings: proposerSlashings,
		AttesterSlashings: attesterSlashings,
		Attestations:      attestations,
		Deposits:          deposits,
		VoluntaryExits:    voluntaryExits,
		SyncAggregate: &altair.SyncAggregate{
			SyncCommitteeBits:      convertToBytes(syncAggregate.GetStringBytes(jsonSyncCommitteeBits)),
			SyncCommitteeSignature: syncCommitteeSignature,
		},
		ExecutionPayloadHeader: &deneb2.ExecutionPayloadHeader{
			ParentHash:       parentHash,
			FeeRecipient:     feeRecipient,
			StateRoot:        executionPayloadHeaderStateRoot,
			ReceiptsRoot:     receiptsRoot,
			LogsBloom:        logsBloom,
			PrevRandao:       prevRandao,
			BlockNumber:      blockNumber,
			GasLimit:         gasLimit,
			GasUsed:          gasUsed,
			Timestamp:        timestamp,
			ExtraData:        convertToBytes(executionPayloadHeader.GetStringBytes(jsonExtraData)),
			BaseFeePerGas:    baseFeePerGas,
			BlockHash:        blockHash,
			TransactionsRoot: transactionsRoot,
			WithdrawalsRoot:  withdrawalsRoot,
			BlobGasUsed:      blobGasUsed,
			ExcessBlobGas:    excessBlobGas,
		},
		BLSToExecutionChanges: blsToExecutionChanges,
		BlobKZGCommitments:    blobKZGCommitments,
	}, nil
}

func UnmarshalToBlindedBeaconBlockBodyElectra(body *fastjson.Value) (*electra.BlindedBeaconBlockBody, error) {
	randaoReveal, err := convertTo96ByteArray(body.GetStringBytes(jsonRandaoReveal))
	if err != nil {
		return nil, err
	}

	eth1Data := body.Get(jsonETH1Data)

	depositRoot, err := convertTo32ByteArray(eth1Data.GetStringBytes(jsonDepositRoot))
	if err != nil {
		return nil, err
	}

	depositCount, err := convertToUint64(eth1Data.GetStringBytes(jsonDepositCount))
	if err != nil {
		return nil, err
	}

	graffiti, err := convertTo32ByteArray(body.GetStringBytes(jsonGraffiti))
	if err != nil {
		return nil, err
	}

	// unmarshal ProposerSlashing slice
	proposerSlashingsValues := body.GetArray(jsonProposerSlashings)
	proposerSlashings := make([]*phase0.ProposerSlashing, len(proposerSlashingsValues))
	for i, proposerSlashingValue := range proposerSlashingsValues {
		signedHeader1, err := unmarshalToSignedBeaconBlockHeader(proposerSlashingValue.Get(jsonSignedHeader1))
		if err != nil {
			return nil, err
		}

		signedHeader2, err := unmarshalToSignedBeaconBlockHeader(proposerSlashingValue.Get(jsonSignedHeader2))
		if err != nil {
			return nil, err
		}

		proposerSlashings[i] = &phase0.ProposerSlashing{
			SignedHeader1: signedHeader1,
			SignedHeader2: signedHeader2,
		}
	}

	// unmarshal AttesterSlashing slice
	attesterSlashingsValues := body.GetArray(jsonAttesterSlashings)
	attesterSlashings := make([]*electraspec.AttesterSlashing, len(attesterSlashingsValues))
	for i, attesterSlashingValue := range attesterSlashingsValues {
		attestation1, err := unmarshalToIndexedElectraAttestation(attesterSlashingValue.Get(jsonAttestation1))
		if err != nil {
			return nil, err
		}

		attestation2, err := unmarshalToIndexedElectraAttestation(attesterSlashingValue.Get(jsonAttestation2))
		if err != nil {
			return nil, err
		}

		attesterSlashings[i] = &electraspec.AttesterSlashing{
			Attestation1: attestation1,
			Attestation2: attestation2,
		}
	}

	// unmarshal Attestation slice
	attestationsValues := body.GetArray(jsonAttestations)
	attestations := make([]*electraspec.Attestation, len(attestationsValues))
	for i, attestationValue := range attestationsValues {
		data, err := unmarshalToAttestationData(attestationValue.Get(jsonData))
		if err != nil {
			return nil, err
		}

		signature, err := convertTo96ByteArray(attestationValue.GetStringBytes(jsonSignature))
		if err != nil {
			return nil, err
		}

		committeBits, err := convertTo8ByteArray(attestationValue.GetStringBytes(jsonCommitteeBits))
		if err != nil {
			return nil, err
		}

		attestations[i] = &electraspec.Attestation{
			AggregationBits: convertToBytes(attestationValue.GetStringBytes(jsonAggregationBits)),
			Data:            data,
			Signature:       signature,
			CommitteeBits:   committeBits[:],
		}
	}

	// unmarshal Deposit slice
	depositsValues := body.GetArray(jsonDeposits)
	deposits := make([]*phase0.Deposit, len(depositsValues))
	for i, depositValue := range depositsValues {
		proofValues := depositValue.GetArray(jsonProof)
		proof := make([][]byte, len(proofValues))
		for i, proofValue := range proofValues {
			proofBytes, err := proofValue.StringBytes()
			if err != nil {
				return nil, err
			}

			proof[i] = convertToBytes(proofBytes)
		}

		data := depositValue.Get(jsonData)

		publicKey, err := convertTo48ByteArray(data.GetStringBytes(jsonPublicKey))
		if err != nil {
			return nil, err
		}

		amount, err := convertToUint64(data.GetStringBytes(jsonAmount))
		if err != nil {
			return nil, err
		}

		signature, err := convertTo96ByteArray(data.GetStringBytes(jsonSignature))
		if err != nil {
			return nil, err
		}

		deposits[i] = &phase0.Deposit{
			Proof: proof,
			Data: &phase0.DepositData{
				PublicKey:             publicKey,
				WithdrawalCredentials: convertToBytes(data.GetStringBytes(jsonWithdrawalCredentials)),
				Amount:                phase0.Gwei(amount),
				Signature:             signature,
			},
		}
	}

	// unmarshal SignedVoluntaryExit slice
	voluntaryExitsValues := body.GetArray(jsonVoluntaryExits)
	voluntaryExits := make([]*phase0.SignedVoluntaryExit, len(voluntaryExitsValues))
	for i, voluntaryExitValue := range voluntaryExitsValues {
		message := voluntaryExitValue.Get(jsonMessage)

		epoch, err := convertToUint64(message.GetStringBytes(jsonEpoch))
		if err != nil {
			return nil, err
		}

		validatorIndex, err := convertToUint64(message.GetStringBytes(jsonValidatorIndex))
		if err != nil {
			return nil, err
		}

		signature, err := convertTo96ByteArray(voluntaryExitValue.GetStringBytes(jsonSignature))
		if err != nil {
			return nil, err
		}

		voluntaryExits[i] = &phase0.SignedVoluntaryExit{
			Message: &phase0.VoluntaryExit{
				Epoch:          phase0.Epoch(epoch),
				ValidatorIndex: phase0.ValidatorIndex(validatorIndex),
			},
			Signature: signature,
		}
	}

	// unmarshal SyncAggregate
	syncAggregate := body.Get(jsonSyncAggregate)

	syncCommitteeSignature, err := convertTo96ByteArray(syncAggregate.GetStringBytes(jsonSyncCommitteeSignature))
	if err != nil {
		return nil, err
	}

	// unmarshal ExecutionPayloadHeader
	executionPayloadHeader := body.Get(jsonExecutionPayloadHeader)

	parentHash, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonParentHash))
	if err != nil {
		return nil, err
	}

	feeRecipient, err := convertTo20ByteArray(executionPayloadHeader.GetStringBytes(jsonFeeRecipient))
	if err != nil {
		return nil, err
	}

	executionPayloadHeaderStateRoot, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonStateRoot))
	if err != nil {
		return nil, err
	}

	receiptsRoot, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonReceiptsRoot))
	if err != nil {
		return nil, err
	}

	logsBloom, err := convertTo256ByteArray(executionPayloadHeader.GetStringBytes(jsonLogsBloom))
	if err != nil {
		return nil, err
	}

	prevRandao, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonPrevRandao))
	if err != nil {
		return nil, err
	}

	blockNumber, err := convertToUint64(executionPayloadHeader.GetStringBytes(jsonBlockNumber))
	if err != nil {
		return nil, err
	}

	gasLimit, err := convertToUint64(executionPayloadHeader.GetStringBytes(jsonGasLimit))
	if err != nil {
		return nil, err
	}

	gasUsed, err := convertToUint64(executionPayloadHeader.GetStringBytes(jsonGasUsed))
	if err != nil {
		return nil, err
	}

	timestamp, err := convertToUint64(executionPayloadHeader.GetStringBytes(jsonTimestamp))
	if err != nil {
		return nil, err
	}

	var baseFeePerGas *uint256.Int
	tmpBytes := bytes.Trim(executionPayloadHeader.GetStringBytes(jsonBaseFeePerGas), `"`)
	if bytes.HasPrefix(tmpBytes, []byte{'0', 'x'}) {
		baseFeePerGas, err = uint256.FromHex(string(tmpBytes))
	} else {
		baseFeePerGas, err = uint256.FromDecimal(string(tmpBytes))
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to set electra base fee per gas")
	}

	blockHash, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonBlockHash))
	if err != nil {
		return nil, err
	}

	transactionsRoot, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonTransactionsRoot))
	if err != nil {
		return nil, err
	}

	withdrawalsRoot, err := convertTo32ByteArray(executionPayloadHeader.GetStringBytes(jsonWithdrawalsRoot))
	if err != nil {
		return nil, err
	}

	// blobGasUsed may be left out of Deneb blinded beacon block body,
	// so we check for its existence before converting to uint64
	var blobGasUsed uint64
	if executionPayloadHeader.Exists(jsonBlobGasUsed) {
		blobGasUsed, err = convertToUint64(executionPayloadHeader.GetStringBytes(jsonBlobGasUsed))
		if err != nil {
			return nil, err
		}
	}

	// excessBlobGas may be left out of Deneb blinded beacon block body,
	// so we check for its existence before converting to uint64
	var excessBlobGas uint64
	if executionPayloadHeader.Exists(jsonExcessBlobGas) {
		excessBlobGas, err = convertToUint64(executionPayloadHeader.GetStringBytes(jsonExcessBlobGas))
		if err != nil {
			return nil, err
		}
	}

	// unmarshal BLSToExecutionChanges slice
	blsToExecutionChangesValues := body.GetArray(jsonBLSToExecutionChanges)
	blsToExecutionChanges := make([]*capella.SignedBLSToExecutionChange, len(blsToExecutionChangesValues))
	for i, blsToExecutionChangeValue := range blsToExecutionChangesValues {
		message := blsToExecutionChangeValue.Get(jsonMessage)

		validatorIndex, err := convertToUint64(message.GetStringBytes(jsonValidatorIndex))
		if err != nil {
			return nil, err
		}

		fromBLSPubkey, err := convertTo48ByteArray(message.GetStringBytes(jsonFromBLSPubkey))
		if err != nil {
			return nil, err
		}

		toExecutionAddress, err := convertTo20ByteArray(message.GetStringBytes(jsonToExecutionAddress))
		if err != nil {
			return nil, err
		}

		signature, err := convertTo96ByteArray(blsToExecutionChangeValue.GetStringBytes(jsonSignature))
		if err != nil {
			return nil, err
		}

		blsToExecutionChanges[i] = &capella.SignedBLSToExecutionChange{
			Message: &capella.BLSToExecutionChange{
				ValidatorIndex:     phase0.ValidatorIndex(validatorIndex),
				FromBLSPubkey:      fromBLSPubkey,
				ToExecutionAddress: toExecutionAddress,
			},
			Signature: signature,
		}
	}

	// unmarshal BlobKZGCommitments slice
	rawBlobKZGCommitments := body.Get(jsonBlobKZGCommitments)
	if rawBlobKZGCommitments == nil {
		return nil, errors.New("blob KZG commitments missing")
	}

	if rawBlobKZGCommitments.Type() != fastjson.TypeArray {
		return nil, errors.New("invalid type for blob KZG commitment")
	}

	blobKZGCommitmentsValues := body.GetArray(jsonBlobKZGCommitments)
	blobKZGCommitments := make([]deneb2.KZGCommitment, len(blobKZGCommitmentsValues))
	for i, blobKZGCommitment := range blobKZGCommitmentsValues {
		blobKZGCommitmentBytes, err := blobKZGCommitment.StringBytes()
		if err != nil {
			return nil, err
		}

		blobKZGCommitmentBytesString := string(blobKZGCommitmentBytes)
		_, err = hex.DecodeString(strings.TrimPrefix(blobKZGCommitmentBytesString, "0x"))
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse blob KZG commitment")
		}

		if len(blobKZGCommitmentBytes) != kzgCommitmentJSONBytesLength {
			return nil, errors.New("incorrect length for blob KZG commitment")
		}

		commitment, err := convertTo48ByteArray(blobKZGCommitmentBytes)
		if err != nil {
			return nil, err
		}

		blobKZGCommitments[i] = commitment
	}

	executionRequestsJSON := body.Get(jsonExecutionRequests)
	if executionRequestsJSON == nil {
		return nil, errors.New("execution requests missing")
	}
	depositRequestsJSON := executionRequestsJSON.GetArray(jsonDeposits)
	withdrawalRequestsJSON := executionRequestsJSON.GetArray(jsonWithdrawalRequests)
	consolidationRequestsJSON := executionRequestsJSON.GetArray(jsonConsolidationRequests)

	depositRequests := make([]*electraspec.DepositRequest, len(depositRequestsJSON))
	withdrawalRequests := make([]*electraspec.WithdrawalRequest, len(withdrawalRequestsJSON))
	consolidationRequests := make([]*electraspec.ConsolidationRequest, len(consolidationRequestsJSON))
	for i, depositRequest := range depositRequestsJSON {
		depositRequestPubkey, err := convertTo48ByteArray(depositRequest.GetStringBytes(jsonPublicKey))
		if err != nil {
			return nil, err
		}
		depositRequestWithdrawalCredential, err := convertTo32ByteArray(depositRequest.GetStringBytes(jsonWithdrawalCredentials))
		if err != nil {
			return nil, err
		}
		depositRequestAmount, err := convertToUint64(depositRequest.GetStringBytes(jsonAmount))
		if err != nil {
			return nil, err
		}
		depositRequestSignature, err := convertTo96ByteArray(depositRequest.GetStringBytes(jsonSignature))
		if err != nil {
			return nil, err
		}
		depositRequestIndex, err := convertToUint64(depositRequest.GetStringBytes(jsonIndex))
		if err != nil {
			return nil, err
		}
		depositRequests[i] = &electraspec.DepositRequest{
			Pubkey:                depositRequestPubkey,
			WithdrawalCredentials: depositRequestWithdrawalCredential[:],
			Amount:                phase0.Gwei(depositRequestAmount),
			Signature:             depositRequestSignature,
			Index:                 depositRequestIndex,
		}
	}

	for i, withdrawalRequest := range withdrawalRequestsJSON {
		withdrawalRequestSourceAddress, err := convertTo20ByteArray(withdrawalRequest.GetStringBytes(jsonSourceAddress))
		if err != nil {
			return nil, err
		}
		withdrawalRequestValidatorPubkey, err := convertTo48ByteArray(withdrawalRequest.GetStringBytes(jsonValidatorPubkey))
		if err != nil {
			return nil, err
		}
		withdrawalRequestAmount, err := convertToUint64(withdrawalRequest.GetStringBytes(jsonAmount))
		if err != nil {
			return nil, err
		}
		withdrawalRequests[i] = &electraspec.WithdrawalRequest{
			SourceAddress:   withdrawalRequestSourceAddress,
			ValidatorPubkey: withdrawalRequestValidatorPubkey,
			Amount:          phase0.Gwei(withdrawalRequestAmount),
		}
	}

	for i, consolidationRequest := range consolidationRequestsJSON {
		consolidationRequestSourceAddress, err := convertTo20ByteArray(consolidationRequest.GetStringBytes(jsonSourceAddress))
		if err != nil {
			return nil, err
		}
		consolidationRequestSourcePubkey, err := convertTo48ByteArray(consolidationRequest.GetStringBytes(jsonSourcePubkey))
		if err != nil {
			return nil, err
		}
		consolidationRequestTargetPubkey, err := convertTo48ByteArray(consolidationRequest.GetStringBytes(jsonTargetPubkey))
		if err != nil {
			return nil, err
		}
		consolidationRequests[i] = &electraspec.ConsolidationRequest{
			SourceAddress: consolidationRequestSourceAddress,
			SourcePubkey:  consolidationRequestSourcePubkey,
			TargetPubkey:  consolidationRequestTargetPubkey,
		}
	}
	executionRequests := &electraspec.ExecutionRequests{
		Deposits:       depositRequests,
		Withdrawals:    withdrawalRequests,
		Consolidations: consolidationRequests,
	}
	return &electra.BlindedBeaconBlockBody{
		RANDAOReveal: randaoReveal,
		ETH1Data: &phase0.ETH1Data{
			DepositRoot:  depositRoot,
			DepositCount: depositCount,
			BlockHash:    convertToBytes(eth1Data.GetStringBytes(jsonBlockHash)),
		},
		Graffiti:          graffiti,
		ProposerSlashings: proposerSlashings,
		AttesterSlashings: attesterSlashings,
		Attestations:      attestations,
		Deposits:          deposits,
		VoluntaryExits:    voluntaryExits,
		SyncAggregate: &altair.SyncAggregate{
			SyncCommitteeBits:      convertToBytes(syncAggregate.GetStringBytes(jsonSyncCommitteeBits)),
			SyncCommitteeSignature: syncCommitteeSignature,
		},
		ExecutionPayloadHeader: &deneb2.ExecutionPayloadHeader{
			ParentHash:       parentHash,
			FeeRecipient:     feeRecipient,
			StateRoot:        executionPayloadHeaderStateRoot,
			ReceiptsRoot:     receiptsRoot,
			LogsBloom:        logsBloom,
			PrevRandao:       prevRandao,
			BlockNumber:      blockNumber,
			GasLimit:         gasLimit,
			GasUsed:          gasUsed,
			Timestamp:        timestamp,
			ExtraData:        convertToBytes(executionPayloadHeader.GetStringBytes(jsonExtraData)),
			BaseFeePerGas:    baseFeePerGas,
			BlockHash:        blockHash,
			TransactionsRoot: transactionsRoot,
			WithdrawalsRoot:  withdrawalsRoot,
			BlobGasUsed:      blobGasUsed,
			ExcessBlobGas:    excessBlobGas,
		},
		BLSToExecutionChanges: blsToExecutionChanges,
		BlobKZGCommitments:    blobKZGCommitments,
		ExecutionRequests:     executionRequests,
	}, nil
}
