package fastjson

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	proxycommon "github.com/bloXroute-Labs/relayproxy/common"
	"github.com/ethereum/go-ethereum/common"
	"github.com/flashbots/go-boost-utils/bls"

	"github.com/valyala/fastjson/fastfloat"
)

func CheckProposerSignature(ethNetwork *proxycommon.EthNetworkDetails, block *proxycommon.VersionedSignedBlindedBeaconBlock, pubKey []byte) (bool, error) {
	switch block.Version {
	case spec.DataVersionCapella:
		return verifyBlockSignature(block, ethNetwork.DomainBeaconProposerCapella, pubKey)
	case spec.DataVersionDeneb:
		return verifyBlockSignature(block, ethNetwork.DomainBeaconProposerDeneb, pubKey)
	default:
		return false, errors.New("unsupported consensus data version")
	}
}
func convertTo20ByteArray(stringBytes []byte) ([bytes20Length]byte, error) {
	if len(stringBytes) == 0 {
		return [bytes20Length]byte{}, errors.New("string bytes slice is empty")
	}

	if has0xPrefix(stringBytes) {
		stringBytes = common.Hex2BytesFixed(string(stringBytes[hexPrefixByteLength:]), bytes20Length)
	}

	bytesLength := len(stringBytes)
	if bytesLength != bytes20Length {
		return [bytes20Length]byte{}, fmt.Errorf("input bytes length %v does not equal expected bytes length %v", bytesLength, bytes20Length)
	}

	array := [bytes20Length]byte{}
	copy(array[:bytesLength], stringBytes[:])

	return array, nil
}

func convertTo32ByteArray(stringBytes []byte) ([bytes32Length]byte, error) {
	if len(stringBytes) == 0 {
		return [bytes32Length]byte{}, errors.New("string bytes slice is empty")
	}

	if has0xPrefix(stringBytes) {
		stringBytes = common.Hex2BytesFixed(string(stringBytes[hexPrefixByteLength:]), bytes32Length)
	}

	bytesLength := len(stringBytes)
	if bytesLength != bytes32Length {
		return [bytes32Length]byte{}, fmt.Errorf("input bytes length %v does not equal expected bytes length %v", bytesLength, bytes32Length)
	}

	array := [bytes32Length]byte{}
	copy(array[:bytesLength], stringBytes[:])

	return array, nil
}

func convertTo48ByteArray(stringBytes []byte) ([bytes48Length]byte, error) {
	if len(stringBytes) == 0 {
		return [bytes48Length]byte{}, errors.New("string bytes slice is empty")
	}

	if has0xPrefix(stringBytes) {
		stringBytes = common.Hex2BytesFixed(string(stringBytes[hexPrefixByteLength:]), bytes48Length)
	}

	bytesLength := len(stringBytes)
	if bytesLength != bytes48Length {
		return [bytes48Length]byte{}, fmt.Errorf("input bytes length %v does not equal expected bytes length %v", bytesLength, bytes48Length)
	}

	array := [bytes48Length]byte{}
	copy(array[:bytesLength], stringBytes[:])

	return array, nil
}

func convertTo96ByteArray(stringBytes []byte) ([bytes96Length]byte, error) {
	if len(stringBytes) == 0 {
		return [bytes96Length]byte{}, errors.New("string bytes slice is empty")
	}

	if has0xPrefix(stringBytes) {
		stringBytes = common.Hex2BytesFixed(string(stringBytes[hexPrefixByteLength:]), bytes96Length)
	}

	bytesLength := len(stringBytes)
	if bytesLength != bytes96Length {
		return [bytes96Length]byte{}, fmt.Errorf("input bytes length %v does not equal expected bytes length %v", bytesLength, bytes96Length)
	}

	array := [bytes96Length]byte{}
	copy(array[:bytesLength], stringBytes[:])

	return array, nil
}

func convertTo256ByteArray(stringBytes []byte) ([bytes256Length]byte, error) {
	if len(stringBytes) == 0 {
		return [bytes256Length]byte{}, errors.New("string bytes slice is empty")
	}

	if has0xPrefix(stringBytes) {
		stringBytes = common.Hex2BytesFixed(string(stringBytes[hexPrefixByteLength:]), bytes256Length)
	}

	bytesLength := len(stringBytes)
	if bytesLength != bytes256Length {
		return [bytes256Length]byte{}, fmt.Errorf("input bytes length %v does not equal expected bytes length %v", bytesLength, bytes256Length)
	}

	array := [bytes256Length]byte{}
	copy(array[:bytesLength], stringBytes[:])

	return array, nil
}

func convertToUint64(numberStringBytes []byte) (uint64, error) {
	number, err := fastfloat.ParseUint64(string(numberStringBytes))
	if err != nil {
		return 0, err
	}

	return number, nil
}

func convertToBytes(stringBytes []byte) []byte {
	hexString := strings.TrimPrefix(string(stringBytes), hexPrefixString)
	return common.Hex2Bytes(hexString)
}

func convertBaseFeePerGas(stringBytes []byte) ([bytes32Length]byte, error) {
	baseFeePerGasString := string(stringBytes)

	if baseFeePerGasString == "" {
		return [bytes32Length]byte{}, errors.New("base fee per gas missing")
	}
	baseFeePerGas := new(big.Int)
	var ok bool
	input := baseFeePerGasString
	if strings.HasPrefix(baseFeePerGasString, "0x") {
		input = strings.TrimPrefix(input, "0x")
		if len(baseFeePerGasString)%2 == 1 {
			input = fmt.Sprintf("0%s", input)
		}
		baseFeePerGas, ok = baseFeePerGas.SetString(input, 16)
	} else {
		baseFeePerGas, ok = baseFeePerGas.SetString(input, 10)
	}
	if !ok {
		return [bytes32Length]byte{}, errors.New("invalid value for base fee per gas")
	}
	if baseFeePerGas.Cmp(maxBaseFeePerGas) > 0 {
		return [bytes32Length]byte{}, errors.New("overflow for base fee per gas")
	}
	// We need to store internally as little-endian, but big.Int uses
	// big-endian so do it manually.
	baseFeePerGasBEBytes := baseFeePerGas.Bytes()
	var baseFeePerGasLEBytes [32]byte
	baseFeeLen := len(baseFeePerGasBEBytes)
	for i := 0; i < baseFeeLen; i++ {
		baseFeePerGasLEBytes[i] = baseFeePerGasBEBytes[baseFeeLen-1-i]
	}
	return baseFeePerGasLEBytes, nil
}

func has0xPrefix(stringBytes []byte) bool {
	return len(stringBytes) >= hexPrefixByteLength && bytes.Equal(stringBytes[0:hexPrefixByteLength], hexPrefixBytes)
}

func verifyBlockSignature(block *proxycommon.VersionedSignedBlindedBeaconBlock, domain phase0.Domain, pubKey []byte) (bool, error) {
	root, err := block.Root()
	if err != nil {
		return false, err
	}
	sig, err := block.Signature()
	if err != nil {
		return false, err
	}
	signingData := phase0.SigningData{ObjectRoot: root, Domain: domain}
	msg, err := signingData.HashTreeRoot()
	if err != nil {
		return false, err
	}

	return bls.VerifySignatureBytes(msg[:], sig[:], pubKey[:])
}
