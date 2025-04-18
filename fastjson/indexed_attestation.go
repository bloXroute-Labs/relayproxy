package fastjson

import (
	electraspec "github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/valyala/fastjson"
)

func unmarshalToIndexedAttestation(value *fastjson.Value) (*phase0.IndexedAttestation, error) {
	attestingIndicesValues := value.GetArray(jsonAttestingIndices)
	attestingIndices := make([]uint64, len(attestingIndicesValues))
	for i := range attestingIndicesValues {
		// TODO: verify this function change with error handling works properly
		indexBytes, err := attestingIndicesValues[i].StringBytes()
		if err != nil {
			return nil, err
		}

		index, err := convertToUint64(indexBytes)
		if err != nil {
			return nil, err
		}

		attestingIndices[i] = index
	}

	data, err := unmarshalToAttestationData(value.Get(jsonData))
	if err != nil {
		return nil, err
	}

	signature, err := convertTo96ByteArray(value.GetStringBytes(jsonSignature))
	if err != nil {
		return nil, err
	}

	return &phase0.IndexedAttestation{
		AttestingIndices: attestingIndices,
		Data:             data,
		Signature:        signature,
	}, nil
}

func unmarshalToIndexedElectraAttestation(value *fastjson.Value) (*electraspec.IndexedAttestation, error) {
	attestingIndicesValues := value.GetArray(jsonAttestingIndices)
	attestingIndices := make([]uint64, len(attestingIndicesValues))
	for i := range attestingIndicesValues {
		// TODO: verify this function change with error handling works properly
		indexBytes, err := attestingIndicesValues[i].StringBytes()
		if err != nil {
			return nil, err
		}

		index, err := convertToUint64(indexBytes)
		if err != nil {
			return nil, err
		}

		attestingIndices[i] = index
	}

	data, err := unmarshalToAttestationData(value.Get(jsonData))
	if err != nil {
		return nil, err
	}

	signature, err := convertTo96ByteArray(value.GetStringBytes(jsonSignature))
	if err != nil {
		return nil, err
	}

	return &electraspec.IndexedAttestation{
		AttestingIndices: attestingIndices,
		Data:             data,
		Signature:        signature,
	}, nil
}
