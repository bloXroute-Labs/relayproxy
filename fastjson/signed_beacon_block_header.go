package fastjson

import (
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/valyala/fastjson"
)

func unmarshalToSignedBeaconBlockHeader(value *fastjson.Value) (*phase0.SignedBeaconBlockHeader, error) {
	message := value.Get(jsonMessage)

	slot, err := convertToUint64(message.GetStringBytes(jsonSlot))
	if err != nil {
		return nil, err
	}

	proposerIndex, err := convertToUint64(message.GetStringBytes(jsonProposerIndex))
	if err != nil {
		return nil, err
	}

	parentRoot, err := convertTo32ByteArray(message.GetStringBytes(jsonParentRoot))
	if err != nil {
		return nil, err
	}

	stateRoot, err := convertTo32ByteArray(message.GetStringBytes(jsonStateRoot))
	if err != nil {
		return nil, err
	}

	bodyRoot, err := convertTo32ByteArray(message.GetStringBytes(jsonBodyRoot))
	if err != nil {
		return nil, err
	}

	signature, err := convertTo96ByteArray(value.GetStringBytes(jsonSignature))
	if err != nil {
		return nil, err
	}

	return &phase0.SignedBeaconBlockHeader{
		Message: &phase0.BeaconBlockHeader{
			Slot:          phase0.Slot(slot),
			ProposerIndex: phase0.ValidatorIndex(proposerIndex),
			ParentRoot:    parentRoot,
			StateRoot:     stateRoot,
			BodyRoot:      bodyRoot,
		},
		Signature: signature,
	}, nil
}
