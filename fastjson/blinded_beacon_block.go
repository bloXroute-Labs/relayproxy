package fastjson

import (
	capellaapi "github.com/attestantio/go-eth2-client/api/v1/capella"
	"github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/api/v1/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/valyala/fastjson"
)

func UnmarshalToBlindedBeaconBlockCapella(blindedBeaconBlock *fastjson.Value) (*capellaapi.BlindedBeaconBlock, error) {
	slot, err := convertToUint64(blindedBeaconBlock.GetStringBytes(jsonSlot))
	if err != nil {
		return nil, err
	}

	proposerIndex, err := convertToUint64(blindedBeaconBlock.GetStringBytes(jsonProposerIndex))
	if err != nil {
		return nil, err
	}

	parentRoot, err := convertTo32ByteArray(blindedBeaconBlock.GetStringBytes(jsonParentRoot))
	if err != nil {
		return nil, err
	}

	blindedBeaconBlockStateRoot, err := convertTo32ByteArray(blindedBeaconBlock.GetStringBytes(jsonStateRoot))
	if err != nil {
		return nil, err
	}

	blindedBeaconBlockBody, err := UnmarshalToBlindedBeaconBlockBodyCapella(blindedBeaconBlock.Get(jsonBody))
	if err != nil {
		return nil, err
	}

	return &capellaapi.BlindedBeaconBlock{
		Slot:          phase0.Slot(slot),
		ProposerIndex: phase0.ValidatorIndex(proposerIndex),
		ParentRoot:    parentRoot,
		StateRoot:     blindedBeaconBlockStateRoot,
		Body:          blindedBeaconBlockBody,
	}, nil
}

func UnmarshalToBlindedBeaconBlockDeneb(blindedBeaconBlock *fastjson.Value) (*deneb.BlindedBeaconBlock, error) {
	slot, err := convertToUint64(blindedBeaconBlock.GetStringBytes(jsonSlot))
	if err != nil {
		return nil, err
	}

	proposerIndex, err := convertToUint64(blindedBeaconBlock.GetStringBytes(jsonProposerIndex))
	if err != nil {
		return nil, err
	}

	parentRoot, err := convertTo32ByteArray(blindedBeaconBlock.GetStringBytes(jsonParentRoot))
	if err != nil {
		return nil, err
	}

	blindedBeaconBlockStateRoot, err := convertTo32ByteArray(blindedBeaconBlock.GetStringBytes(jsonStateRoot))
	if err != nil {
		return nil, err
	}

	blindedBeaconBlockBody, err := UnmarshalToBlindedBeaconBlockBodyDeneb(blindedBeaconBlock.Get(jsonBody))
	if err != nil {
		return nil, err
	}

	return &deneb.BlindedBeaconBlock{
		Slot:          phase0.Slot(slot),
		ProposerIndex: phase0.ValidatorIndex(proposerIndex),
		ParentRoot:    parentRoot,
		StateRoot:     blindedBeaconBlockStateRoot,
		Body:          blindedBeaconBlockBody,
	}, nil
}

func UnmarshalToBlindedBeaconBlockElectra(blindedBeaconBlock *fastjson.Value) (*electra.BlindedBeaconBlock, error) {
	slot, err := convertToUint64(blindedBeaconBlock.GetStringBytes(jsonSlot))
	if err != nil {
		return nil, err
	}

	proposerIndex, err := convertToUint64(blindedBeaconBlock.GetStringBytes(jsonProposerIndex))
	if err != nil {
		return nil, err
	}

	parentRoot, err := convertTo32ByteArray(blindedBeaconBlock.GetStringBytes(jsonParentRoot))
	if err != nil {
		return nil, err
	}

	blindedBeaconBlockStateRoot, err := convertTo32ByteArray(blindedBeaconBlock.GetStringBytes(jsonStateRoot))
	if err != nil {
		return nil, err
	}

	blindedBeaconBlockBody, err := UnmarshalToBlindedBeaconBlockBodyElectra(blindedBeaconBlock.Get(jsonBody))
	if err != nil {
		return nil, err
	}

	return &electra.BlindedBeaconBlock{
		Slot:          phase0.Slot(slot),
		ProposerIndex: phase0.ValidatorIndex(proposerIndex),
		ParentRoot:    parentRoot,
		StateRoot:     blindedBeaconBlockStateRoot,
		Body:          blindedBeaconBlockBody,
	}, nil
}
