package fastjson

import (
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/valyala/fastjson"
)

func unmarshalToAttestationData(value *fastjson.Value) (*phase0.AttestationData, error) {
	slot, err := convertToUint64(value.GetStringBytes(jsonSlot))
	if err != nil {
		return nil, err
	}

	index, err := convertToUint64(value.GetStringBytes(jsonIndex))
	if err != nil {
		return nil, err
	}

	beaconBlockRoot, err := convertTo32ByteArray(value.GetStringBytes(jsonBeaconBlockRoot))
	if err != nil {
		return nil, err
	}

	source := value.Get(jsonSource)
	sourceRoot, err := convertTo32ByteArray(source.GetStringBytes(jsonRoot))
	if err != nil {
		return nil, err
	}
	sourceEpoch, err := convertToUint64(source.GetStringBytes(jsonEpoch))
	if err != nil {
		return nil, err
	}

	target := value.Get(jsonTarget)
	targetRoot, err := convertTo32ByteArray(target.GetStringBytes(jsonRoot))
	if err != nil {
		return nil, err
	}
	targetEpoch, err := convertToUint64(target.GetStringBytes(jsonEpoch))
	if err != nil {
		return nil, err
	}

	return &phase0.AttestationData{
		Slot:            phase0.Slot(slot),
		Index:           phase0.CommitteeIndex(index),
		BeaconBlockRoot: beaconBlockRoot,
		Source: &phase0.Checkpoint{
			Epoch: phase0.Epoch(sourceEpoch),
			Root:  sourceRoot,
		},
		Target: &phase0.Checkpoint{
			Epoch: phase0.Epoch(targetEpoch),
			Root:  targetRoot,
		},
	}, nil
}
