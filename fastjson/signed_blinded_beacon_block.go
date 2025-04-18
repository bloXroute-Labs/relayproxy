package fastjson

import (
	eth2Api "github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/api/v1/electra"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/pkg/errors"
	"github.com/valyala/fastjson"

	"github.com/bloXroute-Labs/relayproxy/common"
)

func UnmarshalToSignedBlindedBeaconBlock(requestBody string) (*common.VersionedSignedBlindedBeaconBlock, error) {
	// TODO: should we implement a ParserPool or is one parser per goroutine sufficient?
	parser := fastjson.Parser{}

	signedBlindedBeaconBlock, err := parser.Parse(requestBody)
	if err != nil {
		return nil, errors.New("unexpected end of JSON input")
	}

	signature, err := convertTo96ByteArray(signedBlindedBeaconBlock.GetStringBytes(jsonSignature))
	if err != nil {
		return nil, err
	}

	if common.IsElectra {
		electraBlindedBeaconBlock, err := UnmarshalToBlindedBeaconBlockElectra(signedBlindedBeaconBlock.Get(jsonMessage))
		if err == nil {
			return &common.VersionedSignedBlindedBeaconBlock{
				VersionedSignedBlindedBeaconBlock: eth2Api.VersionedSignedBlindedBeaconBlock{
					Version: spec.DataVersionElectra,
					Electra: &electra.SignedBlindedBeaconBlock{
						Message:   electraBlindedBeaconBlock,
						Signature: signature,
					},
				},
			}, nil
		}
	}

	denebBlindedBeaconBlock, err := UnmarshalToBlindedBeaconBlockDeneb(signedBlindedBeaconBlock.Get(jsonMessage))
	if err == nil {
		return &common.VersionedSignedBlindedBeaconBlock{
			VersionedSignedBlindedBeaconBlock: eth2Api.VersionedSignedBlindedBeaconBlock{
				Version: spec.DataVersionDeneb,
				Deneb: &deneb.SignedBlindedBeaconBlock{
					Message:   denebBlindedBeaconBlock,
					Signature: signature,
				},
			},
		}, nil
	}

	electraBlindedBeaconBlock, err := UnmarshalToBlindedBeaconBlockElectra(signedBlindedBeaconBlock.Get(jsonMessage))
	if err == nil {
		return &common.VersionedSignedBlindedBeaconBlock{
			VersionedSignedBlindedBeaconBlock: eth2Api.VersionedSignedBlindedBeaconBlock{
				Version: spec.DataVersionElectra,
				Electra: &electra.SignedBlindedBeaconBlock{
					Message:   electraBlindedBeaconBlock,
					Signature: signature,
				},
			},
		}, nil
	}

	return nil, errors.Wrap(err, "failed to unmarshal fastjson VersionedSignedBlindedBeaconBlock")
}
