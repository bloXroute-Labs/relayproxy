package fastjson

import (
	eth2Api "github.com/attestantio/go-eth2-client/api"
	capellaapi "github.com/attestantio/go-eth2-client/api/v1/capella"
	"github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/bloXroute-Labs/relayproxy/common"
	"github.com/pkg/errors"
	"github.com/valyala/fastjson"
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

	//log.Error().Str("requestBody", requestBody).Err(err).Msg("failed to unmarshal fastjson getPayload body to Deneb VersionedSignedBlindedBeaconBlock")

	capellaBlindedBeaconBlock, err := UnmarshalToBlindedBeaconBlockCapella(signedBlindedBeaconBlock.Get(jsonMessage))
	if err == nil {
		return &common.VersionedSignedBlindedBeaconBlock{
			VersionedSignedBlindedBeaconBlock: eth2Api.VersionedSignedBlindedBeaconBlock{
				Version: spec.DataVersionCapella,
				Capella: &capellaapi.SignedBlindedBeaconBlock{
					Message:   capellaBlindedBeaconBlock,
					Signature: signature,
				},
			},
		}, nil
	}

	return nil, errors.Wrap(err, "failed to unmarshal fastjson VersionedSignedBlindedBeaconBlock")
}
