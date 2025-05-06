package common

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"google.golang.org/grpc"

	relaygrpc "github.com/bloXroute-Labs/relay-grpc"

	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	eth2Api "github.com/attestantio/go-eth2-client/api"
	eth2ApiV1Deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2ApiV1Electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-boost-utils/ssz"
	boostTypes "github.com/flashbots/go-boost-utils/types"
)

var (
	ErrUnknownNetwork    = errors.New("unknown network")
	ErrInvalidVersion    = errors.New("invalid version")
	ErrDataMissing       = errors.New("data missing")
	ErrLateHeader        = errors.New("getHeader request too late")
	ErrEmptyPayload      = errors.New("empty payload")
	ErrNoProposerSlotMap = errors.New("no proposer slot map")

	EthNetworkHolesky = "holesky"
	EthNetworkSepolia = "sepolia"
	EthNetworkHoodi   = "hoodi"
	EthNetworkGoerli  = "goerli"
	EthNetworkMainnet = "mainnet"
	EthNetworkCustom  = "custom"

	GenesisForkVersionHolesky = "0x01017000"
	GenesisForkVersionHoodi   = "0x10000910"

	GenesisValidatorsRootHolesky = "0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1"
	GenesisValidatorsRootHoodi   = "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"

	BellatrixForkVersionHolesky = "0x03017000"

	DenebForkVersionHolesky = "0x05017000"
	DenebForkVersionSepolia = "0x90000073"
	DenebForkVersionHoodi   = "0x50000910"
	DenebForkVersionGoerli  = "0x04001020"
	DenebForkVersionMainnet = "0x04000000"

	ElectraForkVersionHolesky = "0x06017000"
	ElectraForkVersionSepolia = "0x90000074"
	ElectraForkVersionHoodi   = "0x60000910"
	ElectraForkVersionMainnet = "0x05000000"
	ElectraForkEpochHolesky   = int64(115968)
	ElectraForkEpochSepolia   = int64(222464)
	ElectraForkEpochHoodi     = int64(2048)
	ElectraForkEpochMainnet   = int64(364032)

	HoodiChainID = 560048

	IsElectra bool
)

type EthNetworkDetails struct {
	Name                     string
	GenesisForkVersionHex    string
	GenesisValidatorsRootHex string
	DenebForkVersionHex      string
	ElectraForkVersionHex    string

	DomainBuilder               phase0.Domain
	DomainBeaconProposerDeneb   phase0.Domain
	DomainBeaconProposerElectra phase0.Domain
}

func NewEthNetworkDetails(networkName string) (ret *EthNetworkDetails, err error) {
	var genesisForkVersion string
	var genesisValidatorsRoot string
	var denebForkVersion string
	var electraForkVersion string
	var domainBuilder phase0.Domain
	var domainBeaconProposerDeneb phase0.Domain
	var domainBeaconProposerElectra phase0.Domain

	switch networkName {
	case EthNetworkHolesky:
		genesisForkVersion = GenesisForkVersionHolesky
		genesisValidatorsRoot = GenesisValidatorsRootHolesky
		denebForkVersion = DenebForkVersionHolesky
		electraForkVersion = ElectraForkVersionHolesky
	case EthNetworkSepolia:
		genesisForkVersion = boostTypes.GenesisForkVersionSepolia
		genesisValidatorsRoot = boostTypes.GenesisValidatorsRootSepolia
		denebForkVersion = DenebForkVersionSepolia
		electraForkVersion = ElectraForkVersionSepolia
	case EthNetworkHoodi:
		genesisForkVersion = GenesisForkVersionHoodi
		genesisValidatorsRoot = GenesisValidatorsRootHoodi
		denebForkVersion = DenebForkVersionHoodi
		electraForkVersion = ElectraForkVersionHoodi
	case EthNetworkMainnet:
		genesisForkVersion = boostTypes.GenesisForkVersionMainnet
		genesisValidatorsRoot = boostTypes.GenesisValidatorsRootMainnet
		denebForkVersion = DenebForkVersionMainnet
		electraForkVersion = ElectraForkVersionMainnet
	case EthNetworkCustom:
		genesisForkVersion = os.Getenv("GENESIS_FORK_VERSION")
		genesisValidatorsRoot = os.Getenv("GENESIS_VALIDATORS_ROOT")
		denebForkVersion = os.Getenv("DENEB_FORK_VERSION")
		electraForkVersion = os.Getenv("ELECTRA_FORK_VERSION")
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownNetwork, networkName)
	}

	domainBuilder, err = ComputeDomain(ssz.DomainTypeAppBuilder, genesisForkVersion, phase0.Root{}.String())
	if err != nil {
		return nil, err
	}

	domainBeaconProposerDeneb, err = ComputeDomain(ssz.DomainTypeBeaconProposer, denebForkVersion, genesisValidatorsRoot)
	if err != nil {
		return nil, err
	}

	domainBeaconProposerElectra, err = ComputeDomain(ssz.DomainTypeBeaconProposer, electraForkVersion, genesisValidatorsRoot)
	if err != nil {
		return nil, err
	}

	return &EthNetworkDetails{
		Name:                        networkName,
		GenesisForkVersionHex:       genesisForkVersion,
		GenesisValidatorsRootHex:    genesisValidatorsRoot,
		DenebForkVersionHex:         denebForkVersion,
		ElectraForkVersionHex:       electraForkVersion,
		DomainBuilder:               domainBuilder,
		DomainBeaconProposerDeneb:   domainBeaconProposerDeneb,
		DomainBeaconProposerElectra: domainBeaconProposerElectra,
	}, nil
}

func (e *EthNetworkDetails) String() string {
	return fmt.Sprintf(
		`EthNetworkDetails{
	Name: %s,
	GenesisForkVersionHex: %s,
	GenesisValidatorsRootHex: %s,
	DenebForkVersionHex: %s,
	ElectraForkVersionHex: %s,
	DomainBuilder: %x,
	DomainBeaconProposerDeneb: %x
	DomainBeaconProposerElectra: %x
}`,
		e.Name,
		e.GenesisForkVersionHex,
		e.GenesisValidatorsRootHex,
		e.DenebForkVersionHex,
		e.ElectraForkVersionHex,
		e.DomainBuilder,
		e.DomainBeaconProposerDeneb,
		e.DomainBeaconProposerElectra)
}

// ComputeDomain computes the signing domain
func ComputeDomain(domainType phase0.DomainType, forkVersionHex, genesisValidatorsRootHex string) (domain phase0.Domain, err error) {
	genesisValidatorsRoot := phase0.Root(ethcommon.HexToHash(genesisValidatorsRootHex))
	forkVersionBytes, err := hexutil.Decode(forkVersionHex)
	if err != nil || len(forkVersionBytes) != 4 {
		return domain, errors.New("invalid fork version")
	}
	var forkVersion [4]byte
	copy(forkVersion[:], forkVersionBytes[:4])
	return ssz.ComputeDomain(domainType, forkVersion, genesisValidatorsRoot), nil
}

type VersionedSignedBlindedBeaconBlock struct {
	eth2Api.VersionedSignedBlindedBeaconBlock
}

func (r *VersionedSignedBlindedBeaconBlock) MarshalJSON() ([]byte, error) {
	switch r.Version { //nolint:exhaustive
	case spec.DataVersionElectra:
		return json.Marshal(r.Electra)
	case spec.DataVersionDeneb:
		return json.Marshal(r.Deneb)
	default:
		return nil, fmt.Errorf("%s is not supported", r.Version)
	}
}

func (r *VersionedSignedBlindedBeaconBlock) UnmarshalJSON(input []byte) error {
	var err error
	if IsElectra {
		electraBlock := new(eth2ApiV1Electra.SignedBlindedBeaconBlock)
		if err = json.Unmarshal(input, electraBlock); err == nil {
			r.Version = spec.DataVersionElectra
			r.Electra = electraBlock
			return nil
		}
	}
	denebBlock := new(eth2ApiV1Deneb.SignedBlindedBeaconBlock)
	if err = json.Unmarshal(input, denebBlock); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebBlock
		return nil
	}

	electraBlock := new(eth2ApiV1Electra.SignedBlindedBeaconBlock)
	if err = json.Unmarshal(input, electraBlock); err == nil {
		r.Version = spec.DataVersionElectra
		r.Electra = electraBlock
		return nil
	}
	return fmt.Errorf("failed to unmarshal SignedBlindedBeaconBlock %v", err)
}

func (r *VersionedSignedBlindedBeaconBlock) UnmarshalSSZ(input []byte) error {
	var err error

	if IsElectra {
		electraBlock := new(eth2ApiV1Electra.SignedBlindedBeaconBlock)
		if err = electraBlock.UnmarshalSSZ(input); err == nil {
			r.Version = spec.DataVersionElectra
			r.Electra = electraBlock
			return nil
		}
	}

	denebBlock := new(eth2ApiV1Deneb.SignedBlindedBeaconBlock)
	if err = denebBlock.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebBlock
		return nil
	}

	electraBlock := new(eth2ApiV1Electra.SignedBlindedBeaconBlock)
	if err = electraBlock.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionElectra
		r.Electra = electraBlock
		return nil
	}

	return fmt.Errorf("failed to unmarshal SignedBlindedBeaconBlock %w", err)
}

// ExecutionParentHash returns the parent hash of the beacon block.
func (r *VersionedSignedBlindedBeaconBlock) ExecutionParentHash() (phase0.Hash32, error) {
	switch r.Version {
	case spec.DataVersionElectra:
		if r.Electra == nil ||
			r.Electra.Message == nil ||
			r.Electra.Message.Body == nil ||
			r.Electra.Message.Body.ExecutionPayloadHeader == nil {
			return phase0.Hash32{}, ErrDataMissing
		}

		return r.Electra.Message.Body.ExecutionPayloadHeader.ParentHash, nil
	case spec.DataVersionDeneb:
		if r.Deneb == nil ||
			r.Deneb.Message == nil ||
			r.Deneb.Message.Body == nil ||
			r.Deneb.Message.Body.ExecutionPayloadHeader == nil {
			return phase0.Hash32{}, ErrDataMissing
		}

		return r.Deneb.Message.Body.ExecutionPayloadHeader.ParentHash, nil
	default:
		return phase0.Hash32{}, fmt.Errorf("%s is not supported", r.Version)
	}
}

type Client struct {
	URL          string
	ConnectionID string
	Conn         *grpc.ClientConn
	IPOpts       URLOpts
	relaygrpc.RelayClient
}
type URLOpts struct {
	Primary string
	Backup  string
}
type Bid struct {
	Value            []byte // block value
	Payload          []byte // blinded block
	BlockHash        string
	BuilderPubkey    string
	BuilderExtraData string
	AccountID        string
	Client           *Client
}

type DuplicateBlock struct {
	Time   int64
	Source string
}

type PayloadResponseForProxy struct {
	MarshalledPayloadResponse []byte
	PayloadResponse           VersionedSubmitBlindedBlockResponse
	BlockValue                string
}

func (p *PayloadResponseForProxy) GetMarshalledResponse() ([]byte, error) {
	if len(p.MarshalledPayloadResponse) != 0 {
		return p.MarshalledPayloadResponse, nil
	}
	if p.PayloadResponse.IsEmpty() {
		return nil, errors.New("empty payload response")
	}
	marshaledResponse, err := p.PayloadResponse.MarshalJSON()
	if err != nil {
		return nil, err
	}
	p.MarshalledPayloadResponse = marshaledResponse
	return marshaledResponse, nil
}

// BuildVersionedPayloadInfo builds the VersionedPayloadInfo struct and sets it to the PayloadResponseForProxy struct
func (p *PayloadResponseForProxy) BuildVersionedPayloadInfo(slot uint64, parentHash string, blockHash string, pubkey string) (*VersionedPayloadInfo, error) {
	marshalledPayload, err := p.GetMarshalledResponse()
	if err != nil {
		return &VersionedPayloadInfo{}, err
	}
	versionedPayloadInfo := VersionedPayloadInfo{
		Response:   marshalledPayload,
		Slot:       slot,
		ParentHash: parentHash,
		BlockHash:  blockHash,
		Pubkey:     pubkey,
		BlockValue: p.BlockValue,
	}
	return &versionedPayloadInfo, nil
}

type ForwardedBlockInfo struct {
	Context     context.Context
	Block       *relaygrpc.StreamBlockResponse
	ReceivedAt  time.Time
	Latency     int64
	TraceID     string
	Method      string
	ClientIP    string
	ProcessTime int64
}

type BuilderInfo struct {
	BuilderPubkey                           phase0.BLSPubKey `json:"builder_pubkey"`
	IsOptimistic                            bool             `json:"is_optimistic"`
	IsDemoted                               bool             `json:"is_demoted"`
	AccountID                               string           `json:"external_builder_account_id"`
	IsBuilderPubkeyHighPriority             bool             `json:"is_builder_pubkey_high_priority"`
	BuilderPubkeySkipSimulationThreshold    *big.Int         `json:"builder_pubkey_skip_simulation_threshold"`
	IsBuilderAccountIDHighPriority          bool             `json:"is_builder_account_id_high_priority"`
	BuilderAccountIDSkipSimulationThreshold *big.Int         `json:"builder_account_id_skip_simulation_threshold"`
	TrustedExternalBuilder                  bool             `json:"trusted_external_builder"`
	IsOptedIn                               bool             `json:"is_opted_in"`
}

type MiniValidatorLatency struct {
	Registration   *builderApiV1.SignedValidatorRegistration `json:"registration"`
	LastRegistered int64                                     `json:"last_registered"`
	ReceivedAt     time.Time                                 `json:"-"`

	IsOptedIn bool `json:"is_opted_in"`
}
