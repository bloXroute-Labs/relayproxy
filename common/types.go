package common

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/attestantio/go-builder-client/api/fulu"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/attestantio/go-builder-client/api/deneb"
	"github.com/attestantio/go-builder-client/api/electra"

	//"github.com/attestantio/go-eth2-client/api/v1/fulu"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	eth2Api "github.com/attestantio/go-eth2-client/api"
	eth2ApiV1Deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	eth2ApiV1Electra "github.com/attestantio/go-eth2-client/api/v1/electra"

	//eth2ApiV1Fulu "github.com/attestantio/go-eth2-client/api/v1/fulu"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	relaygrpc "github.com/bloXroute-Labs/relay-grpc"
	"github.com/bloXroute-Labs/relay-grpc/bidadjustment"
	"github.com/bloXroute-Labs/relay-grpc/optimisticv3"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-boost-utils/bls"
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

	//FULU
	FuluForkVersionHolesky = "0x07017000"
	FuluForkVersionSepolia = "0x90000075"
	FuluForkVersionHoodi   = "0x70000910"
	FuluForkVersionMainnet = "0x06000000"
	FuluForkEpochHolesky   = int64(165120)
	FuluForkEpochSepolia   = int64(272640)
	FuluForkEpochHoodi     = int64(50688)
	FuluForkEpochMainnet   = int64(411392)

	HoodiChainID   = "560048"
	HoleskyChainID = "17000"
	SepoliaChainID = "11155111"
	MainnetChainID = "1"

	IsElectra                       bool
	IsFulu                          bool
	TransferGasLimit                = uint64(21000)
	SlotsPerEpoch                   = uint64(32)
	OptimisticV3FetchPayloadTimeout = 10 * time.Second
)

type EthNetworkDetails struct {
	Name                     string
	GenesisForkVersionHex    string
	GenesisValidatorsRootHex string
	DenebForkVersionHex      string
	ElectraForkVersionHex    string
	FuluForkVersionHex       string

	DomainBuilder               phase0.Domain
	DomainBeaconProposerDeneb   phase0.Domain
	DomainBeaconProposerElectra phase0.Domain
	DomainBeaconProposerFulu    phase0.Domain

	ChainID    string
	ChainIDInt int
}

func NewEthNetworkDetails(networkName string) (ret *EthNetworkDetails, err error) {
	var genesisForkVersion string
	var genesisValidatorsRoot string
	var denebForkVersion string
	var electraForkVersion string
	var fuluForkVersion string
	var domainBuilder phase0.Domain
	var domainBeaconProposerDeneb phase0.Domain
	var domainBeaconProposerElectra phase0.Domain
	var domainBeaconProposerFulu phase0.Domain
	var chainID string
	switch networkName {
	case EthNetworkHolesky:
		genesisForkVersion = GenesisForkVersionHolesky
		genesisValidatorsRoot = GenesisValidatorsRootHolesky
		denebForkVersion = DenebForkVersionHolesky
		electraForkVersion = ElectraForkVersionHolesky
		fuluForkVersion = FuluForkVersionHolesky
		chainID = HoleskyChainID
	case EthNetworkSepolia:
		genesisForkVersion = boostTypes.GenesisForkVersionSepolia
		genesisValidatorsRoot = boostTypes.GenesisValidatorsRootSepolia
		denebForkVersion = DenebForkVersionSepolia
		electraForkVersion = ElectraForkVersionSepolia
		fuluForkVersion = FuluForkVersionSepolia
		chainID = SepoliaChainID
	case EthNetworkHoodi:
		genesisForkVersion = GenesisForkVersionHoodi
		genesisValidatorsRoot = GenesisValidatorsRootHoodi
		denebForkVersion = DenebForkVersionHoodi
		electraForkVersion = ElectraForkVersionHoodi
		fuluForkVersion = FuluForkVersionHoodi
		chainID = HoodiChainID
	case EthNetworkMainnet:
		genesisForkVersion = boostTypes.GenesisForkVersionMainnet
		genesisValidatorsRoot = boostTypes.GenesisValidatorsRootMainnet
		denebForkVersion = DenebForkVersionMainnet
		electraForkVersion = ElectraForkVersionMainnet
		fuluForkVersion = FuluForkVersionMainnet
		chainID = MainnetChainID
	case EthNetworkCustom:
		genesisForkVersion = os.Getenv("GENESIS_FORK_VERSION")
		genesisValidatorsRoot = os.Getenv("GENESIS_VALIDATORS_ROOT")
		denebForkVersion = os.Getenv("DENEB_FORK_VERSION")
		electraForkVersion = os.Getenv("ELECTRA_FORK_VERSION")
		fuluForkVersion = os.Getenv("FULU_FORK_VERSION")
		chainID = os.Getenv("CHAIN_ID")
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

	domainBeaconProposerFulu, err = ComputeDomain(ssz.DomainTypeBeaconProposer, fuluForkVersion, genesisValidatorsRoot)
	if err != nil {
		return nil, err
	}
	chainIDInt, err := strconv.Atoi(chainID)
	if err != nil {
		return nil, fmt.Errorf("invalid chain ID %s: %w", chainID, err)
	}
	return &EthNetworkDetails{
		Name:                        networkName,
		GenesisForkVersionHex:       genesisForkVersion,
		GenesisValidatorsRootHex:    genesisValidatorsRoot,
		DenebForkVersionHex:         denebForkVersion,
		ElectraForkVersionHex:       electraForkVersion,
		FuluForkVersionHex:          fuluForkVersion,
		DomainBuilder:               domainBuilder,
		DomainBeaconProposerDeneb:   domainBeaconProposerDeneb,
		DomainBeaconProposerElectra: domainBeaconProposerElectra,
		DomainBeaconProposerFulu:    domainBeaconProposerFulu,
		ChainID:                     chainID,
		ChainIDInt:                  chainIDInt,
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
	FuluForkVersionHex:%s,
	DomainBuilder: %x,
	DomainBeaconProposerDeneb: %x
	DomainBeaconProposerElectra: %x
	DomainBeaconProposerFulu:%x
}`,
		e.Name,
		e.GenesisForkVersionHex,
		e.GenesisValidatorsRootHex,
		e.DenebForkVersionHex,
		e.ElectraForkVersionHex,
		e.FuluForkVersionHex,
		e.DomainBuilder,
		e.DomainBeaconProposerDeneb,
		e.DomainBeaconProposerElectra,
		e.DomainBeaconProposerFulu)
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
	case spec.DataVersionFulu:
		return json.Marshal(r.Fulu)
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

	if IsFulu {
		fuluBlock := new(eth2ApiV1Electra.SignedBlindedBeaconBlock)
		if err = json.Unmarshal(input, fuluBlock); err == nil {
			r.Version = spec.DataVersionFulu
			r.Fulu = fuluBlock
			return nil
		}
	}
	electraBlock := new(eth2ApiV1Electra.SignedBlindedBeaconBlock)
	if err = json.Unmarshal(input, electraBlock); err == nil {
		r.Version = spec.DataVersionElectra
		r.Electra = electraBlock
		return nil
	}

	denebBlock := new(eth2ApiV1Deneb.SignedBlindedBeaconBlock)
	if err = json.Unmarshal(input, denebBlock); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebBlock
		return nil
	}
	return fmt.Errorf("failed to unmarshal SignedBlindedBeaconBlock %v", err)
}

func (r *VersionedSignedBlindedBeaconBlock) UnmarshalSSZ(input []byte) error {
	var err error

	if IsFulu {
		fuluBlock := new(eth2ApiV1Electra.SignedBlindedBeaconBlock)
		if err = fuluBlock.UnmarshalSSZ(input); err == nil {
			r.Version = spec.DataVersionFulu
			r.Fulu = fuluBlock
			return nil
		}
	}

	electraBlock := new(eth2ApiV1Electra.SignedBlindedBeaconBlock)
	if err = electraBlock.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionElectra
		r.Electra = electraBlock
		return nil
	}

	denebBlock := new(eth2ApiV1Deneb.SignedBlindedBeaconBlock)
	if err = denebBlock.UnmarshalSSZ(input); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebBlock
		return nil
	}
	return fmt.Errorf("failed to unmarshal SignedBlindedBeaconBlock %w", err)
}

// ExecutionParentHash returns the parent hash of the beacon block.
func (r *VersionedSignedBlindedBeaconBlock) ExecutionParentHash() (phase0.Hash32, error) {
	switch r.Version {
	case spec.DataVersionFulu:
		if r.Fulu == nil ||
			r.Fulu.Message == nil ||
			r.Fulu.Message.Body == nil ||
			r.Fulu.Message.Body.ExecutionPayloadHeader == nil {
			return phase0.Hash32{}, ErrDataMissing
		}

		return r.Fulu.Message.Body.ExecutionPayloadHeader.ParentHash, nil
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

var clientFailureWindow = time.Minute * 10

type Client struct {
	URL    string
	NodeID string
	relaygrpc.RelayClient
}

type ParentClient struct {
	FastClient *Client
	SafeClient *Client
}

func (p *ParentClient) String() string {
	return fmt.Sprintf("ParentClient{FastClient: %s, SafeClient: %s}", p.FastClient.URL, p.SafeClient.URL)
}

func (p *ParentClient) GetActiveClient(lastConnectTime time.Time) (*Client, bool) {
	if time.Since(lastConnectTime) <= clientFailureWindow {
		return p.SafeClient, true
	}
	return p.FastClient, false
}

func NewParentClient(safeUrl string, safeConn *grpc.ClientConn, fastUrl string, fastConn *grpc.ClientConn) *ParentClient {
	return &ParentClient{
		FastClient: &Client{
			URL:         fastUrl,
			RelayClient: relaygrpc.NewRelayClient(fastConn),
		},
		SafeClient: &Client{
			URL:         safeUrl,
			RelayClient: relaygrpc.NewRelayClient(safeConn),
		},
	}
}

type Bid struct {
	Value               []byte // block value
	payload             []byte // blinded block
	HeaderSubmissionV3  *optimisticv3.HeaderSubmissionV3
	BlockHash           string
	BuilderPubkey       string
	BuilderExtraData    string
	AccountID           string
	Client              *ParentClient
	PayloadFetchUrl     string
	ReceivedAt          time.Time
	AuthHeader          string
	BlockSequenceNumber *uint64
	Hidden              bool
}

func NewBid(Value []byte,
	payload []byte,
	headerSubmissionV3 *optimisticv3.HeaderSubmissionV3,
	blockHash string,
	builderPubkey string,
	builderExtraData string,
	accountID string,
	client *ParentClient,
	payloadFetchUrl string,
	receivedAt time.Time,
	authHeader string,
	blockSequenceNumber *uint64,
	hidden bool,
) *Bid {
	return &Bid{
		Value:               Value,
		payload:             payload,
		HeaderSubmissionV3:  headerSubmissionV3,
		BlockHash:           blockHash,
		BuilderPubkey:       builderPubkey,
		BuilderExtraData:    builderExtraData,
		AccountID:           accountID,
		Client:              client,
		PayloadFetchUrl:     payloadFetchUrl,
		ReceivedAt:          receivedAt,
		AuthHeader:          authHeader,
		BlockSequenceNumber: blockSequenceNumber,
		Hidden:              hidden,
	}
}

func (b *Bid) GetSignedHeaderResponse(sk *bls.SecretKey, pubkey *phase0.BLSPubKey, domain phase0.Domain) ([]byte, bool, error) {
	if b.payload != nil {
		return b.payload, true, nil
	}
	if b.HeaderSubmissionV3 == nil {
		return nil, false, errors.New("empty payload")
	}

	relayProxyGetHeaderResponse, err := BuildGetHeaderResponseAndSign(b.HeaderSubmissionV3, sk, pubkey, domain)
	if err != nil {
		return nil, false, err
	}
	wrappedRelayProxyGetHeaderResponse := &VersionedSignedBuilderBid{}
	wrappedRelayProxyGetHeaderResponse.VersionedSignedBuilderBid = *relayProxyGetHeaderResponse

	payload, err := json.Marshal(wrappedRelayProxyGetHeaderResponse)
	if err != nil {
		return nil, false, err
	}
	b.payload = payload
	return payload, false, nil
}

type DuplicateBlock struct {
	Time   int64
	Source string
}

type PayloadResponseForProxy struct {
	SszMarshalledPayloadResponse []byte
	PayloadResponse              VersionedSubmitBlindedBlockResponse
	BlockValue                   string
}

func (p *PayloadResponseForProxy) GetSszMarshalledResponse() ([]byte, error) {
	if len(p.SszMarshalledPayloadResponse) != 0 {
		return p.SszMarshalledPayloadResponse, nil
	}
	if p.PayloadResponse.IsEmpty() {
		return nil, errors.New("empty payload response")
	}
	marshaledResponse, err := p.PayloadResponse.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	p.SszMarshalledPayloadResponse = marshaledResponse
	return marshaledResponse, nil
}

// BuildVersionedPayloadInfo builds the VersionedPayloadInfo struct and sets it to the PayloadResponseForProxy struct
func (p *PayloadResponseForProxy) BuildVersionedPayloadInfo(slot uint64, parentHash string, blockHash string, pubkey string) (*VersionedPayloadInfo, error) {
	marshalledPayload, err := p.GetSszMarshalledResponse()
	if err != nil {
		return &VersionedPayloadInfo{}, err
	}
	versionedPayloadInfo := VersionedPayloadInfo{
		FullPayloadResponse: &p.PayloadResponse,
		SszResponse:         marshalledPayload,
		Slot:                slot,
		ParentHash:          parentHash,
		BlockHash:           blockHash,
		Pubkey:              pubkey,
		BlockValue:          p.BlockValue,
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

type OnHeaderDeliveredParams struct {
	SignedHeaderResponse     []byte
	Slot                     uint64
	GetHeaderRequestID       string
	ProposerPubkey           string
	GetHeaderStartTimeUnixMS string
	ExtraData                string
	Sleep                    int64
	MaxSleep                 int64
	MsIntoSlot               int64
	MsIntoSlotWithDelay      int64
	BlockHash                string
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
	WalletAccounts                          []WalletAccount  `json:"wallet_accounts"`
}

type MiniValidatorLatency struct {
	Registration   *builderApiV1.SignedValidatorRegistration `json:"registration"`
	LastRegistered int64                                     `json:"last_registered"`
	ReceivedAt     time.Time                                 `json:"-"`

	IsOptedIn               bool        `json:"is_opted_in"`
	LastUpdatedBlock        uint64      `json:"last_updated_block"`
	IsEOA                   bool        `json:"is_eoa"`
	ExpectedParentBlockRoot phase0.Root `json:"expected_parent_block_root"`
}

type PreFetchGetPayloadResponseHTTP struct {
	Code                         uint32
	Message                      string
	SszVersionedExecutionPayload []byte
}

type PreFetchGetPayloadRequestHTTP struct {
	Slot           uint64
	ParentHash     string
	BlockHash      string
	Pubkey         string
	ClientIp       string
	ReceivedAt     *timestamppb.Timestamp
	GetHeaderReqID string
	PrefetchReqID  string
	NodeID         string
}

func ToSubmitBlockRequest(v *optimisticv3.VersionedAdjustableSubmitBlockRequest) (*VersionedSubmitBlockRequest, *bidadjustment.AdjustmentData, error) {
	switch v.Version {
	case spec.DataVersionDeneb:
		return &VersionedSubmitBlockRequest{
			VersionedSubmitBlockRequest: builderSpec.VersionedSubmitBlockRequest{
				Version: spec.DataVersionDeneb,
				Deneb: &deneb.SubmitBlockRequest{
					Message:          v.Deneb.Message,
					ExecutionPayload: v.Deneb.ExecutionPayload,
					BlobsBundle:      v.Deneb.BlobsBundle,
					Signature:        v.Deneb.Signature,
				},
			},
		}, v.Deneb.AdjustmentData, nil
	case spec.DataVersionElectra:
		return &VersionedSubmitBlockRequest{
			VersionedSubmitBlockRequest: builderSpec.VersionedSubmitBlockRequest{
				Version: spec.DataVersionElectra,
				Electra: &electra.SubmitBlockRequest{
					Message:           v.Electra.Message,
					ExecutionPayload:  v.Electra.ExecutionPayload,
					BlobsBundle:       v.Electra.BlobsBundle,
					ExecutionRequests: v.Electra.ExecutionRequests,
					Signature:         v.Electra.Signature,
				},
			},
		}, v.Electra.AdjustmentData, nil

	case spec.DataVersionFulu:
		return &VersionedSubmitBlockRequest{
			VersionedSubmitBlockRequest: builderSpec.VersionedSubmitBlockRequest{
				Version: spec.DataVersionFulu,
				Fulu: &fulu.SubmitBlockRequest{
					Message:           v.Fulu.Message,
					ExecutionPayload:  v.Fulu.ExecutionPayload,
					BlobsBundle:       v.Fulu.BlobsBundle,
					ExecutionRequests: v.Fulu.ExecutionRequests,
					Signature:         v.Fulu.Signature,
				},
			},
		}, v.Fulu.AdjustmentData, nil
	}
	return nil, nil, errors.New("unknown data version")
}
