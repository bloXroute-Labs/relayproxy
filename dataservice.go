package relayproxy

import (
	"context"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/bloXroute-Labs/relayproxy/common"
	"github.com/bloXroute-Labs/relayproxy/fluentstats"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v2"

	"github.com/patrickmn/go-cache"
	"go.opentelemetry.io/otel/trace"
)

const (
	GetHeaderRequestCutoffMs             = 3000
	delayEligibilityCacheCleanupInterval = 60 * time.Second

	flowRetention       = time.Hour       // keep in-memory long enough for on-call /flows debugging
	flowCleanupInterval = 5 * time.Minute // how often expired entries are purged
)

type IDataService interface {
	GetAccounts(ctx context.Context) map[string]any
	SetAccounts(ctx context.Context)
	SendAccount(accountID, validatorID string)

	GetDelaySettings(ctx context.Context) map[string]DelaySettings
	SetDelayForValidator(id string, delay, maxDelay int64)
	SetDelayForValidators(settings map[string]DelaySettings)
	GetSlotDuty(slot uint64) (*common.MiniValidatorLatency, error)

	GetFlowService() IFlowService
}

type DataService struct {
	logger                 zerolog.Logger
	nodeID                 string
	tracer                 trace.Tracer
	fluentD                fluentstats.Stats
	beaconGenesisTime      int64
	secondsPerSlot         int64
	httpClient             *http.Client
	getHeaderDelaySettings map[string]DelaySettings
	accounts               *cache.Cache // list of accountID:validatorID
	accountCh              chan account
	getHeaderDelayMutex    sync.RWMutex
	getHeaderTimeout       map[string]int64 // MEV Boost get header timeout for each validator
	ipCacheStore           *cache.Cache     // list of ip to verify delay eligibility
	accountsLists          *AccountsLists
	delayerPlugin          func(accountID string, msIntoSlot int64, cluster, userAgent string, latency int64, clientIP string, logger zerolog.Logger, getHeaderTimeout map[string]int64, clientTimeoutMS int64, bidAdjustmentBufferTimeMs int64) (int64, int64, int64, error)
	miniProposerSlotMap    *SyncMap[uint64, *common.MiniValidatorLatency]

	flowSvc *FlowService
}

func NewDataService(opts ...DataServiceOption) *DataService {
	svc := &DataService{
		accounts:     cache.New(cache.NoExpiration, cache.NoExpiration),
		accountCh:    make(chan account, 500),
		ipCacheStore: cache.New(delayEligibilityCacheCleanupInterval, delayEligibilityCacheCleanupInterval),
		accountsLists: &AccountsLists{
			AccountIDToInfo:   make(map[string]*AccountInfo),
			AccountNameToInfo: make(map[AccountName]*AccountInfo),
		},
		flowSvc: NewFlowService(flowRetention, flowCleanupInterval),
	}

	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

func LoadAccountsFromYAML(filename string) (*AccountsLists, error) {
	var data []AccountInfo
	yamlBytes, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("Error reading YAML file: %v", err)
	}
	err = yaml.Unmarshal(yamlBytes, &data)
	if err != nil {
		return nil, err
	}
	log.Default().Printf("loaded accounts: %+v\n", data)
	a := AccountsLists{
		AccountIDToInfo:   make(map[string]*AccountInfo),
		AccountNameToInfo: make(map[AccountName]*AccountInfo),
	}
	for _, v := range data {
		a.AccountIDToInfo[v.AccountID] = &v
		a.AccountNameToInfo[v.AccountName] = &v
	}
	return &a, nil
}

type AccountName string
type AccountInfo struct {
	AccountName               AccountName `yaml:"account-name"`
	AccountID                 string      `yaml:"account-id"`
	UseAccountAsValidator     bool        `yaml:"use-account-as-validator"`
	CustomCtx                 string      `yaml:"custom-context"`
	InstantReturnFirstRequest bool        `yaml:"instant-return-first-request"`
	IsWhitelisted             bool        `yaml:"whitelisted"`
	IsTrusted                 bool        `yaml:"trusted"`
}
type AccountsLists struct {
	AccountIDToInfo   map[string]*AccountInfo
	AccountNameToInfo map[AccountName]*AccountInfo
}

func (s *DataService) shouldRequestDelayed(ip, slotWithParentHash string) bool {
	if ip != "" {
		k := slotWithParentHash + "-" + ip
		if _, ok := s.ipCacheStore.Get(k); ok {
			return true
		}
		_ = s.ipCacheStore.Add(k, struct{}{}, delayEligibilityCacheCleanupInterval)
		return false
	}
	s.logger.Warn().Str("key", slotWithParentHash).Msg("received empty client IP, unable to verify delay eligibility")
	return false
}

func (s *DataService) GetDelaySettings(ctx context.Context) map[string]DelaySettings {
	s.getHeaderDelayMutex.RLock()
	defer s.getHeaderDelayMutex.RUnlock()
	out := make(map[string]DelaySettings, len(s.getHeaderDelaySettings))
	for key, setting := range s.getHeaderDelaySettings {
		out[key] = setting
	}
	return out
}

func (s *DataService) SetDelayForValidators(settings map[string]DelaySettings) {

	s.getHeaderDelayMutex.Lock()
	defer s.getHeaderDelayMutex.Unlock()
	if len(s.getHeaderDelaySettings) == 0 {
		s.getHeaderDelaySettings = settings
		return
	}
	for id, setting := range settings {
		s.getHeaderDelaySettings[id] = setting
	}
}
func (s *DataService) SetDelayForValidator(id string, delay, maxDelay int64) {
	s.getHeaderDelayMutex.Lock()
	defer s.getHeaderDelayMutex.Unlock()
	if len(s.getHeaderDelaySettings) == 0 {
		s.getHeaderDelaySettings = map[string]DelaySettings{
			id: {delay, maxDelay},
		}
		return
	}
	s.getHeaderDelaySettings[id] = DelaySettings{delay, maxDelay}
}
func (s *DataService) GetAccounts(ctx context.Context) map[string]any {
	items := s.accounts.Items()
	accounts := make(map[string]any)
	for k, v := range items {
		accounts[k] = v.Object
	}

	return accounts
}

func (s *DataService) SetAccounts(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case acc := <-s.accountCh:
			s.accounts.Set(acc.accountID, acc.validatorID, cache.NoExpiration)
		}
	}
}

func (s *DataService) SendAccount(accountID, validatorID string) {
	select {
	case s.accountCh <- account{accountID: accountID, validatorID: validatorID}:
	default:
		s.logger.Warn().Msg("accountCh is full, unable to send account details")
	}
}

func (s *DataService) dynamicFuncWrapper(accountID string, msIntoSlot int64, cluster, userAgent string, latency int64, clientIP string, clientTimeoutMS int64, bidAdjustmentBufferTimeMs int64) (int64, int64, int64, error) {
	if s.delayerPlugin != nil {
		return s.delayerPlugin(accountID, msIntoSlot, cluster, userAgent, latency, clientIP, s.logger, s.getHeaderTimeout, clientTimeoutMS, bidAdjustmentBufferTimeMs)
	}

	return 0, 0, 0, nil
}

func (s *DataService) GetSlotDuty(slot uint64) (*common.MiniValidatorLatency, error) {
	if s.miniProposerSlotMap == nil {
		return nil, common.ErrNoProposerSlotMap
	}
	v, _ := s.miniProposerSlotMap.Load(slot)
	return v, nil
}

func (s *DataService) GetFlowService() IFlowService {
	return s.flowSvc
}
