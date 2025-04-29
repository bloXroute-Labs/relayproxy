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
	"gopkg.in/yaml.v2"

	"github.com/patrickmn/go-cache"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

const (
	GetHeaderRequestCutoffMs             = 3000
	delayEligibilityCacheCleanupInterval = 60 * time.Second
)

type IDataService interface {
	GetAccounts(ctx context.Context) map[string]any
	SetAccounts(ctx context.Context)
	SendAccount(accountID, validatorID string)

	GetDelaySettings(ctx context.Context) map[string]DelaySettings
	SetDelayForValidator(id string, delay, maxDelay int64)
	SetDelayForValidators(settings map[string]DelaySettings)
	DelayGetHeader(ctx context.Context, in DelayGetHeaderParams) (DelayGetHeaderResponse, error)
}

type DataService struct {
	logger                 *zap.Logger
	nodeID                 string
	tracer                 trace.Tracer
	fluentD                fluentstats.Stats
	beaconGenesisTime      int64
	secondsPerSlot         int64
	httpClient             *http.Client
	externalRelay          string
	getHeaderDelay         int64
	getHeaderMaxDelay      int64
	getHeaderDelaySettings map[string]DelaySettings
	accounts               *cache.Cache // list of accountID:validatorID
	accountCh              chan account
	getHeaderDelayMutex    sync.RWMutex
	getHeaderTimeout       map[string]int64 // MEV Boost get header timeout for each validator
	ipCacheStore           *cache.Cache     // list of ip to verify delay eligibility
	accountsLists          *AccountsLists
	delayerPlugin          func(accountID string, msIntoSlot int64, cluster, userAgent string, latency int64, clientIP string, logger *zap.Logger, getHeaderTimeout map[string]int64) (int64, int64, error)
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
}
type AccountsLists struct {
	AccountIDToInfo   map[string]*AccountInfo
	AccountNameToInfo map[AccountName]*AccountInfo
}
type DelayGetHeaderResponse struct {
	Sleep, MaxSleep       int64
	SlotStartTime         time.Time
	Latency               int64
	ExternalRelayResponse ExternalRelayResponse
}
type ExternalRelayResponse struct {
	URL             string
	ReqStartTime    time.Time
	ResReceivedAt   time.Time
	ReqDurationInMS int64
	Response        []byte
	Err             error
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
	s.logger.Warn("received empty client IP, unable to verify delay eligibility", zap.String("key", slotWithParentHash))
	return false
}

func (s *DataService) DelayGetHeader(ctx context.Context, in DelayGetHeaderParams) (DelayGetHeaderResponse, error) {

	slotInt := AToI(in.Slot)
	slotStartTime := GetSlotStartTime(s.beaconGenesisTime, slotInt, s.secondsPerSlot)
	msIntoSlot := in.ReceivedAt.Sub(slotStartTime).Milliseconds()

	// first request from an IP is responded immediately
	// subsequent request from same IP will be delayed
	if s.accountsLists.AccountIDToInfo[in.AccountID] != nil &&
		s.accountsLists.AccountIDToInfo[in.AccountID].InstantReturnFirstRequest {
		if ok := s.shouldRequestDelayed(in.ClientIP, in.SlotWithParentHash); !ok {
			return DelayGetHeaderResponse{
				Sleep:         0,
				MaxSleep:      0,
				Latency:       in.Latency,
				SlotStartTime: slotStartTime,
			}, nil
		}
	}
	var (
		sleep, maxSleep int64
		err             error
	)
	if GetHeaderRequestCutoffMs > 0 && msIntoSlot > GetHeaderRequestCutoffMs {
		return DelayGetHeaderResponse{}, common.ErrLateHeader
	}
	sleep, maxSleep, err = s.dynamicFuncWrapper(in.AccountID, msIntoSlot, in.Cluster, in.UserAgent, in.Latency, in.ClientIP)
	if err != nil {
		return DelayGetHeaderResponse{}, err
	}

	delayFunc := func() {
		maxSleepTime := slotStartTime.Add(time.Duration(maxSleep) * time.Millisecond)
		if time.Now().UTC().Add(time.Duration(sleep) * time.Millisecond).After(maxSleepTime) {
			time.Sleep(maxSleepTime.Sub(time.Now().UTC()))
		} else {
			time.Sleep(time.Duration(sleep) * time.Millisecond)
		}
	}
	if msIntoSlot < maxSleep {
		delayFunc()
	}

	return DelayGetHeaderResponse{
		Sleep:         sleep,
		MaxSleep:      maxSleep,
		Latency:       in.Latency,
		SlotStartTime: slotStartTime,
	}, nil
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
		s.logger.Warn("accountCh is full, unable to send account details")
	}
}

func (s *DataService) dynamicFuncWrapper(accountID string, msIntoSlot int64, cluster, userAgent string, latency int64, clientIP string) (int64, int64, error) {
	if s.delayerPlugin != nil {
		return s.delayerPlugin(accountID, msIntoSlot, cluster, userAgent, latency, clientIP, s.logger, s.getHeaderTimeout)
	}

	return 0, 0, nil
}
