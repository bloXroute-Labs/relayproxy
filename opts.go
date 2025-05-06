package relayproxy

import (
	"net/http"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloXroute-Labs/relayproxy/common"
	"github.com/bloXroute-Labs/relayproxy/fluentstats"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/patrickmn/go-cache"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type ServerOption func(*Server)

func WithLogger(logger *zap.Logger) ServerOption {
	return func(s *Server) {
		s.logger = logger
	}
}

func WithHTTPServer(server *http.Server) ServerOption {
	return func(s *Server) {
		s.server = server
	}
}

func WithService(svc *Service) ServerOption {
	return func(s *Server) {
		s.svc = svc
	}
}

func WithListenAddress(address string) ServerOption {
	return func(s *Server) {
		s.listenAddress = address
	}
}

func WithBeaconGenesisTime(genesisTime int64) ServerOption {
	return func(s *Server) {
		s.beaconGenesisTime = genesisTime
	}
}
func WithSecondsPerSlot(secondsPerSlot int64) ServerOption {
	return func(s *Server) {
		s.secondsPerSlot = secondsPerSlot
	}
}

func WithTracer(tracer trace.Tracer) ServerOption {
	return func(s *Server) {
		s.tracer = tracer
	}
}

func WithFluentD(fluentD fluentstats.Stats) ServerOption {
	return func(s *Server) {
		s.fluentD = fluentD
	}
}

func WithAccessFilter(filter AccessFilter) ServerOption {
	return func(s *Server) {
		s.accessFilter = filter
	}
}
func WithSkipAuth(skip bool) ServerOption {
	return func(s *Server) {
		s.accessFilter.SkipAuth = skip
	}
}

func WithAuthHeaderP2P(authHeader string) ServerOption {
	return func(s *Server) {
		s.authHeaderP2P = authHeader
	}
}

func WithAccountsLists(accountsLists *AccountsLists) ServerOption {
	return func(s *Server) {
		s.accountsLists = accountsLists
	}
}
func WithServerNodeID(nodeID string) ServerOption {
	return func(s *Server) {
		s.NodeID = nodeID
	}
}
func WithAdminAccountID(accountId string) ServerOption {
	return func(s *Server) {
		s.AdminAccountID = accountId
	}
}

type ServiceOption func(*Service)

func WithSvcLogger(logger *zap.Logger) ServiceOption {
	return func(s *Service) {
		s.logger = logger
	}
}

func WithVersion(version string) ServiceOption {
	return func(s *Service) {
		s.version = version
	}
}

func WithNodeID(nodeID string) ServiceOption {
	return func(s *Service) {
		s.nodeID = nodeID
	}
}

func WithAuthKey(authKey string) ServiceOption {
	return func(s *Service) {
		s.authKey = authKey
	}
}

func WithSecretToken(secretToken string) ServiceOption {
	return func(s *Service) {
		s.secretToken = secretToken
	}
}

func WithSvcTracer(tracer trace.Tracer) ServiceOption {
	return func(s *Service) {
		s.tracer = tracer
	}
}

func WithSvcFluentD(fluentD fluentstats.Stats) ServiceOption {
	return func(s *Service) {
		s.fluentD = fluentD
	}
}

func WithBuilderBidsForProxySlot(cache *cache.Cache) ServiceOption {
	return func(s *Service) {
		s.builderBidsForProxySlot = cache
	}
}
func WithBuilderExistingBlockHash(cache *cache.Cache) ServiceOption {
	return func(s *Service) {
		s.builderExistingBlockHash = cache
	}
}

func WithBuilderInfo(builderInfo *cache.Cache) ServiceOption {
	return func(s *Service) {
		s.builderInfo = builderInfo
	}
}

func WithGetPayloadResponseForProxySlot(cache *cache.Cache) ServiceOption {
	return func(s *Service) {
		s.getPayloadResponseForProxySlot = cache
	}
}

func WithPreFetchPayloadChan(ch chan preFetcherFields) ServiceOption {
	return func(s *Service) {
		s.preFetchPayloadChan = ch
	}
}

func WithSvcBeaconGenesisTime(time int64) ServiceOption {
	return func(s *Service) {
		s.beaconGenesisTime = time
	}
}

func WithSvcSecondsPerSlot(secondsPerSlot int64) ServiceOption {
	return func(s *Service) {
		s.secondsPerSlot = secondsPerSlot
	}
}

func WithSlotStats(cache *cache.Cache) ServiceOption {
	return func(s *Service) {
		s.slotStats = cache
	}
}

func WithDuplicateSlotCache(cache *cache.Cache) ServiceOption {
	return func(s *Service) {
		s.duplicateSlotCache = cache
	}
}

func WithSlotStatsEventCh(ch chan slotStatsEvent) ServiceOption {
	return func(s *Service) {
		s.slotStatsEventCh = ch
	}
}

func WithEthNetworkDetails(details *common.EthNetworkDetails) ServiceOption {
	return func(s *Service) {
		s.ethNetworkDetails = details
	}
}

func WithDialerClients(clients *DialerClients) ServiceOption {
	return func(s *Service) {
		s.dialerClients = clients
	}
}

func WithCurrentRegistrationRelayIndex(index int) ServiceOption {
	return func(s *Service) {
		s.currentRegistrationRelayIndex = index
	}
}

func WithSecretKey(secretKey *bls.SecretKey) ServiceOption {
	return func(s *Service) {
		s.secretKey = secretKey
	}
}

func WithPublicKey(publicKey phase0.BLSPubKey) ServiceOption {
	return func(s *Service) {
		s.publicKey = publicKey
	}
}

func WithSigningDomain(domain phase0.Domain) ServiceOption {
	return func(s *Service) {
		s.builderSigningDomain = domain
	}
}

func WithSvcListenAddress(listenAddr string) ServiceOption {
	return func(s *Service) {
		s.listenAddress = listenAddr
	}
}

func WithSvcGrpcListenAddress(listenAddr string) ServiceOption {
	return func(s *Service) {
		s.GrpcListenAddress = listenAddr
	}
}

func WithForwardedBlockCh(ch *chan common.ForwardedBlockInfo) ServiceOption {
	return func(s *Service) {
		s.forwardedBlockCh = ch
	}
}
func WithAccountList(accountsLists *AccountsLists) ServiceOption {
	return func(s *Service) {
		s.accountsLists = accountsLists
	}
}

func WithDataService(ds *DataService) ServiceOption {
	return func(s *Service) {
		s.IDataService = ds
	}
}

type DataServiceOption func(s *DataService)

func WithDataSvcLogger(logger *zap.Logger) DataServiceOption {
	return func(s *DataService) {
		s.logger = logger
	}
}

func WithDataSvcNodeID(nodeID string) DataServiceOption {
	return func(s *DataService) {
		s.nodeID = nodeID
	}
}

func WithDataSvcTracer(tracer trace.Tracer) DataServiceOption {
	return func(s *DataService) {
		s.tracer = tracer
	}
}

func WithDataSvcFluentD(fluentD fluentstats.Stats) DataServiceOption {
	return func(s *DataService) {
		s.fluentD = fluentD
	}
}

func WithDataSvcBeaconGenesisTime(time int64) DataServiceOption {
	return func(s *DataService) {
		s.beaconGenesisTime = time
	}
}

func WithDataSvcSecondsPerSlot(secondsPerSlot int64) DataServiceOption {
	return func(s *DataService) {
		s.secondsPerSlot = secondsPerSlot
	}
}

func WithHttpClient(client *http.Client) DataServiceOption {
	return func(s *DataService) {
		s.httpClient = client
	}
}

func WithExternalRelay(relay string) DataServiceOption {
	return func(s *DataService) {
		s.externalRelay = relay
	}
}
func WithAccounts(accounts *cache.Cache) DataServiceOption {
	return func(s *DataService) {
		s.accounts = accounts
	}
}

func WithAccountChannel(ch chan account) DataServiceOption {
	return func(s *DataService) {
		s.accountCh = ch
	}
}
func WithGetHeaderDelay(delay int64) DataServiceOption {
	return func(s *DataService) {
		s.getHeaderDelay = delay
	}
}

func WithGetHeaderMaxDelay(maxDelay int64) DataServiceOption {
	return func(s *DataService) {
		s.getHeaderMaxDelay = maxDelay
	}
}

func WithGetHeaderDelaySettings(settings map[string]DelaySettings) DataServiceOption {
	return func(s *DataService) {
		s.getHeaderDelaySettings = settings
	}
}

// WithGetHeaderTimeout set MEV boost timeout for each validator - default 950
func WithGetHeaderTimeout(timeout map[string]int64) DataServiceOption {
	return func(s *DataService) {
		s.getHeaderTimeout = timeout
	}
}

// Dialer options

type DialerOption func(*Dialer)

func WithRelayURL(url string) DialerOption {
	return func(d *Dialer) {
		d.DialURL.RelayURL = url
	}
}

func WithStreamingURL(url string) DialerOption {
	return func(d *Dialer) {
		d.DialURL.StreamingURL = url
	}
}

func WithRegistrationURL(url string) DialerOption {
	return func(d *Dialer) {
		d.DialURL.RegistrationURL = url
	}
}

func WithStreamingBlockURL(url string) DialerOption {
	return func(d *Dialer) {
		d.DialURL.StreamingBlockURL = url
	}
}

func WithIPConverter(ipConverter map[string]common.URLOpts) DialerOption {
	return func(d *Dialer) {
		d.IPConverter = ipConverter
	}
}

// Dialer clients options

type DialerClientsOption func(*DialerClients)

func WithClients(clients ...*common.Client) DialerClientsOption {
	return func(d *DialerClients) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.clients = append(d.clients, clients...)
	}
}

func WithStreamingClients(clients ...*common.Client) DialerClientsOption {
	return func(d *DialerClients) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.streamingClients = append(d.streamingClients, clients...)
	}
}

func WithStreamingBlockClients(clients ...*common.Client) DialerClientsOption {
	return func(d *DialerClients) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.streamingBlockClients = append(d.streamingBlockClients, clients...)
	}
}

func WithRegistrationClients(clients ...*common.Client) DialerClientsOption {
	return func(d *DialerClients) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.registrationClients = append(d.registrationClients, clients...)
	}
}

func WithAccountImportLists(accountsLists *AccountsLists) DataServiceOption {
	return func(s *DataService) {
		s.accountsLists = accountsLists
	}
}

func WithPlugin(customDelayer func(accountID string, msIntoSlot int64, cluster string, userAgent string, latency int64, clientIP string, logger *zap.Logger, getHeaderTimeout map[string]int64) (int64, int64, error)) DataServiceOption {
	return func(s *DataService) {
		s.delayerPlugin = customDelayer
	}
}

func WithMiniProposerSlotMap(miniProposerSlotMap *SyncMap[uint64, *common.MiniValidatorLatency]) DataServiceOption {
	return func(s *DataService) {
		s.miniProposerSlotMap = miniProposerSlotMap
	}
}
