package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	relaygrpc "github.com/bloXroute-Labs/relay-grpc"
	"github.com/bloXroute-Labs/relayproxy"
	"github.com/bloXroute-Labs/relayproxy/common"
	"github.com/bloXroute-Labs/relayproxy/fluentstats"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-boost-utils/bls"
	boostSsz "github.com/flashbots/go-boost-utils/ssz"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/fluent/fluent-logger-golang/fluent"
	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
	"github.com/uptrace/uptrace-go/uptrace"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	_ "google.golang.org/grpc/encoding/gzip" // to enable gzip encoding
	"google.golang.org/grpc/keepalive"
)

// GRPC dial options
const (
	windowSize = 1024 * 1024 * 3 // 3 MB
	bufferSize = 0               // to disallow batching data before writing

	defaultBufferLimit = 32 * 1024
	tag                = "proxy.go.log"
	messageField       = "msg"
	timestampFormat    = "2006-01-02T15:04:05.000Z07:00"
)

var (
	// Included in the build process
	_BuildVersion string
	_AppName      = ""
	_SecretToken  string
	// defaults
	defaultListenAddr = getEnv("RELAY_PROXY_LISTEN_ADDR", "localhost:18550")
	defaultNetwork    = common.EthNetworkMainnet

	listenAddr                = flag.String("addr", defaultListenAddr, "mev-relay-proxy server listening address")
	relaysGRPCURL             = flag.String("relays", fmt.Sprintf("%v:%d", "127.0.0.1", 5000), "comma seperated list of relay grpc URL")
	streamingRelaysGRPCURL    = flag.String("streaming-relays", fmt.Sprintf("%v:%d", "127.0.0.1", 5000), "comma seperated list of relay grpc URL for streaming")
	registrationRelaysGRPCURL = flag.String("registration-relays", fmt.Sprintf("%v:%d", "127.0.0.1", 5000), "registration relays grpc URL")
	getHeaderDelayInMS        = flag.Int64("get-header-delay-ms", 0, "delay for sending the getHeader request in millisecond")
	getHeaderMaxDelayInMS     = flag.Int64("get-header-max-delay-ms", 0, "max delay for sending the getHeader request in millisecond")
	authKey                   = flag.String("auth-key", "", "account authentication key")
	nodeID                    = flag.String("node-id", fmt.Sprintf("rproxy-%v", uuid.New().String()), "unique identifier for the node")
	uptraceDSN                = flag.String("uptrace-dsn", "", "uptrace URL")
	// fluentD
	fluentDHostFlag   = flag.String("fluentd-host", "", "fluentd host")
	beaconGenesisTime = flag.Int64("beacon-genesis-time", 1606824023, "beacon genesis time in unix timestamp, default value set to mainnet")
	delaySettingsJSON = flag.String("get-header-delay-ms-settings-json", "{}",
		"JSON string representing delay settings for each validator in millisecond Ex:`{\"validatorA\": {\"sleep\": 0, \"max_sleep\": 0}, \"validatorB\": {\"sleep\": 0, \"max_sleep\": 0}}`")
	getHeaderTimeoutJSON = flag.String("get-header-timout-ms-json", "{}",
		"JSON string representing get header time out for each validator(accountID) in millisecond Ex:`{\"validatorA\": 0, \"validatorB\": 0}`")
	// access filter
	ipAllowList      = flag.String("ip-allow-list", "", "comma seperated list of ip address to be allowed")
	ipBlockList      = flag.String("ip-block-list", "", "comma seperated list of ip address to be blocked")
	accountAllowList = flag.String("account-allow-list", "", "comma seperated list of account id to be allowed")
	accountBlockList = flag.String("account-block-list", "", "comma seperated list of account id to be blocked")
	network          = flag.String("network", defaultNetwork, "which network to use")
	skipAuth         = flag.Bool("skip-auth", false, "auth header authentication skip flag")

	// external relay
	externalRelayURL = flag.String("external-relay", "", "external relay to be called")
)
var (
	grpcPort          = flag.String("grpc-port", "5001", "grpc port")
	secondsPerSlot    = flag.Int64("seconds-per-slot", 12, "seconds per slot")
	secretKey         = flag.String("secret-key", "", "private key used for signing messages")
	expectedPublicKey = flag.String("expected-public-key", "", "expected decoded public key")
	accountImportPath = flag.String("account-import-filepath", "", "file path for accounts list")
	adminAccountID    = flag.String("admin-account-id", "", "admin account id")
)

func main() {
	flag.Parse()

	l := newLogger(_AppName, _BuildVersion)

	if *fluentDHostFlag != "" {
		host, port, err := net.SplitHostPort(*fluentDHostFlag)
		if err != nil {
			l.Fatal("error parsing fluentd host", zap.Error(err))
		}
		portInt, err := strconv.Atoi(port)
		if err != nil {
			l.Fatal("error parsing fluentd port", zap.Error(err))
		}
		fluentLogger, err := fluent.New(fluent.Config{
			FluentHost:    host,
			FluentPort:    portInt,
			MarshalAsJSON: true,
			Async:         true,
			BufferLimit:   defaultBufferLimit,
		})
		if err != nil {
			l.Fatal("failed to create fluentd logger", zap.Error(err))
		}
		l = l.WithOptions(zap.Hooks(func(entry zapcore.Entry) error {
			return fluentLogger.EncodeAndPostData(tag, time.Now(), map[string]string{messageField: entry.Message, "level": entry.Level.String(), "instance": *nodeID, "timestamp": time.Now().Format(timestampFormat)})
		}))
	}

	defer func() {
		if err := l.Sync(); err != nil {
			fmt.Fprintf(os.Stderr, "Error syncing log: %v\n", err)
		}
	}()
	// get header delay settings for each validator
	var delaySettings map[string]relayproxy.DelaySettings
	if err := json.Unmarshal([]byte(*delaySettingsJSON), &delaySettings); err != nil {
		l.Fatal("failed to parse delay settings json field")
	}
	// get header timeout for each validator
	var timeout map[string]int64
	if err := json.Unmarshal([]byte(*getHeaderTimeoutJSON), &timeout); err != nil {
		l.Fatal("failed to parse timeout settings json field", zap.String("getHeaderTimeoutJSON", *getHeaderTimeoutJSON))
	}
	l.Info("getHeaderSettings", zap.Any("timeoutMap", timeout), zap.Any("delaySettings", delaySettings))

	// create list of accounts/IPs to be allowed/blocked
	createAccessList := func(a, b string) relayproxy.AccessList {
		f := func(accStr string) map[string]struct{} {
			list := strings.Split(accStr, ",")
			acc := make(map[string]struct{}, len(list))
			for _, item := range list {
				if item != "" {
					acc[item] = struct{}{}
				}
			}
			return acc
		}
		return relayproxy.AccessList{
			AllowList: f(a),
			BlockList: f(b),
		}
	}

	accessFilter := relayproxy.AccessFilter{
		Accounts: createAccessList(*accountAllowList, *accountBlockList),
		IPs:      createAccessList(*ipAllowList, *ipBlockList),
	}

	ctx, cancel := context.WithCancel(context.Background())
	keepaliveOpts := grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                time.Minute,
		Timeout:             20 * time.Second,
		PermitWithoutStream: true,
	})

	// init client connection
	var (
		clients []*common.Client
		conns   []*grpc.ClientConn

		streamingClients []*common.Client
		streamingConns   []*grpc.ClientConn

		registrationClients []*common.Client
		regConns            []*grpc.ClientConn
	)

	// Parse the relaysGRPCURL
	newClients, newConns := getClientsAndConnsFromURLs(l, *relaysGRPCURL, conns, keepaliveOpts, clients)
	defer func() {
		for _, conn := range newConns {
			conn.Close()
		}
	}()

	// Parse the streamingRelaysGRPCURL
	newStreamingClients, newStreamingConns := getClientsAndConnsFromURLs(l, *streamingRelaysGRPCURL, streamingConns, keepaliveOpts, streamingClients)
	defer func() {
		for _, conn := range newStreamingConns {
			conn.Close()
		}
	}()

	// Parse the registrationRelaysURL
	newRegistrationClients, newRegConns := getClientsAndConnsFromURLs(l, *registrationRelaysGRPCURL, regConns, keepaliveOpts, registrationClients)
	defer func() {
		for _, conn := range newRegConns {
			conn.Close()
		}
	}()

	// Configure OpenTelemetry with sensible defaults.
	uptrace.ConfigureOpentelemetry(
		uptrace.WithDSN(*uptraceDSN),

		uptrace.WithServiceName(_AppName),
		uptrace.WithServiceVersion(_BuildVersion),
		uptrace.WithDeploymentEnvironment(*nodeID),
	)
	// Send buffered spans and free resources.
	defer func() {
		ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		if err := uptrace.Shutdown(ctxWithTimeout); err != nil {
			l.Error("failed to shutdown uptrace", zap.Error(err))
		}
	}()

	tracer := otel.Tracer("main")

	// init fluentD if enabled
	fluentLogger := fluentstats.NewStats(true, *fluentDHostFlag)

	ethNetworks, err := common.NewEthNetworkDetails(*network)
	if err != nil {
		l.Fatal("failed to create eth network", zap.Error(err))
	}
	httpClient := &http.Client{
		Timeout: time.Second * 2,
	}

	// set private and public keys
	boostSecretKey := bls.SecretKey{}
	var pubKey phase0.BLSPubKey
	if *secretKey == "" {
		newPrivateKey, _, err := bls.GenerateNewKeypair()
		if err != nil {
			l.Fatal("could not generate secret key", zap.Error(err))
		}
		boostSecretKey = *newPrivateKey

		// If using a random secret key, ensure it's the correct one
		blsPubkey, err := bls.PublicKeyFromSecretKey(&boostSecretKey)
		if err != nil {
			l.Fatal("could not generate public key", zap.Error(err))
		}
		pubKey, err = utils.BlsPublicKeyToPublicKey(blsPubkey)
		if err != nil {
			l.Fatal("could not generate public key", zap.Error(err))
		}

		l.Info("private key, " + boostSecretKey.String())
		l.Info("public key, " + pubKey.String())
	} else {
		envSkBytes, err := hexutil.Decode(*secretKey)
		if err != nil {
			l.Fatal("could not decode secret key")
		}
		sk, err := bls.SecretKeyFromBytes(envSkBytes)
		if err != nil {
			l.Fatal("could not decode secret key")
		}
		boostSecretKey = *sk

		// If using a secret key, ensure it's the correct one
		blsPubkey, err := bls.PublicKeyFromSecretKey(&boostSecretKey)
		if err != nil {
			l.Fatal("could not generate public key", zap.Error(err))
		}
		pubKey, err = utils.BlsPublicKeyToPublicKey(blsPubkey)
		if err != nil {
			l.Fatal("could not generate public key", zap.Error(err))
		}

		l.Info("public key, " + pubKey.String())
	}
	if pubKey.String() != *expectedPublicKey {
		l.Fatal("mismatched public keys", zap.String("expectedPubkey", *expectedPublicKey), zap.String("pubkey", pubKey.String()))
	}

	var accountsLists *relayproxy.AccountsLists
	if *accountImportPath != "" {
		accountsLists, err = relayproxy.LoadAccountsFromYAML(*accountImportPath)
		if err != nil {
			log.Fatalf("could not load accounts from yaml: %s", err.Error())
		}
	}

	// compute builder signing domain for Ethereum Mainnet
	var genesisForkVersion string
	switch *network {
	case common.EthNetworkHolesky:
		genesisForkVersion = common.GenesisForkVersionHolesky
	case common.EthNetworkSepolia:
		genesisForkVersion = boostTypes.GenesisForkVersionSepolia
	case common.EthNetworkMainnet:
		genesisForkVersion = boostTypes.GenesisForkVersionMainnet
	case common.EthNetworkCustom:
		genesisForkVersion = os.Getenv("GENESIS_FORK_VERSION")
	default:
		genesisForkVersion = boostTypes.GenesisForkVersionMainnet
	}

	builderSigningDomain, err := common.ComputeDomain(boostSsz.DomainTypeAppBuilder, genesisForkVersion, phase0.Root{}.String())
	if err != nil {
		l.Fatal("failed to compute builder signing domain", zap.Error(err))
	}

	l.Info("Starting rproxy server",
		zap.String("listenAddr", *listenAddr),
		zap.String("uptraceDSN", *uptraceDSN),
		zap.String("nodeID", *nodeID),
		zap.String("authKey", *authKey),
		zap.String("relaysGrpcURL", *relaysGRPCURL),
		zap.String("streamingRelaysGrpcURL", *streamingRelaysGRPCURL),
		zap.String("registrationRelaysGRPCURL", *registrationRelaysGRPCURL),
		zap.Int64("getHeaderDelayInMS", *getHeaderDelayInMS),
		zap.Int64("getHeaderMaxDelayInMS", *getHeaderMaxDelayInMS),
		zap.String("fluentdHostFlag", *fluentDHostFlag),
		zap.Int64("beaconGenesisTime", *beaconGenesisTime),
		zap.Int64("secondsPerSlot", *secondsPerSlot),
		zap.Bool("skipAuth", *skipAuth),
		zap.Any("externalRelays", *externalRelayURL),
		zap.Any("delaySettings", delaySettings),
		zap.String("ipAllowList", *ipAllowList),
	)

	var (
		dataSvcOpts []relayproxy.DataServiceOption
		svcOpts     []relayproxy.ServiceOption
		serverOpts  []relayproxy.ServerOption
	)
	dataSvcOpts = append(dataSvcOpts, relayproxy.WithDataSvcLogger(l))
	dataSvcOpts = append(dataSvcOpts, relayproxy.WithDataSvcNodeID(*nodeID))
	dataSvcOpts = append(dataSvcOpts, relayproxy.WithDataSvcTracer(tracer))
	dataSvcOpts = append(dataSvcOpts, relayproxy.WithDataSvcFluentD(fluentLogger))
	dataSvcOpts = append(dataSvcOpts, relayproxy.WithDataSvcBeaconGenesisTime(*beaconGenesisTime))
	dataSvcOpts = append(dataSvcOpts, relayproxy.WithDataSvcSecondsPerSlot(*secondsPerSlot))
	dataSvcOpts = append(dataSvcOpts, relayproxy.WithHttpClient(httpClient))
	dataSvcOpts = append(dataSvcOpts, relayproxy.WithExternalRelay(*externalRelayURL))
	dataSvcOpts = append(dataSvcOpts, relayproxy.WithGetHeaderDelay(*getHeaderDelayInMS))
	dataSvcOpts = append(dataSvcOpts, relayproxy.WithGetHeaderMaxDelay(*getHeaderMaxDelayInMS))
	dataSvcOpts = append(dataSvcOpts, relayproxy.WithGetHeaderDelaySettings(delaySettings))
	dataSvcOpts = append(dataSvcOpts, relayproxy.WithGetHeaderTimeout(timeout))
	dataSvcOpts = append(dataSvcOpts, relayproxy.WithAccountImportLists(accountsLists))

	dataSvc := relayproxy.NewDataService(dataSvcOpts...)

	builderBidsForProxySlot := cache.New(relayproxy.BuilderBidsCleanupInterval, relayproxy.BuilderBidsCleanupInterval)
	builderExistingBlockHash := cache.New(relayproxy.BuilderBidsCleanupInterval, relayproxy.BuilderBidsCleanupInterval)
	builderInfo := cache.New(time.Duration(*secondsPerSlot)*time.Second, time.Duration(*secondsPerSlot)*time.Second)
	// local cache to store getPayloadResponse
	getPayloadResponseForProxySlot := cache.New(relayproxy.ExecutionPayloadCleanupInterval, relayproxy.ExecutionPayloadCleanupInterval)

	svcOpts = append(svcOpts, relayproxy.WithSvcLogger(l))
	svcOpts = append(svcOpts, relayproxy.WithVersion(_BuildVersion))
	svcOpts = append(svcOpts, relayproxy.WithNodeID(*nodeID))
	svcOpts = append(svcOpts, relayproxy.WithAuthKey(*authKey))
	svcOpts = append(svcOpts, relayproxy.WithSecretToken(_SecretToken))
	svcOpts = append(svcOpts, relayproxy.WithSvcBeaconGenesisTime(*beaconGenesisTime))
	svcOpts = append(svcOpts, relayproxy.WithSvcSecondsPerSlot(*secondsPerSlot))
	svcOpts = append(svcOpts, relayproxy.WithEthNetworkDetails(ethNetworks))
	svcOpts = append(svcOpts, relayproxy.WithClients(newClients))
	svcOpts = append(svcOpts, relayproxy.WithStreamingClients(newStreamingClients))
	svcOpts = append(svcOpts, relayproxy.WithRegistrationClients(newRegistrationClients))
	svcOpts = append(svcOpts, relayproxy.WithSvcTracer(tracer))
	svcOpts = append(svcOpts, relayproxy.WithSvcFluentD(fluentLogger))
	svcOpts = append(svcOpts, relayproxy.WithDataService(dataSvc))
	svcOpts = append(svcOpts, relayproxy.WithBuilderBidsForProxySlot(builderBidsForProxySlot))
	svcOpts = append(svcOpts, relayproxy.WithBuilderExistingBlockHash(builderExistingBlockHash))
	svcOpts = append(svcOpts, relayproxy.WithBuilderInfo(builderInfo))
	svcOpts = append(svcOpts, relayproxy.WithGetPayloadResponseForProxySlot(getPayloadResponseForProxySlot))
	svcOpts = append(svcOpts, relayproxy.WithSecretKey(&boostSecretKey))
	svcOpts = append(svcOpts, relayproxy.WithPublicKey(pubKey))
	svcOpts = append(svcOpts, relayproxy.WithSigningDomain(builderSigningDomain))
	svcOpts = append(svcOpts, relayproxy.WithSvcListenAddress(*listenAddr))
	svcOpts = append(svcOpts, relayproxy.WithSvcGrpcListenAddress(*grpcPort))
	svcOpts = append(svcOpts, relayproxy.WithAccountList(accountsLists))

	svc := relayproxy.NewService(svcOpts...)

	// server options
	serverOpts = append(serverOpts, relayproxy.WithLogger(l))
	serverOpts = append(serverOpts, relayproxy.WithListenAddress(*listenAddr))
	serverOpts = append(serverOpts, relayproxy.WithService(svc))
	serverOpts = append(serverOpts, relayproxy.WithBeaconGenesisTime(*beaconGenesisTime))
	serverOpts = append(serverOpts, relayproxy.WithSecondsPerSlot(*secondsPerSlot))
	serverOpts = append(serverOpts, relayproxy.WithTracer(tracer))
	serverOpts = append(serverOpts, relayproxy.WithFluentD(fluentLogger))
	serverOpts = append(serverOpts, relayproxy.WithAccessFilter(accessFilter))
	serverOpts = append(serverOpts, relayproxy.WithSkipAuth(*skipAuth))
	serverOpts = append(serverOpts, relayproxy.WithAccountsLists(accountsLists))
	serverOpts = append(serverOpts, relayproxy.WithServerNodeID(*nodeID))
	serverOpts = append(serverOpts, relayproxy.WithAdminAccountID(*adminAccountID))

	// init server
	server := relayproxy.New(serverOpts...)

	exit := make(chan struct{})
	go func() {
		shutdown := make(chan os.Signal, 1)
		signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
		<-shutdown
		l.Warn("shutting down")
		signal.Stop(shutdown)
		cancel()
		server.Stop()
		close(exit)
	}()

	// start receiving account info
	go dataSvc.SetAccounts(ctx)

	// start listening for payload prefetch event
	go svc.StartPreFetcher(ctx)

	// start streaming headers
	go func(_ctx context.Context) {
		wg := new(sync.WaitGroup)
		svc.StartStreamHeaders(_ctx, wg)
	}(ctx)

	<-exit
}

func newLogger(appName, version string) *zap.Logger {
	logLevel := zap.DebugLevel
	var zapCore zapcore.Core
	level := zap.NewAtomicLevel()
	level.SetLevel(logLevel)
	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.EncodeTime = zapcore.TimeEncoderOfLayout(time.RFC3339Nano)

	// Use a buffered, non-blocking writer
	logWriter := zapcore.AddSync(&zapcore.BufferedWriteSyncer{
		WS:            zapcore.Lock(os.Stdout), // Output destination
		Size:          256 * 1024,              // 256 KB buffer before flush
		FlushInterval: time.Second,             // Flush every second
	})

	encoder := zapcore.NewJSONEncoder(encoderCfg)
	zapCore = zapcore.NewCore(encoder, logWriter, level)

	logger := zap.New(zapCore, zap.AddCaller(), zap.ErrorOutput(zapcore.Lock(os.Stderr)))
	logger = logger.With(zap.String("app", appName), zap.String("buildVersion", version))
	return logger
}

func getEnv(key string, defaultValue string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return defaultValue
}

func getClientsAndConnsFromURLs(l *zap.Logger, relaysGRPCURL string, conns []*grpc.ClientConn, keepaliveOpts grpc.DialOption, clients []*common.Client) ([]*common.Client, []*grpc.ClientConn) {
	// Parse the relaysGRPCURL
	relays := strings.Split(relaysGRPCURL, ",")
	// Dial each relay and store the connections
	for _, relayURL := range relays {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
		conn, err := grpc.DialContext(
			ctx,
			relayURL,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			keepaliveOpts,
			grpc.WithInitialConnWindowSize(windowSize),
			grpc.WithWriteBufferSize(bufferSize),
		)
		cancel()
		if err != nil {
			// Handle error: failed to dial relay
			l.Error("failed to dial relay", zap.Error(err), zap.String("url", relayURL))
			continue
		}
		conns = append(conns, conn)
		clients = append(clients, &common.Client{URL: relayURL, RelayClient: relaygrpc.NewRelayClient(conn)})
	}
	if len(conns) == 0 {
		l.Fatal("failed to create grpc connection")
	}
	return clients, conns
}
