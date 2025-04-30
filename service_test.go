package relayproxy

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attestantio/go-builder-client/spec"
	relaygrpc "github.com/bloXroute-Labs/relay-grpc"
	"github.com/bloXroute-Labs/relayproxy/common"
	"github.com/bloXroute-Labs/relayproxy/fluentstats"
	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	testNodeID                = ""
	testParentHash            = "0x736f7e43b0b9d840d9152e7a5426f8d876a33f3ba52300bbd2923c9c7d5b62dc"
	testProposerPubkey        = "0x932c01d6fdb20b882983a74fd0d140015e7d6f6ca783209aad778507e62dc92143238484257f9aa39fb90f01f6b5ecdf"
	testBuilderPubkey1        = "0xae147691b534e441597cbd6a479aaa662126ca8426457737e895ae33251ea048d2d94bd18800999d6b04b1ace560be50"
	testBuilderPubkey2        = "0xb9451d2bc9d8c82d88da94da16ea30435dfc9c0de14bf7eb2a5bd3c0774a9a99c3136914679d9a11d214bec1e46f55a0"
	testBuilderPubkey3        = "0x8265169a40b57b91ad258817217f3edeeb3d648a4a61ef0bc125b2c23ac72be1c31dff632a2aa5d58b86203d4c3e5c43"
	testSlot1          uint64 = 1
	//testSlot2          uint64 = 2
	testValueLow    int64 = 1
	testValueMedium int64 = 10
	testValueHigh   int64 = 100
)

var (
	testBlockHash1   = [32]byte{0x0000000000000000000000000000000000000000000000000000000000000001}
	testBlockHash2   = [32]byte{0x0000000000000000000000000000000000000000000000000000000000000002}
	testBlockHash3   = [32]byte{0x0000000000000000000000000000000000000000000000000000000000000003}
	lowBlockBytes    = []byte(`lowBlock`)
	mediumBlockBytes = []byte(`mediumBlock`)
	highBlockBytes   = []byte(`highBlock`)
)

const (
	TestAuthHeader = ""
)

func TestService_RegisterValidator(t *testing.T) {

	tests := map[string]struct {
		f           func(ctx context.Context, req *relaygrpc.RegisterValidatorRequest, opts ...grpc.CallOption) (*relaygrpc.RegisterValidatorResponse, error)
		wantSuccess any
		wantErr     *ErrorResp
	}{
		"If registerValidator succeeded ": {
			f: func(ctx context.Context, req *relaygrpc.RegisterValidatorRequest, opts ...grpc.CallOption) (*relaygrpc.RegisterValidatorResponse, error) {
				return &relaygrpc.RegisterValidatorResponse{Code: 0, Message: "success"}, nil
			},
			wantSuccess: struct{}{},
			wantErr:     nil,
		},
		"If registerValidator returns error": {
			f: func(ctx context.Context, req *relaygrpc.RegisterValidatorRequest, opts ...grpc.CallOption) (*relaygrpc.RegisterValidatorResponse, error) {
				return nil, fmt.Errorf("error")
			},
			wantErr: toErrorResp(http.StatusInternalServerError, "relays returned error"),
		},
		"If registerValidator returns empty output": {
			f: func(ctx context.Context, req *relaygrpc.RegisterValidatorRequest, opts ...grpc.CallOption) (*relaygrpc.RegisterValidatorResponse, error) {
				return nil, nil
			},
			wantErr: toErrorResp(http.StatusInternalServerError, "empty response from relay"),
		},
		"If registerValidator returns error output": {
			f: func(ctx context.Context, req *relaygrpc.RegisterValidatorRequest, opts ...grpc.CallOption) (*relaygrpc.RegisterValidatorResponse, error) {
				return &relaygrpc.RegisterValidatorResponse{Code: 2, Message: "failed"}, nil
			},
			wantErr: toErrorResp(http.StatusInternalServerError, "relay returned failure response code"),
		},
	}
	for testName, tt := range tests {
		t.Run(testName, func(t *testing.T) {
			s := &Service{
				logger:              zap.NewNop(),
				clients:             []*common.Client{{URL: "", NodeID: "", Conn: nil, RelayClient: &mockRelayClient{RegisterValidatorFunc: tt.f}}},
				registrationClients: []*common.Client{{URL: "", NodeID: "", Conn: nil, RelayClient: &mockRelayClient{RegisterValidatorFunc: tt.f}}},
				tracer:              noop.NewTracerProvider().Tracer("test"),
				fluentD:             fluentstats.NewStats(true, "0.0.0.0:24224"),
			}
			got, _, err := s.RegisterValidator(context.Background(), context.Background(), time.Now(), nil, "", TestAuthHeader, "", "", "", false, false)
			if err == nil {
				assert.Equal(t, got, tt.wantSuccess)
				return
			}
			assert.Equal(t, err.Error(), tt.wantErr.Error())
		})
	}
}

func TestService_GetHeader(t *testing.T) {
	tests := map[string]struct {
		slot               string
		parentHash         string
		pubKey             string
		accountID          string
		slotStartTimeShift time.Duration
		wantErr            *ErrorResp
	}{
		"invalid slot ": {
			slot: "xyz",
			wantErr: &ErrorResp{
				Code:    http.StatusNoContent,
				Message: errInvalidSlot.Error(),
			},
		},
		"invalid pubKey ": {
			slot:   "123",
			pubKey: "dummy-pubkey",
			wantErr: &ErrorResp{
				Code:    http.StatusNoContent,
				Message: errInvalidPubkey.Error(),
			},
		},
		"invalid parent hash": {
			slot:       "123",
			pubKey:     testBuilderPubkey1,
			parentHash: "dummy-parent-hash",
			wantErr: &ErrorResp{
				Code:    http.StatusNoContent,
				Message: errInvalidHash.Error(),
			},
		},
		"default header too late": {
			slot:               "123",
			pubKey:             testBuilderPubkey1,
			parentHash:         "dummy-parent-hash",
			slotStartTimeShift: 3100 * time.Millisecond,
			wantErr: &ErrorResp{
				Code:    http.StatusNoContent,
				Message: common.ErrLateHeader.Error(),
			},
		},
	}
	for testName, tt := range tests {
		t.Run(testName, func(t *testing.T) {
			dopts := make([]DataServiceOption, 0)
			dopts = append(dopts, WithDataSvcLogger(zap.NewNop()))
			dopts = append(dopts, WithDataSvcSecondsPerSlot(12))
			dopts = append(dopts, WithDataSvcBeaconGenesisTime(1606824023))
			dSvc := NewDataService(dopts...)
			dSvc.accountsLists = &AccountsLists{AccountIDToInfo: make(map[string]*AccountInfo),
				AccountNameToInfo: make(map[AccountName]*AccountInfo)}
			opts := make([]ServiceOption, 0)
			opts = append(opts, WithSvcLogger(zap.NewNop()))
			opts = append(opts, WithDataService(dSvc))
			opts = append(opts, WithClients([]*common.Client{{URL: "", NodeID: "", Conn: nil, RelayClient: &mockRelayClient{}}}))
			opts = append(opts, WithSvcTracer(noop.NewTracerProvider().Tracer("test")))
			opts = append(opts, WithSvcFluentD(fluentstats.NewStats(true, "0.0.0.0:24224")))
			opts = append(opts, WithSvcBeaconGenesisTime(1606824023))
			opts = append(opts, WithSvcSecondsPerSlot(12))
			opts = append(opts, WithBuilderBidsForProxySlot(cache.New(5*time.Minute, 12*time.Minute)))
			svc := NewService(opts...)
			svc.accountsLists = &AccountsLists{AccountIDToInfo: make(map[string]*AccountInfo),
				AccountNameToInfo: make(map[AccountName]*AccountInfo)}
			slotInt, _ := strconv.Atoi(tt.slot)
			slotStartTime := GetSlotStartTime(1606824023, int64(slotInt), 12)
			if tt.slotStartTimeShift > 0 {
				slotStartTime = slotStartTime.Add(tt.slotStartTimeShift)
			}
			accountID := tt.accountID
			_, _, err := svc.GetHeader(context.Background(), slotStartTime, "", "ip", tt.slot, tt.parentHash, tt.pubKey, TestAuthHeader, "", accountID, "", "", "")
			assert.Equal(t, tt.wantErr.Error(), err.Error())
		})
	}
}

func TestService_getPayload(t *testing.T) {

	tests := map[string]struct {
		f           func(ctx context.Context, req *relaygrpc.GetPayloadRequest, opts ...grpc.CallOption) (*relaygrpc.GetPayloadResponse, error)
		wantSuccess []byte
		wantErr     *ErrorResp
	}{
		"If getPayload succeeded ": {
			f: func(ctx context.Context, req *relaygrpc.GetPayloadRequest, opts ...grpc.CallOption) (*relaygrpc.GetPayloadResponse, error) {
				return &relaygrpc.GetPayloadResponse{Code: 0, Message: "success", VersionedExecutionPayload: []byte(`payload`)}, nil
			},
			wantSuccess: []byte(`payload`),
			wantErr:     nil,
		},
		"If getPayload returns error": {
			f: func(ctx context.Context, req *relaygrpc.GetPayloadRequest, opts ...grpc.CallOption) (*relaygrpc.GetPayloadResponse, error) {
				return nil, fmt.Errorf("error")
			},
			wantErr: toErrorResp(http.StatusInternalServerError, "relay returned error"),
		},
		"If getPayload returns empty output": {
			f: func(ctx context.Context, req *relaygrpc.GetPayloadRequest, opts ...grpc.CallOption) (*relaygrpc.GetPayloadResponse, error) {
				return nil, nil
			},
			wantErr: toErrorResp(http.StatusInternalServerError, "empty response from relay"),
		},
	}
	for testName, tt := range tests {
		t.Run(testName, func(t *testing.T) {
			var svcOpts []ServiceOption
			svcOpts = append(svcOpts, WithSvcLogger(zap.NewNop()))
			svcOpts = append(svcOpts, WithClients([]*common.Client{{RelayClient: &mockRelayClient{GetPayloadFunc: tt.f}}}))
			svcOpts = append(svcOpts, WithSvcTracer(noop.NewTracerProvider().Tracer("test")))
			svcOpts = append(svcOpts, WithSvcFluentD(fluentstats.NewStats(true, "0.0.0.0:24224")))

			s := NewService(svcOpts...)
			s.accountsLists = &AccountsLists{AccountIDToInfo: make(map[string]*AccountInfo),
				AccountNameToInfo: make(map[AccountName]*AccountInfo)}
			got, _, err := s.GetPayload(context.Background(), time.Now(), nil, "", TestAuthHeader, "", "", "", "", "", "")
			if err == nil {
				assert.Equal(t, string(got.(json.RawMessage)), string(tt.wantSuccess))
				return
			}
			assert.Equal(t, err.Error(), tt.wantErr.Error())
		})
	}
}
func TestBlockCancellation(t *testing.T) {
	s := &Service{
		logger:                  zap.NewNop(),
		builderBidsForProxySlot: cache.New(BuilderBidsCleanupInterval, BuilderBidsCleanupInterval),
		accountsLists: &AccountsLists{AccountIDToInfo: make(map[string]*AccountInfo),
			AccountNameToInfo: make(map[AccountName]*AccountInfo)},
	}

	// test no bids found (cache key not found)
	result, err := s.GetTopBuilderBid("unknown")
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no builder bids found")

	// set up bids map for cache key
	cacheKey := s.keyForCachingBids(testSlot1, testParentHash, testProposerPubkey)
	bidsMap := NewStringMapOf[*common.Bid]()
	s.builderBidsForProxySlot.Set(cacheKey, bidsMap, cache.DefaultExpiration)

	// test no bids found (cache key found but bids map empty)
	result, err = s.GetTopBuilderBid(cacheKey)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no builder bids found")

	// add low value bid
	lowBid := common.NewBid(
		new(big.Int).SetInt64(testValueLow).Bytes(),
		lowBlockBytes,
		nil,
		hex.EncodeToString(testBlockHash1[:]),
		testBuilderPubkey1,
		"",
		"",
		nil,
	)
	bidsMap.Store(testBuilderPubkey1, lowBid)

	// add high value bid
	highBid := common.NewBid(
		new(big.Int).SetInt64(testValueHigh).Bytes(),
		highBlockBytes,
		nil,
		hex.EncodeToString(testBlockHash2[:]),
		testBuilderPubkey2,
		"",
		"",
		nil,
	)
	bidsMap.Store(testBuilderPubkey2, highBid)

	// add medium value bid
	mediumBid := common.NewBid(
		new(big.Int).SetInt64(testValueMedium).Bytes(),
		mediumBlockBytes,
		nil,
		hex.EncodeToString(testBlockHash3[:]),
		testBuilderPubkey3,
		"",
		"",
		nil,
	)
	bidsMap.Store(testBuilderPubkey3, mediumBid)

	// test expected high bid found
	result, err = s.GetTopBuilderBid(cacheKey)
	assert.Nil(t, err)
	assert.Equal(t, *highBid, *result)
}

func TestBlockCancellationForSamePubKey(t *testing.T) {
	s := &Service{
		logger:                  zap.NewNop(),
		builderBidsForProxySlot: cache.New(BuilderBidsCleanupInterval, BuilderBidsCleanupInterval),
		accountsLists: &AccountsLists{AccountIDToInfo: make(map[string]*AccountInfo),
			AccountNameToInfo: make(map[AccountName]*AccountInfo)},
	}

	// test no bids found (cache key not found)
	result, err := s.GetTopBuilderBid("unknown")
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no builder bids found")

	// set up bids map for cache key
	cacheKey := s.keyForCachingBids(testSlot1, testParentHash, testProposerPubkey)
	bidsMap := NewStringMapOf[*common.Bid]()
	s.builderBidsForProxySlot.Set(cacheKey, bidsMap, cache.DefaultExpiration)

	// test no bids found (cache key found but bids map empty)
	result, err = s.GetTopBuilderBid(cacheKey)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no builder bids found")

	// Add value for testBuilderPubkey1
	// add low value bid
	lowBid := common.NewBid(
		new(big.Int).SetInt64(testValueLow).Bytes(),
		lowBlockBytes,
		nil,
		hex.EncodeToString(testBlockHash1[:]),
		testBuilderPubkey1,
		"",
		"",
		nil,
	)
	bidsMap.Store(testBuilderPubkey1, lowBid)

	// add high value bid
	highBid := common.NewBid(
		new(big.Int).SetInt64(testValueHigh).Bytes(),
		highBlockBytes,
		nil,
		hex.EncodeToString(testBlockHash2[:]),
		testBuilderPubkey1,
		"",
		"",
		nil,
	)
	bidsMap.Store(testBuilderPubkey1, highBid)

	// add medium value bid
	mediumBid := common.NewBid(
		new(big.Int).SetInt64(testValueMedium).Bytes(),
		mediumBlockBytes,
		nil,
		hex.EncodeToString(testBlockHash3[:]),
		testBuilderPubkey1,
		"",
		"",
		nil,
	)
	bidsMap.Store(testBuilderPubkey1, mediumBid)

	// Add value for testBuilderPubkey2
	// add low value bid
	lowBid1 := common.NewBid(
		new(big.Int).SetInt64(testValueLow).Bytes(),
		lowBlockBytes,
		nil,
		hex.EncodeToString(testBlockHash1[:]),
		testBuilderPubkey2,
		"",
		"",
		nil,
	)
	bidsMap.Store(testBuilderPubkey2, lowBid1)

	// add medium value bid
	mediumBid1 := common.NewBid(
		new(big.Int).SetInt64(testValueMedium).Bytes(),
		mediumBlockBytes,
		nil,
		hex.EncodeToString(testBlockHash3[:]),
		testBuilderPubkey2,
		"",
		"",
		nil,
	)
	bidsMap.Store(testBuilderPubkey2, mediumBid1)

	// add high value bid
	highBid1 := common.NewBid(
		new(big.Int).SetInt64(testValueHigh).Bytes(),
		highBlockBytes,
		nil,
		hex.EncodeToString(testBlockHash2[:]),
		testBuilderPubkey2,
		"",
		"",
		nil,
	)
	bidsMap.Store(testBuilderPubkey2, highBid1)

	// Add value for testBuilderPubkey3
	// add medium value bid
	mediumBid2 := common.NewBid(
		new(big.Int).SetInt64(testValueMedium).Bytes(),
		mediumBlockBytes,
		nil,
		hex.EncodeToString(testBlockHash3[:]),
		testBuilderPubkey3,
		"",
		"",
		nil,
	)
	bidsMap.Store(testBuilderPubkey3, mediumBid2)

	// add high value bid
	highBid2 := common.NewBid(
		new(big.Int).SetInt64(testValueHigh).Bytes(),
		highBlockBytes,
		nil,
		hex.EncodeToString(testBlockHash2[:]),
		testBuilderPubkey3,
		"",
		"",
		nil,
	)
	bidsMap.Store(testBuilderPubkey3, highBid2)

	// add low value bid
	lowBid2 := common.NewBid(
		new(big.Int).SetInt64(testValueLow).Bytes(),
		lowBlockBytes,
		nil,
		hex.EncodeToString(testBlockHash1[:]),
		testBuilderPubkey3,
		"",
		"",
		nil,
	)
	bidsMap.Store(testBuilderPubkey3, lowBid2)

	// test expected high bid found
	result, err = s.GetTopBuilderBid(cacheKey)
	assert.Nil(t, err)
	assert.Equal(t, *highBid1, *result)
}

func TestService_StreamHeaderAndGetMethod(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := zap.NewNop()
	fluent := fluentstats.NewStats(true, "0.0.0.0:24224")
	//l, _ := zap.NewDevelopment()
	streams := []stream{
		{Slot: uint64(66), BlockHash: "blockHash66", ParentHash: "0x66", ProposerPubKey: "0x66", Value: new(big.Int).SetInt64(66666).Bytes()},
		{Slot: uint64(66), BlockHash: "blockHash66", ParentHash: "0x66", ProposerPubKey: "0x66", Value: new(big.Int).SetInt64(66668).Bytes()},
		{Slot: uint64(66), BlockHash: "blockHash67", ParentHash: "0x66", ProposerPubKey: "0x66", Value: new(big.Int).SetInt64(66669).Bytes(), Payload: []byte("{\"version\":\"capella\",\"data\":{\"message\":{\"header\":{\"parent_hash\":\"0xbd0ada39aca5fed393fa4bf80d45d4703e3a9aa3c0a09750879cb842f1bdfc58\",\"fee_recipient\":\"0x8dC847Af872947Ac18d5d63fA646EB65d4D99560\",\"state_root\":\"0x3047ac621434c21c527f38d676382fa10e402f742e6d47bc6e07e7a2c13fdf32\",\"receipts_root\":\"0xeaf609cff0ccedd82d3db9029455b5ce52f0d8f4b91977d9251db72bc73acf1e\",\"logs_bloom\":\"0x00310412002012002a001066840114452398001008403a4000eb341024000912221080280208300681509a0b80810070740ba236ca21371102118f89312c201653f2c03c4c009c9946a0401a5218c233c20d046090460801860442868c2610244900006086420ad0a008b28430000ac0700008e84028054400826812c09800c12a22b472491401c03040301502c100000027100d904c82e8342104e2e400808042e808402465080203811582a04808880602f610900043a000487036a08002009410c00210a21084004aa4108153430a060200a2408800190821849a5808e0084130004509222c47280a11808240800492421454021303414898f80415800774\",\"prev_randao\":\"0x21a739f58604430cef3e5c550a955bc5943bae4c3dae6a01672be878ae0a5e1b\",\"block_number\":\"10077336\",\"gas_limit\":\"30000000\",\"gas_used\":\"9696787\",\"timestamp\":\"1700496012\",\"extra_data\":\"0x506f776572656420627920626c6f58726f757465\",\"base_fee_per_gas\":\"11\",\"block_hash\":\"0xf4488a3b1fa59a3ce2e52a087ae3d7c93ff4a29f0a2df93a003b02902571cc54\",\"transactions_root\":\"0x9956dd9ece5082f2eab87c2b5d22f7ed6cf7c865cc461c20ee71bee07b031368\",\"withdrawals_root\":\"0x2f2680e6bca4d97e9a776567779f7a290766634e1fc6a0fce75ceabe239240bb\"},\"value\":\"54788421837882049\",\"pubkey\":\"0x821f2a65afb70e7f2e820a925a9b4c80a159620582c1766b1b09729fec178b11ea22abb3a51f07b288be815a1a2ff516\"},\"signature\":\"0x8e7678fb099b1489ad5d0929d48d4c5839e09f8884bf3cbbf309a5d1032f723c5b599ac00d53c3bea7b5fc70f1ac53fd0f8e6692d18ec94b8565f9fa18dc393867b43400774968f6e0f1d40282764d64a5ef5897716a2e5f9e3b667f3e49c0fe\"}}")},
		{Slot: uint64(77), BlockHash: "blockHash77", ParentHash: "0x77", ProposerPubKey: "0x77", Value: new(big.Int).SetInt64(77777).Bytes()},
		{Slot: uint64(88), BlockHash: "blockHash88", ParentHash: "0x88", ProposerPubKey: "0x88", Value: new(big.Int).SetInt64(88888).Bytes()},
	}
	// Set up your mock gRPC server and client.
	srv := grpc.NewServer()

	relaygrpc.RegisterRelayServer(srv, &mockRelayServer{output: streams, logger: l})

	// Create a listener and start the server.
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal("Failed to create listener", zap.Error(err))
	}
	go func() {
		if err := srv.Serve(lis); err != nil {
			panic(err)
		}
	}()

	defer srv.Stop()

	// Create a gRPC client that connects to the mock server.
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal("Failed to create client connection", zap.Error(err))
	}
	defer conn.Close()
	relayClient := relaygrpc.NewRelayClient(conn)
	dSvc := NewDataService(WithDataSvcLogger(zap.NewNop()))
	dSvc.accountsLists = &AccountsLists{AccountIDToInfo: make(map[string]*AccountInfo),
		AccountNameToInfo: make(map[AccountName]*AccountInfo)}
	svcOpts := make([]ServiceOption, 0)
	c := &common.Client{URL: lis.Addr().String(), NodeID: "", Conn: conn, RelayClient: relayClient}
	clients := []*common.Client{c}
	sc := &common.Client{URL: lis.Addr().String(), NodeID: "", Conn: conn, RelayClient: relayClient}
	streamingClients := []*common.Client{sc}
	registrationClient := &common.Client{URL: lis.Addr().String(), NodeID: "", Conn: conn, RelayClient: relayClient}
	registrationClients := []*common.Client{registrationClient}
	tracer := noop.NewTracerProvider().Tracer("test")
	svcOpts = append(svcOpts, WithSvcLogger(l))
	svcOpts = append(svcOpts, WithClients(clients))
	svcOpts = append(svcOpts, WithStreamingClients(streamingClients))
	svcOpts = append(svcOpts, WithRegistrationClients(registrationClients))
	svcOpts = append(svcOpts, WithSvcTracer(tracer))
	svcOpts = append(svcOpts, WithSvcFluentD(fluent))
	svcOpts = append(svcOpts, WithDataService(dSvc))
	svcOpts = append(svcOpts, WithBuilderExistingBlockHash(cache.New(BuilderBidsCleanupInterval, BuilderBidsCleanupInterval)))
	svcOpts = append(svcOpts, WithBuilderBidsForProxySlot(cache.New(BuilderBidsCleanupInterval, BuilderBidsCleanupInterval)))

	service := NewService(svcOpts...)
	service.accountsLists = &AccountsLists{AccountIDToInfo: make(map[string]*AccountInfo),
		AccountNameToInfo: make(map[AccountName]*AccountInfo)}
	go func() {
		if _, err := service.StreamHeader(ctx, c); err != nil {
			panic(err)
		}
	}()

	server := &Server{svc: service, logger: zap.NewNop(), listenAddress: "127.0.0.1:9090", accountsLists: &AccountsLists{AccountIDToInfo: make(map[string]*AccountInfo),
		AccountNameToInfo: make(map[AccountName]*AccountInfo)}}
	go func() {
		if err := server.Start(); err != nil {
			panic(err)
		}
	}()

	defer server.Stop()

	<-time.After(time.Second * 1)

	client := http.Client{}

	tests := map[string]struct {
		in      stream
		args    []stream
		want    any
		wantErr bool
	}{
		"If key not present in the header map": {
			in:      stream{Slot: uint64(99), ParentHash: "0x00", ProposerPubKey: "0x00"},
			args:    streams,
			wantErr: true,
		},
		// "If key present in the header map": {
		// 	in:      stream{Slot: uint64(66), ParentHash: "0x66", ProposerPubKey: "0x66"},
		// 	args:    streams,
		// 	want:    json.RawMessage("{\"version\":\"capella\",\"data\":{\"message\":{\"header\":{\"parent_hash\":\"0xbd0ada39aca5fed393fa4bf80d45d4703e3a9aa3c0a09750879cb842f1bdfc58\",\"fee_recipient\":\"0x8dC847Af872947Ac18d5d63fA646EB65d4D99560\",\"state_root\":\"0x3047ac621434c21c527f38d676382fa10e402f742e6d47bc6e07e7a2c13fdf32\",\"receipts_root\":\"0xeaf609cff0ccedd82d3db9029455b5ce52f0d8f4b91977d9251db72bc73acf1e\",\"logs_bloom\":\"0x00310412002012002a001066840114452398001008403a4000eb341024000912221080280208300681509a0b80810070740ba236ca21371102118f89312c201653f2c03c4c009c9946a0401a5218c233c20d046090460801860442868c2610244900006086420ad0a008b28430000ac0700008e84028054400826812c09800c12a22b472491401c03040301502c100000027100d904c82e8342104e2e400808042e808402465080203811582a04808880602f610900043a000487036a08002009410c00210a21084004aa4108153430a060200a2408800190821849a5808e0084130004509222c47280a11808240800492421454021303414898f80415800774\",\"prev_randao\":\"0x21a739f58604430cef3e5c550a955bc5943bae4c3dae6a01672be878ae0a5e1b\",\"block_number\":\"10077336\",\"gas_limit\":\"30000000\",\"gas_used\":\"9696787\",\"timestamp\":\"1700496012\",\"extra_data\":\"0x506f776572656420627920626c6f58726f757465\",\"base_fee_per_gas\":\"11\",\"block_hash\":\"0xf4488a3b1fa59a3ce2e52a087ae3d7c93ff4a29f0a2df93a003b02902571cc54\",\"transactions_root\":\"0x9956dd9ece5082f2eab87c2b5d22f7ed6cf7c865cc461c20ee71bee07b031368\",\"withdrawals_root\":\"0x2f2680e6bca4d97e9a776567779f7a290766634e1fc6a0fce75ceabe239240bb\"},\"value\":\"54788421837882049\",\"pubkey\":\"0x821f2a65afb70e7f2e820a925a9b4c80a159620582c1766b1b09729fec178b11ea22abb3a51f07b288be815a1a2ff516\"},\"signature\":\"0x8e7678fb099b1489ad5d0929d48d4c5839e09f8884bf3cbbf309a5d1032f723c5b599ac00d53c3bea7b5fc70f1ac53fd0f8e6692d18ec94b8565f9fa18dc393867b43400774968f6e0f1d40282764d64a5ef5897716a2e5f9e3b667f3e49c0fe\"}}"),
		// 	wantErr: false,
		// },
	}
	for testName, tt := range tests {
		t.Run(testName, func(t *testing.T) {
			got, _, err := service.GetHeader(ctx, time.Now(), "", "", strconv.FormatUint(tt.in.Slot, 10), tt.in.ParentHash, tt.in.ProposerPubKey, TestAuthHeader, "", "", "", "", "")
			if (err != nil) != tt.wantErr {
				t.Errorf("GetHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetHeader() got = %v, wantErr %v", got, tt.want)
			}
			responsePayload := new(spec.VersionedSignedBuilderBid)
			code, err := sendHTTPRequest(context.Background(), client, http.MethodGet, fmt.Sprintf("http://127.0.0.1:9090/eth/v1/builder/header/%v/%v/%v", tt.in.Slot, tt.in.ParentHash, tt.in.ProposerPubKey), "", map[string]string{}, nil, responsePayload)
			if !tt.wantErr {
				assert.Nil(t, err)
				assert.Equal(t, code, http.StatusOK)
				hash, err := responsePayload.BlockHash()
				assert.Nil(t, err)
				assert.Equal(t, hash.String(), "0xf4488a3b1fa59a3ce2e52a087ae3d7c93ff4a29f0a2df93a003b02902571cc54")
			}
		})
	}
}

type UserAgent string

//lint:ignore U1000 Ignore unused variable
func sendHTTPRequest(ctx context.Context, client http.Client, method, url string, userAgent UserAgent, headers map[string]string, payload, dst any) (code int, err error) {
	var req *http.Request

	if payload == nil {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	} else {
		payloadBytes, err2 := json.Marshal(payload)
		if err2 != nil {
			return 0, fmt.Errorf("could not marshal request: %w", err2)
		}
		req, err = http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payloadBytes))

		// Set header
		req.Header.Add("Content-Type", "application/json")
	}
	if err != nil {
		return 0, fmt.Errorf("could not prepare request: %w", err)
	}

	// Set user agent header
	req.Header.Set("User-Agent", strings.TrimSpace(fmt.Sprintf("mev-boost/%s %s", "test-version", userAgent)))

	// Set other headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}

	if resp.StatusCode > 299 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("could not read error response body for status code %d: %w", resp.StatusCode, err)
		}
		return resp.StatusCode, fmt.Errorf("%w: %d / %s", errors.New("HTTP error response"), resp.StatusCode, string(bodyBytes))
	}

	if dst != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("could not read response body: %w", err)
		}
		if err := json.Unmarshal(bodyBytes, &dst); err != nil {
			return resp.StatusCode, fmt.Errorf("could not unmarshal response %s: %w", string(bodyBytes), err)
		}

	}

	return resp.StatusCode, nil
}
func TestGetBuilderBidForSlot(t *testing.T) {
	svc := &Service{
		logger:                  zap.NewNop(),
		builderBidsForProxySlot: cache.New(5*time.Minute, 10*time.Minute),
		accountsLists: &AccountsLists{AccountIDToInfo: make(map[string]*AccountInfo),
			AccountNameToInfo: make(map[AccountName]*AccountInfo)},
	}
	bid1 := &common.Bid{}
	bid2 := &common.Bid{}
	// set up builder bids map for test slot
	cacheKey := svc.keyForCachingBids(testSlot1, testParentHash, testProposerPubkey)
	builderBidsMap := NewStringMapOf[*common.Bid]()
	builderBidsMap.Store(testBuilderPubkey1, bid1)
	svc.builderBidsForProxySlot.Set(cacheKey, builderBidsMap, cache.DefaultExpiration)

	// test builder bid found
	bid, found := svc.getBuilderBidForSlot(cacheKey, testBuilderPubkey1)
	assert.Equal(t, bid, bid2)
	assert.True(t, found)

	// test builder bid not found (unknown builder pubkey)
	bid, found = svc.getBuilderBidForSlot(cacheKey, "unknown")
	assert.Nil(t, bid)
	assert.False(t, found)

	// test builder bid not found (unknown cache key)
	cacheKey = svc.keyForCachingBids(testSlot1, testParentHash, "unknown")
	bid, found = svc.getBuilderBidForSlot(cacheKey, testBuilderPubkey1)
	assert.Nil(t, bid)
	assert.False(t, found)
}

//lint:ignore U1000 Ignore unused variable
type mockRelayServer struct {
	relaygrpc.UnimplementedRelayServer
	output []stream
	logger *zap.Logger
}

func (m *mockRelayServer) SubmitBlock(ctx context.Context, request *relaygrpc.SubmitBlockRequest) (*relaygrpc.SubmitBlockResponse, error) {
	panic("implement me")
}

func (m *mockRelayServer) RegisterValidator(ctx context.Context, request *relaygrpc.RegisterValidatorRequest) (*relaygrpc.RegisterValidatorResponse, error) {
	panic("implement me")
}

func (m *mockRelayServer) GetHeader(ctx context.Context, request *relaygrpc.GetHeaderRequest) (*relaygrpc.GetHeaderResponse, error) {
	panic("implement me")
}

func (m *mockRelayServer) GetPayload(ctx context.Context, request *relaygrpc.GetPayloadRequest) (*relaygrpc.GetPayloadResponse, error) {
	panic("implement me")
}

func (m *mockRelayServer) StreamHeader(request *relaygrpc.StreamHeaderRequest, srv relaygrpc.Relay_StreamHeaderServer) error {
	// Simulate streaming of header for testing.
	// send predefined headers to the client via srv.Send().
	bidStream := make(chan stream, 100)
	go func() {
		for _, s := range m.output {
			m.logger.Warn("sending stream")
			bidStream <- s
		}
		close(bidStream)
	}()
	for bid := range bidStream {
		m.logger.Warn("sending header")
		header := &relaygrpc.StreamHeaderResponse{
			Slot:       bid.Slot,
			ParentHash: bid.ParentHash,
			Pubkey:     bid.ProposerPubKey,
			Value:      bid.Value,
			Payload:    bid.Payload,
			BlockHash:  bid.BlockHash,
		}
		if err := srv.Send(header); err != nil {
			m.logger.Error("error sending header", zap.Error(err))
			continue
		}
	}
	return nil
}

//lint:ignore U1000 Ignore unused variable
type stream struct {
	Slot           uint64
	ParentHash     string
	ProposerPubKey string
	Value          []byte
	Payload        []byte
	BlockHash      string
	BuilderPubKey  string
}

type mockRelayClient struct {
	RegisterValidatorFunc func(ctx context.Context, req *relaygrpc.RegisterValidatorRequest, opts ...grpc.CallOption) (*relaygrpc.RegisterValidatorResponse, error)
	GetPayloadFunc        func(ctx context.Context, req *relaygrpc.GetPayloadRequest, opts ...grpc.CallOption) (*relaygrpc.GetPayloadResponse, error)
	StreamHeaderFunc      func(ctx context.Context, in *relaygrpc.StreamHeaderRequest, opts ...grpc.CallOption) (relaygrpc.Relay_StreamHeaderClient, error)
	GetHeaderFunc         func(ctx context.Context, req *relaygrpc.GetHeaderRequest, opts ...grpc.CallOption) (*relaygrpc.GetHeaderResponse, error)
	StreamBlockFunc       func(ctx context.Context, in *relaygrpc.StreamBlockRequest, opts ...grpc.CallOption) (relaygrpc.Relay_StreamBlockClient, error)
	StreamBuilderFunc     func(ctx context.Context, in *relaygrpc.StreamBuilderRequest, opts ...grpc.CallOption) (relaygrpc.Relay_StreamBuilderClient, error)

	ForwardBlockFunc func(ctx context.Context, in *relaygrpc.StreamBlockResponse, opts ...grpc.CallOption) (*relaygrpc.SubmitBlockResponse, error)
	Pingfunc         func(ctx context.Context, in *relaygrpc.PingRequest, opts ...grpc.CallOption) (*relaygrpc.PingResponse, error)
}

func (m *mockRelayClient) GetValidatorRegistration(ctx context.Context, in *relaygrpc.GetValidatorRegistrationRequest, opts ...grpc.CallOption) (*relaygrpc.GetValidatorRegistrationResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockRelayClient) PreFetchGetPayload(ctx context.Context, in *relaygrpc.PreFetchGetPayloadRequest, opts ...grpc.CallOption) (*relaygrpc.PreFetchGetPayloadResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (m *mockRelayClient) SubmitBlock(ctx context.Context, in *relaygrpc.SubmitBlockRequest, opts ...grpc.CallOption) (*relaygrpc.SubmitBlockResponse, error) {
	panic("implement me")
}

func (m *mockRelayClient) ForwardBlock(ctx context.Context, in *relaygrpc.StreamBlockResponse, opts ...grpc.CallOption) (*relaygrpc.SubmitBlockResponse, error) {
	panic("implement me")
}

func (m *mockRelayClient) RegisterValidator(ctx context.Context, req *relaygrpc.RegisterValidatorRequest, opts ...grpc.CallOption) (*relaygrpc.RegisterValidatorResponse, error) {
	if m.RegisterValidatorFunc != nil {
		return m.RegisterValidatorFunc(ctx, req, opts...)
	}
	return nil, nil
}
func (m *mockRelayClient) GetHeader(ctx context.Context, in *relaygrpc.GetHeaderRequest, opts ...grpc.CallOption) (*relaygrpc.GetHeaderResponse, error) {
	if m.GetHeaderFunc != nil {
		return m.GetHeaderFunc(ctx, in, opts...)
	}
	return nil, nil
}

func (m *mockRelayClient) StreamHeader(ctx context.Context, in *relaygrpc.StreamHeaderRequest, opts ...grpc.CallOption) (relaygrpc.Relay_StreamHeaderClient, error) {
	if m.StreamHeaderFunc != nil {
		return m.StreamHeaderFunc(ctx, in, opts...)
	}
	return nil, nil
}

func (m *mockRelayClient) GetPayload(ctx context.Context, req *relaygrpc.GetPayloadRequest, opts ...grpc.CallOption) (*relaygrpc.GetPayloadResponse, error) {

	if m.GetPayloadFunc != nil {
		return m.GetPayloadFunc(ctx, req, opts...)
	}
	return nil, nil
}

func (m *mockRelayClient) StreamBlock(ctx context.Context, in *relaygrpc.StreamBlockRequest, opts ...grpc.CallOption) (relaygrpc.Relay_StreamBlockClient, error) {
	if m.StreamBlockFunc != nil {
		return m.StreamBlockFunc(ctx, in, opts...)
	}
	return nil, nil
}

func (m *mockRelayClient) StreamBuilder(ctx context.Context, in *relaygrpc.StreamBuilderRequest, opts ...grpc.CallOption) (relaygrpc.Relay_StreamBuilderClient, error) {
	if m.StreamBuilderFunc != nil {
		return m.StreamBuilderFunc(ctx, in, opts...)
	}
	return nil, nil
}

func (m *mockRelayClient) Ping(ctx context.Context, req *relaygrpc.PingRequest, opts ...grpc.CallOption) (*relaygrpc.PingResponse, error) {
	if m.Pingfunc != nil {
		return m.Pingfunc(ctx, req, opts...)
	}
	return nil, nil
}

// MockClient is a mock of Client interface
type MockClient struct {
	mock.Mock
}

func (m *MockClient) SubmitBlock(ctx context.Context, in *relaygrpc.SubmitBlockRequest, opts ...grpc.CallOption) (*relaygrpc.SubmitBlockResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockClient) RegisterValidator(ctx context.Context, in *relaygrpc.RegisterValidatorRequest, opts ...grpc.CallOption) (*relaygrpc.RegisterValidatorResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockClient) GetHeader(ctx context.Context, in *relaygrpc.GetHeaderRequest, opts ...grpc.CallOption) (*relaygrpc.GetHeaderResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockClient) StreamHeader(ctx context.Context, in *relaygrpc.StreamHeaderRequest, opts ...grpc.CallOption) (relaygrpc.Relay_StreamHeaderClient, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockClient) GetValidatorRegistration(ctx context.Context, in *relaygrpc.GetValidatorRegistrationRequest, opts ...grpc.CallOption) (*relaygrpc.GetValidatorRegistrationResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockClient) PreFetchGetPayload(ctx context.Context, in *relaygrpc.PreFetchGetPayloadRequest, opts ...grpc.CallOption) (*relaygrpc.PreFetchGetPayloadResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockClient) GetPayload(ctx context.Context, in *relaygrpc.GetPayloadRequest, opts ...grpc.CallOption) (*relaygrpc.GetPayloadResponse, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*relaygrpc.GetPayloadResponse), args.Error(1)
}

func (m *MockClient) StreamBlock(ctx context.Context, in *relaygrpc.StreamBlockRequest, opts ...grpc.CallOption) (relaygrpc.Relay_StreamBlockClient, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockClient) StreamBuilder(ctx context.Context, in *relaygrpc.StreamBuilderRequest, opts ...grpc.CallOption) (relaygrpc.Relay_StreamBuilderClient, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockClient) ForwardBlock(ctx context.Context, in *relaygrpc.StreamBlockResponse, opts ...grpc.CallOption) (*relaygrpc.SubmitBlockResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockClient) Ping(ctx context.Context, in *relaygrpc.PingRequest, opts ...grpc.CallOption) (*relaygrpc.PingResponse, error) {
	//TODO implement me
	panic("implement me")
}

func TestGetPayloadWithRetry(t *testing.T) {
	// Define test cases
	tests := []struct {
		name                    string
		mockReq                 *relaygrpc.GetPayloadRequest
		mockResp                *relaygrpc.GetPayloadResponse
		mockErr                 error
		expectedErr             *ErrorResp
		expectedResult          string
		expectedNoOfTimesCalled int
	}{
		{
			name:                    "Success on first try",
			mockResp:                &relaygrpc.GetPayloadResponse{Code: uint32(codes.OK), Message: "Success"},
			mockReq:                 &relaygrpc.GetPayloadRequest{},
			expectedErr:             nil,
			expectedResult:          "Success",
			expectedNoOfTimesCalled: 1,
		},
		{
			name:     "Fail with could not find requested payload",
			mockResp: &relaygrpc.GetPayloadResponse{Code: uint32(codes.Unavailable), Message: "could not find requested payload"},
			mockReq:  &relaygrpc.GetPayloadRequest{},
			expectedErr: toErrorResp(http.StatusBadRequest, "relay returned failure response code",
				zap.String("relayError", "could not find requested payload"), zap.String("url", ""), zap.Uint64("slot", 0), zap.String("BlockHash", ""),
				zap.String("parentHash", ""), zap.String("BlockValue", ""), zap.String("uniqueKey", "slot_0_bHash__pHash_")),
			expectedResult:          "could not find requested payload",
			expectedNoOfTimesCalled: 3,
		},
		{
			name:     "Fail with invalid signature",
			mockResp: &relaygrpc.GetPayloadResponse{Code: uint32(codes.Unavailable), Message: "invalid signature"},
			mockReq:  &relaygrpc.GetPayloadRequest{},
			expectedErr: toErrorResp(http.StatusBadRequest, "relay returned error",
				zap.String("relayError", "invalid signature"), zap.String("url", ""), zap.Uint64("slot", 0), zap.String("BlockHash", ""),
				zap.String("parentHash", ""), zap.String("BlockValue", ""), zap.String("uniqueKey", "slot_0_bHash__pHash_")),
			expectedResult:          "invalid signature",
			expectedNoOfTimesCalled: 1,
		},
		{
			name:                    "Fail with error",
			mockResp:                nil,
			mockReq:                 &relaygrpc.GetPayloadRequest{},
			mockErr:                 fmt.Errorf("context cancelled"),
			expectedErr:             toErrorResp(http.StatusInternalServerError, "relay returned error", zap.String("relayError", "context cancelled"), zap.String("url", "")),
			expectedResult:          "",
			expectedNoOfTimesCalled: 3,
		},
		{
			name:                    "Fail with empty resp",
			mockResp:                nil,
			mockReq:                 &relaygrpc.GetPayloadRequest{},
			mockErr:                 nil,
			expectedErr:             toErrorResp(http.StatusInternalServerError, "empty response from relay", zap.String("url", "")),
			expectedResult:          "",
			expectedNoOfTimesCalled: 3,
		},
		// Add more test cases for retry logic, empty responses, etc.
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockClient := new(MockClient)
			mockClient.On("GetPayload", mock.Anything, mock.Anything).Return(tc.mockResp, tc.mockErr)
			trcr := noop.NewTracerProvider().Tracer("")
			_, span := trcr.Start(context.Background(), "")
			client := &common.Client{URL: "", NodeID: "", Conn: nil, RelayClient: mockClient}
			service := &Service{
				clients: []*common.Client{client},
				tracer:  trcr,
				accountsLists: &AccountsLists{AccountIDToInfo: make(map[string]*AccountInfo),
					AccountNameToInfo: make(map[AccountName]*AccountInfo)},
			}
			result, err := service.getPayloadWithRetry(context.Background(), client, span, tc.mockReq, 2)
			if result != nil {
				assert.Equal(t, tc.expectedResult, result.ServerMessage)
			}
			assert.Equal(t, tc.expectedErr, err)
			mockClient.AssertNumberOfCalls(t, "GetPayload", tc.expectedNoOfTimesCalled)
		})
	}
}

func TestVouch(t *testing.T) {
	require.True(t, isVouch("Vouch/1.9.1"))
}
