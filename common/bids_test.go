package common

import (
	"math/big"
	"testing"
	"time"

	"github.com/holiman/uint256"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

var (
	testBuilderPubkeyA    = "0xaf89ab00a0eab1131645292a9cfba583a69a1e3ac58b210e262494853e67385aeb50d4af428bdd577b9399daa96d8b20"
	testBuilderPubkeyB    = "0x8a1d7b8dd64e0aafe7ea7b6c95065c9364cf99d38470c12ee807d55f7de1529ad29ce2c422e0b65e3d5a05c02caca249"
	testBuilderPubkeyC    = "0x98ab429cbb173ed76f2718d7ae4ab1cfe8fc36375f9d6c4618f998058d0e8b158255a4387faed53bb01cf8cb2a484a04"
	testBuilderExtraDataA = "0xa"
	testBuilderExtraDataB = "0xb"
	testBuilderExtraDataC = "0xc"
	testBlockHash1        = "blockHash1"
	testBlockHash2        = "blockHash2"
	testBlockHash3        = "blockHash3"
	testBlockHash4        = "blockHash4"
	testBlockHash5        = "blockHash5"
)

func saveTestBidMetadata(
	bidCache *BidMetadataCache,
	log *zerolog.Logger,
	cacheKey string,
	value int64,
	blockHash string,
	builderPubkey string,
	builderExtraData string,
	receivedAt time.Time,
	BlockSequenceNumber *uint64,
) (*Bid, *big.Int) {
	bidValue := big.NewInt(value)

	bid := &Bid{
		Value:               bidValue.Bytes(),
		BlockHash:           blockHash,
		BuilderPubkey:       builderPubkey,
		BuilderExtraData:    builderExtraData,
		ReceivedAt:          receivedAt,
		BlockSequenceNumber: BlockSequenceNumber,
	}

	bidCache.SetBidMetadataForProxySlot(log, cacheKey, bid)

	return bid, bidValue
}

func TestGetBidAdjustmentTargetBid(t *testing.T) {
	log := &zerolog.Logger{}
	cacheKey := "cacheKey"

	t.Run("No lookback time, later higher bid from top builder should win", func(t *testing.T) {
		bidCache := NewBidMetadataCache(time.Minute)
		now := time.Now().UTC()

		saveTestBidMetadata(bidCache, log, cacheKey, 200, testBlockHash1, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-2*time.Millisecond), nil)
		topBid, topBidValue := saveTestBidMetadata(bidCache, log, cacheKey, 300, testBlockHash2, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-1*time.Millisecond), nil)
		saveTestBidMetadata(bidCache, log, cacheKey, 100, testBlockHash3, testBuilderPubkeyC, testBuilderExtraDataB, now, nil)

		bidAdjustmentTargetBid := bidCache.GetBidAdjustmentTargetBid(log, cacheKey, 0, topBid, topBidValue)
		require.NotNil(t, bidAdjustmentTargetBid)
		require.Equal(t, uint256.NewInt(100).Bytes(), bidAdjustmentTargetBid.Value)
	})

	t.Run("No lookback time, later lower bid from top builder should win", func(t *testing.T) {
		bidCache := NewBidMetadataCache(time.Minute)
		now := time.Now().UTC()

		saveTestBidMetadata(bidCache, log, cacheKey, 300, testBlockHash1, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-2*time.Millisecond), nil)
		topBid, topBidValue := saveTestBidMetadata(bidCache, log, cacheKey, 200, testBlockHash2, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-1*time.Millisecond), nil)
		saveTestBidMetadata(bidCache, log, cacheKey, 100, testBlockHash3, testBuilderPubkeyB, testBuilderExtraDataB, now, nil)

		bidAdjustmentTargetBid := bidCache.GetBidAdjustmentTargetBid(log, cacheKey, 0, topBid, topBidValue)
		require.NotNil(t, bidAdjustmentTargetBid)
		require.Equal(t, uint256.NewInt(100).Bytes(), bidAdjustmentTargetBid.Value)
	})

	t.Run("No lookback time, BidAdjustmentTargetBid should be nil", func(t *testing.T) {
		bidCache := NewBidMetadataCache(time.Minute)
		now := time.Now().UTC()

		saveTestBidMetadata(bidCache, log, cacheKey, 100, testBlockHash1, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-1*time.Millisecond), nil)
		topBid, topBidValue := saveTestBidMetadata(bidCache, log, cacheKey, 300, testBlockHash2, testBuilderPubkeyA, testBuilderExtraDataA, now, nil)

		bidAdjustmentTargetBid := bidCache.GetBidAdjustmentTargetBid(log, cacheKey, 0, topBid, topBidValue)
		require.Nil(t, bidAdjustmentTargetBid)
	})

	t.Run("No lookback time, winning builder high bids were canceled with higher bid", func(t *testing.T) {
		bidCache := NewBidMetadataCache(time.Minute)
		now := time.Now().UTC()

		saveTestBidMetadata(bidCache, log, cacheKey, 300, testBlockHash1, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-4*time.Millisecond), nil)
		saveTestBidMetadata(bidCache, log, cacheKey, 400, testBlockHash2, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-3*time.Millisecond), nil)
		topBid, topBidValue := saveTestBidMetadata(bidCache, log, cacheKey, 500, testBlockHash3, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-2*time.Millisecond), nil)
		saveTestBidMetadata(bidCache, log, cacheKey, 200, testBlockHash4, testBuilderPubkeyB, testBuilderExtraDataB, now.Add(-1*time.Millisecond), nil)
		saveTestBidMetadata(bidCache, log, cacheKey, 100, testBlockHash5, testBuilderPubkeyC, testBuilderExtraDataC, now, nil)

		bidAdjustmentTargetBid := bidCache.GetBidAdjustmentTargetBid(log, cacheKey, 0, topBid, topBidValue)
		require.NotNil(t, bidAdjustmentTargetBid)
		require.Equal(t, uint256.NewInt(200).Bytes(), bidAdjustmentTargetBid.Value)
	})

	t.Run("No lookback time, winning builder high bids were canceled with lower bid", func(t *testing.T) {
		bidCache := NewBidMetadataCache(time.Minute)
		now := time.Now().UTC()

		saveTestBidMetadata(bidCache, log, cacheKey, 300, testBlockHash1, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-3*time.Millisecond), nil)
		saveTestBidMetadata(bidCache, log, cacheKey, 400, testBlockHash2, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-2*time.Millisecond), nil)
		topBid, topBidValue := saveTestBidMetadata(bidCache, log, cacheKey, 200, testBlockHash3, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-1*time.Millisecond), nil)
		saveTestBidMetadata(bidCache, log, cacheKey, 100, testBlockHash4, testBuilderPubkeyB, testBuilderExtraDataB, now, nil)

		bidAdjustmentTargetBid := bidCache.GetBidAdjustmentTargetBid(log, cacheKey, 0, topBid, topBidValue)
		require.NotNil(t, bidAdjustmentTargetBid)
		require.Equal(t, uint256.NewInt(100).Bytes(), bidAdjustmentTargetBid.Value)
	})

	t.Run("No lookback time, no bids", func(t *testing.T) {
		bidCache := NewBidMetadataCache(time.Minute)
		bidAdjustmentTargetBid := bidCache.GetBidAdjustmentTargetBid(log, cacheKey, 0, nil, big.NewInt(0))
		require.Nil(t, bidAdjustmentTargetBid)
	})

	t.Run("1000ms lookback time, later higher bid from top builder should win, bid adjustment target from same builder", func(t *testing.T) {
		bidCache := NewBidMetadataCache(time.Minute)
		now := time.Now().UTC()

		saveTestBidMetadata(bidCache, log, cacheKey, 200, testBlockHash1, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-1001*time.Millisecond), nil)
		topBid, topBidValue := saveTestBidMetadata(bidCache, log, cacheKey, 300, testBlockHash2, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-1*time.Millisecond), nil)
		saveTestBidMetadata(bidCache, log, cacheKey, 100, testBlockHash3, testBuilderPubkeyC, testBuilderExtraDataB, now, nil)

		bidAdjustmentTargetBid := bidCache.GetBidAdjustmentTargetBid(log, cacheKey, 1000, topBid, topBidValue)
		require.NotNil(t, bidAdjustmentTargetBid)
		require.Equal(t, uint256.NewInt(200).Bytes(), bidAdjustmentTargetBid.Value)
	})

	t.Run("1000ms lookback time, later higher bid from top builder should win, bid adjustment target from different builder", func(t *testing.T) {
		bidCache := NewBidMetadataCache(time.Minute)
		now := time.Now().UTC()

		saveTestBidMetadata(bidCache, log, cacheKey, 250, testBlockHash1, testBuilderPubkeyC, testBuilderExtraDataC, now.Add(-1002*time.Millisecond), nil)
		saveTestBidMetadata(bidCache, log, cacheKey, 200, testBlockHash2, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-1001*time.Millisecond), nil)
		topBid, topBidValue := saveTestBidMetadata(bidCache, log, cacheKey, 300, testBlockHash3, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-1*time.Millisecond), nil)
		saveTestBidMetadata(bidCache, log, cacheKey, 100, testBlockHash4, testBuilderPubkeyC, testBuilderExtraDataB, now, nil)

		bidAdjustmentTargetBid := bidCache.GetBidAdjustmentTargetBid(log, cacheKey, 1000, topBid, topBidValue)
		require.NotNil(t, bidAdjustmentTargetBid)
		require.Equal(t, uint256.NewInt(250).Bytes(), bidAdjustmentTargetBid.Value)
	})

	t.Run("1000ms lookback time, BidAdjustmentTargetBid should be nil", func(t *testing.T) {
		bidCache := NewBidMetadataCache(time.Minute)
		now := time.Now().UTC()

		saveTestBidMetadata(bidCache, log, cacheKey, 100, testBlockHash1, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-2*time.Millisecond), nil)
		saveTestBidMetadata(bidCache, log, cacheKey, 200, testBlockHash2, testBuilderPubkeyB, testBuilderExtraDataB, now.Add(-1*time.Millisecond), nil)
		topBid, topBidValue := saveTestBidMetadata(bidCache, log, cacheKey, 300, testBlockHash3, testBuilderPubkeyC, testBuilderExtraDataC, now, nil)

		bidAdjustmentTargetBid := bidCache.GetBidAdjustmentTargetBid(log, cacheKey, 1000, topBid, topBidValue)
		require.Nil(t, bidAdjustmentTargetBid)
	})

	t.Run("1000ms lookback time, winning builder high bids were canceled with higher bid", func(t *testing.T) {
		bidCache := NewBidMetadataCache(time.Minute)
		now := time.Now().UTC()

		saveTestBidMetadata(bidCache, log, cacheKey, 300, testBlockHash1, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-1003*time.Millisecond), nil)
		saveTestBidMetadata(bidCache, log, cacheKey, 400, testBlockHash2, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-3*time.Millisecond), nil)
		topBid, topBidValue := saveTestBidMetadata(bidCache, log, cacheKey, 500, testBlockHash3, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-2*time.Millisecond), nil)
		saveTestBidMetadata(bidCache, log, cacheKey, 200, testBlockHash4, testBuilderPubkeyB, testBuilderExtraDataB, now.Add(-1*time.Millisecond), nil)
		saveTestBidMetadata(bidCache, log, cacheKey, 100, testBlockHash5, testBuilderPubkeyC, testBuilderExtraDataC, now, nil)

		bidAdjustmentTargetBid := bidCache.GetBidAdjustmentTargetBid(log, cacheKey, 1000, topBid, topBidValue)
		require.NotNil(t, bidAdjustmentTargetBid)
		require.Equal(t, uint256.NewInt(300).Bytes(), bidAdjustmentTargetBid.Value)
	})

	t.Run("1000ms lookback time, winning builder high bids were canceled with lower bid", func(t *testing.T) {
		bidCache := NewBidMetadataCache(time.Minute)
		now := time.Now().UTC()

		saveTestBidMetadata(bidCache, log, cacheKey, 300, testBlockHash1, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-1002*time.Millisecond), nil)
		saveTestBidMetadata(bidCache, log, cacheKey, 400, testBlockHash2, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-2*time.Millisecond), nil)
		topBid, topBidValue := saveTestBidMetadata(bidCache, log, cacheKey, 200, testBlockHash3, testBuilderPubkeyA, testBuilderExtraDataA, now.Add(-1*time.Millisecond), nil)
		saveTestBidMetadata(bidCache, log, cacheKey, 100, testBlockHash4, testBuilderPubkeyB, testBuilderExtraDataB, now, nil)

		bidAdjustmentTargetBid := bidCache.GetBidAdjustmentTargetBid(log, cacheKey, 1000, topBid, topBidValue)
		require.NotNil(t, bidAdjustmentTargetBid)
		require.Equal(t, uint256.NewInt(300).Bytes(), bidAdjustmentTargetBid.Value)
	})

	t.Run("1000ms lookback time, no bids", func(t *testing.T) {
		bidCache := NewBidMetadataCache(time.Minute)
		bidAdjustmentTargetBid := bidCache.GetBidAdjustmentTargetBid(log, cacheKey, 1000, nil, big.NewInt(0))
		require.Nil(t, bidAdjustmentTargetBid)
	})
}
