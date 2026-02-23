package common

import (
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog"
)

type BidMetadataCache struct {
	lock sync.RWMutex
	bids *cache.Cache
}

func NewBidMetadataCache(cleanupInterval time.Duration) *BidMetadataCache {
	return &BidMetadataCache{
		lock: sync.RWMutex{},
		bids: cache.New(cleanupInterval, cleanupInterval),
	}
}

func (b *BidMetadataCache) GetBidAdjustmentTargetBid(
	log *zerolog.Logger,
	cacheKey string,
	bidAdjustmentLookbackMs int64,
	topBid *Bid,
	topBidValue *big.Int,
) *BidMetadata {
	if topBid == nil {
		log.Warn().Msg("Failed to get bid adjustment target bid, topBid is nil")
		return nil
	}

	start := time.Now().UTC()

	b.lock.RLock()
	defer b.lock.RUnlock()

	entry, allBidsFound := b.bids.Get(cacheKey)
	if !allBidsFound {
		log.Warn().Str("cacheKey", cacheKey).Msg("No bids found for cache key while getting bid adjustment target bid")
		return nil
	}

	allBidsForSlot, ok := entry.([]*BidMetadata)
	if !ok {
		log.Warn().Str("cacheKey", cacheKey).Msg("Failed to cast 'allBidsForSlot' slice while getting bid adjustment target bid")
		return nil
	}

	bidRetrievalTime := time.Now().UTC()
	lookbackTime := time.Duration(bidAdjustmentLookbackMs) * time.Millisecond
	maxBidAdjustmentTargetTimestamp := bidRetrievalTime.Add(-lookbackTime)

	// Get best bid in time range by for each builder pubkey
	topBidBlockHash := strings.ToLower(topBid.BlockHash)
	bestBuilderBidByPubkey := make(map[string]*BidMetadata)
	for _, bid := range allBidsForSlot {
		isTopBid := topBidBlockHash == strings.ToLower(bid.BlockHash)

		// Skip current top bid, or any bids received after max target timestamp
		if isTopBid || bid.ReceivedAt.After(maxBidAdjustmentTargetTimestamp) {
			continue
		}

		// If there is no bid in the map for this pubkey, add the bid and continue
		existingBid, found := bestBuilderBidByPubkey[bid.BuilderPubkey]
		if !found {
			bestBuilderBidByPubkey[bid.BuilderPubkey] = bid
			continue
		}

		// Otherwise compare to bid sequence numbers
		if bid.BlockSequenceNumber != nil &&
			existingBid.BlockSequenceNumber != nil &&
			*bid.BlockSequenceNumber > *existingBid.BlockSequenceNumber {
			bestBuilderBidByPubkey[bid.BuilderPubkey] = bid
			continue
		}

		// Then compare bid receive times if necessary
		if bid.ReceivedAt.After(existingBid.ReceivedAt) {
			bestBuilderBidByPubkey[bid.BuilderPubkey] = bid
		}
	}

	// Get the overall top lookback bid from top builder bids
	var bidAdjustmentTargetBid *BidMetadata
	bidAdjustmentTargetBidValue := big.NewInt(0)

	for _, bid := range bestBuilderBidByPubkey {
		bidValue := new(big.Int).SetBytes(bid.Value)
		if bidValue.Cmp(bidAdjustmentTargetBidValue) > 0 {
			bidAdjustmentTargetBid = bid
			bidAdjustmentTargetBidValue = bidValue
		}
	}

	// Get info for log if non-nil
	bidAdjustmentTargetBidBlockHash := ""
	bidAdjustmentTargetBidBuilderPubkey := ""
	bidAdjustmentTargetBidBuilderExtraData := ""
	var bidAdjustmentTargetBidTimestamp time.Time

	if bidAdjustmentTargetBid != nil {
		bidAdjustmentTargetBidBlockHash = bidAdjustmentTargetBid.BlockHash
		bidAdjustmentTargetBidBuilderPubkey = bidAdjustmentTargetBid.BuilderPubkey
		bidAdjustmentTargetBidBuilderExtraData = bidAdjustmentTargetBid.BuilderExtraData
		bidAdjustmentTargetBidTimestamp = bidAdjustmentTargetBid.ReceivedAt
	}

	log.Info().
		Int64("durationMs", time.Since(start).Milliseconds()).
		Int64("lookBackMs", bidAdjustmentLookbackMs).
		Str("bidRetrievalTime", bidRetrievalTime.Format(time.RFC3339Nano)).
		Str("maxBidAdjustmentTargetTimestamp", maxBidAdjustmentTargetTimestamp.Format(time.RFC3339Nano)).
		Str("topBidTimestamp", topBid.ReceivedAt.Format(time.RFC3339Nano)).
		Str("topBidBlockHash", topBid.BlockHash).
		Str("topBidValue", WeiToEth(topBidValue.String())).
		Str("topBidBuilderPubkey", topBid.BuilderPubkey).
		Str("topBidBuilderExtraData", topBid.BuilderExtraData).
		Str("bidAdjustmentTargetBidTimestamp", bidAdjustmentTargetBidTimestamp.Format(time.RFC3339Nano)).
		Str("bidAdjustmentTargetBidBlockHash", bidAdjustmentTargetBidBlockHash).
		Str("bidAdjustmentTargetBidValue", WeiToEth(bidAdjustmentTargetBidValue.String())).
		Str("bidAdjustmentTargetBidBuilderPubkey", bidAdjustmentTargetBidBuilderPubkey).
		Str("bidAdjustmentTargetBidBuilderExtraData", bidAdjustmentTargetBidBuilderExtraData).
		Bool("found", bidAdjustmentTargetBid != nil).
		Msg("Returning bid adjustment target bid")

	return bidAdjustmentTargetBid
}

func (b *BidMetadataCache) SetBidMetadataForProxySlot(log *zerolog.Logger, cacheKey string, bid *Bid) {
	b.lock.Lock()
	defer b.lock.Unlock()

	var allBidsForSlot []*BidMetadata

	// If the cache key does not exist, create a new slice and store it in the cache
	if entry, bidsFound := b.bids.Get(cacheKey); !bidsFound {
		allBidsForSlot = make([]*BidMetadata, 0, 1000)
	} else {
		// Otherwise use the existing slice
		var ok bool
		allBidsForSlot, ok = entry.([]*BidMetadata)
		if !ok {
			log.Warn().Str("cacheKey", cacheKey).Msg("Failed to cast allBidsForSlot slice in 'SetBidMetadataForProxySlot'")
			return
		}
	}

	allBidsForSlot = append(allBidsForSlot, NewBidMetadata(bid))

	b.bids.Set(cacheKey, allBidsForSlot, cache.DefaultExpiration)
}
