package common

import (
	"math/big"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog"
)

func GetBidAdjustmentTargetBid(
	log *zerolog.Logger,
	cacheKey string,
	allBidsLock *sync.RWMutex,
	allBidsMetadataForProxySlot *cache.Cache,
	bidAdjustmentLookbackMs int64,
	topBid *Bid,
) *BidMetadata {
	if topBid == nil {
		log.Warn().Msg("Failed to get bid adjustment target bid, topBid is nil")
	}

	start := time.Now().UTC()

	allBidsLock.RLock()
	defer allBidsLock.RUnlock()

	entry, allBidsFound := allBidsMetadataForProxySlot.Get(cacheKey)
	if !allBidsFound {
		log.Warn().Str("cacheKey", cacheKey).Msg("No bids found for cache key while getting bid adjustment target bid")
		return nil
	}

	allBidsForSlot, ok := entry.([]*BidMetadata)
	if !ok {
		log.Warn().Str("cacheKey", cacheKey).Msg("Failed to cast 'allBidsForSlot' slice while getting bid adjustment target bid")
		return nil
	}

	now := time.Now().UTC()
	lookbackTime := time.Duration(bidAdjustmentLookbackMs) * time.Millisecond
	maxBidAdjustmentTargetTimestamp := now.Add(-lookbackTime)

	// Get best bid in time range by for each builder pubkey
	bestBuilderBidByPubkey := make(map[string]*BidMetadata)
	for _, bid := range allBidsForSlot {
		// Skip bids after max target timestamp
		// TODO: is "ReceivedAt" ok to use here?
		if bid.ReceivedAt.After(maxBidAdjustmentTargetTimestamp) {
			continue
		}

		existingBid, found := bestBuilderBidByPubkey[bid.BuilderPubkey]

		// If there is no bid in the map for this pubkey, add the bid and continue
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
		Str("now", now.Format(time.RFC3339Nano)).
		Str("maxBidAdjustmentTargetTimestamp", maxBidAdjustmentTargetTimestamp.Format(time.RFC3339Nano)).
		Str("bidTimestamp", bidAdjustmentTargetBidTimestamp.Format(time.RFC3339Nano)).
		Str("blockHash", bidAdjustmentTargetBidBlockHash).
		Str("value", bidAdjustmentTargetBidValue.String()).
		Str("builderPubkey", bidAdjustmentTargetBidBuilderPubkey).
		Str("builderExtraData", bidAdjustmentTargetBidBuilderExtraData).
		Bool("found", bidAdjustmentTargetBid != nil).
		Msg("Found bid adjustment target bid")

	return bidAdjustmentTargetBid
}
