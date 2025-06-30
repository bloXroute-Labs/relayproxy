package relayproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sort"
	"time"

	"github.com/bloXroute-Labs/relayproxy/fluentstats"
	"github.com/rs/zerolog"
)

const (
	proposerHeaderDeliveredURI = "/relay/v1/data/bidtraces/proposer_header_delivered?slot="
)

type RewardEngine struct {
	logger               zerolog.Logger
	httpClient           *http.Client
	slotStartRecordCh    chan SlotStatsRecord
	relayUrlsWithApiKeys map[string]string
	nodeID               string
	fluentd              fluentstats.Stats
}

type BidTrace struct {
	HeaderRequestID         string `json:"header_request_id"`
	Slot                    string `json:"slot"`
	ParentHash              string `json:"parent_hash"`
	BlockHash               string `json:"block_hash"`
	BuilderPubkey           string `json:"builder_pubkey"`
	ProposerPubkey          string `json:"proposer_pubkey"`
	ProposerFeeRecipient    string `json:"proposer_fee_recipient"`
	Value                   string `json:"value"`
	BlockNumber             string `json:"block_number"`
	ValueEth                string `json:"value_eth"`
	ProposerSendTimestampMs string `json:"proposer_send_timestamp_ms"`
	ExtraData               string `json:"extra_data"`
}

type ElRewardInfo struct {
	Slot                           string                `json:"slot"`
	SlotUID                        string                `json:"slot_uid"`
	BlockNumber                    string                `json:"block_number"`
	Bids                           map[string][]BidTrace `json:"bids"`
	SelectedHeaderStartTimeUnixMs  string                `json:"selected_header_start_time_unix_ms"`
	BlockHash                      string                `json:"block_hash"`
	IsProxyWin                     bool                  `json:"is_proxy_win"`
	IsWinningBidHighest            bool                  `json:"is_winning_bid_highest"`
	ElRewardIncreaseWei            *big.Int              `json:"el_reward_increase_wei"`
	ElRewardIncreaseEth            float64               `json:"el_reward_increase_eth"`
	OnchainBidValue                float64               `json:"onchain_bid_value"`
	SecondHighestBidValue          float64               `json:"second_highest_bid_value"`
	OnchainBidDeliveredRelay       string                `json:"onchain_bid_delivered_relay"`
	SecondHigherBidDeliveredRelay  string                `json:"second_higher_bid_delivered_relay"`
	IsPayloadReceived              bool                  `json:"is_payload_received"`
	ElRewardIncreasePercentage     uint64                `json:"el_reward_increase_percentage"`
	ElRewardIncreasePercentPrecise float64               `json:"el_reward_increase_percent_precise"`
	EqualToProxyBidders            string                `json:"equal_to_proxy_bidders"`
	IsEqualToProxyBid              bool                  `json:"is_equal_to_proxy_bid"`
	FeePerBlock                    float64               `json:"fee_per_block"`
}

func NewElRewardEngine(opts ...RewardEngineOpts) *RewardEngine {
	rewardEngine := &RewardEngine{}
	for _, opt := range opts {
		opt(rewardEngine)
	}
	return rewardEngine
}

func (r *RewardEngine) Start(ctx context.Context) {
	for {
		select {
		case slotStats := <-r.slotStartRecordCh:
			bids := r.collectExternalRelayBids(slotStats.Slot)
			reward := r.calculateElRewardInfo(slotStats, bids)
			r.logger.Info().Msgf("calculated EL reward: %v", reward) //TODO:omit bids while logging to avoid cluttering
		default:
		}
	}
}

func (r *RewardEngine) collectExternalRelayBids(slot uint64) []BidTrace {
	var allBids []BidTrace

	for baseURL, apiKey := range r.relayUrlsWithApiKeys {
		url := fmt.Sprintf("%s%s%d", baseURL, proposerHeaderDeliveredURI, slot)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			r.logger.Error().Err(err).Str("url", baseURL).Msg("failed to create proposer header delivered request")
			continue
		}
		req.Header.Set("X-API-Key", apiKey)
		resp, err := r.httpClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			r.logger.Error().Err(err).Msgf("http request failed or returned non-200 from %s", baseURL)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		var bids []BidTrace
		if err = json.Unmarshal(body, &bids); err != nil {
			r.logger.Error().Err(err).Msg("failed to unmarshal bid trace")
			continue
		}
		allBids = append(allBids, bids...)
	}

	return allBids
}

// TODO: Recovery option, move as a standalone script to calculate based on db and endpoints
func (r *RewardEngine) calculateElRewardInfo(slotStats SlotStatsRecord, allBids []BidTrace) ElRewardInfo {
	elInfo := ElRewardInfo{
		Slot:                          fmt.Sprintf("%d", slotStats.Slot),
		SlotUID:                       slotStats.HeaderSlotUID,
		BlockHash:                     slotStats.PayloadDeliveredBlockHash,
		SelectedHeaderStartTimeUnixMs: slotStats.HeaderStartTimeUnixMs,
		IsPayloadReceived:             slotStats.PayloadSucceeded,
		IsProxyWin:                    slotStats.HeaderDeliveredBlockHash == slotStats.PayloadDeliveredBlockHash,
		Bids:                          make(map[string][]BidTrace),
		ElRewardIncreaseWei:           big.NewInt(0),
	}

	var matchedBids []BidTrace
	for _, bid := range allBids {
		elInfo.Bids[bid.ProposerSendTimestampMs] = append(elInfo.Bids[bid.ProposerSendTimestampMs], bid)
		if bid.ProposerSendTimestampMs == slotStats.HeaderStartTimeUnixMs {
			matchedBids = append(matchedBids, bid)
		}
	}

	if len(matchedBids) < 2 {
		return elInfo
	}

	sort.SliceStable(matchedBids, func(i, j int) bool {
		iVal, _ := new(big.Float).SetString(matchedBids[i].ValueEth)
		jVal, _ := new(big.Float).SetString(matchedBids[j].ValueEth)
		return iVal.Cmp(jVal) < 0
	})

	secondHighest := matchedBids[len(matchedBids)-1]

	winVal, _ := new(big.Float).SetString(slotStats.PayloadBlockValue)
	secondVal, _ := new(big.Float).SetString(secondHighest.ValueEth)
	increase := new(big.Float).Sub(winVal, secondVal)
	percentPrecise := new(big.Float).Quo(increase, winVal)
	percentPrecise.Mul(percentPrecise, big.NewFloat(100))

	// Check equality: if second best bid == winning bid
	isEqual := winVal.Cmp(secondVal) == 0
	elInfo.IsEqualToProxyBid = isEqual
	if isEqual {
		elInfo.IsProxyWin = false
	}

	onchainFloat, _ := winVal.Float64()
	secondFloat, _ := secondVal.Float64()
	incFloat, _ := increase.Float64()
	percentFloat, _ := percentPrecise.Float64()

	elInfo.OnchainBidValue = onchainFloat
	elInfo.SecondHighestBidValue = secondFloat
	elInfo.ElRewardIncreaseEth = incFloat
	elInfo.ElRewardIncreasePercentPrecise = percentFloat
	elInfo.ElRewardIncreasePercentage = uint64(percentFloat + 0.5)

	weiFactor := new(big.Float).SetFloat64(1e18)
	elRewardWei := new(big.Float).Mul(increase, weiFactor)
	elRewardWei.Int(elInfo.ElRewardIncreaseWei)

	//TODO: Perform fee per block calculation only certain accountID
	if elInfo.ElRewardIncreasePercentage <= 1 {
		elInfo.FeePerBlock = 0.0
	} else if elInfo.ElRewardIncreasePercentage <= 5 {
		if elInfo.ElRewardIncreaseEth >= 0.0015 {
			elInfo.FeePerBlock = 0.0015
		} else {
			elInfo.FeePerBlock = 0.0
		}
	} else if elInfo.ElRewardIncreasePercentage <= 9 {
		if elInfo.ElRewardIncreaseEth > 0.003 {
			elInfo.FeePerBlock = 0.003
		} else if elInfo.ElRewardIncreaseEth > 0.0015 {
			elInfo.FeePerBlock = 0.0015
		} else {
			elInfo.FeePerBlock = 0.0
		}
	} else {
		if elInfo.ElRewardIncreaseEth > 0.005 {
			elInfo.FeePerBlock = 0.005
		} else if elInfo.ElRewardIncreaseEth > 0.003 {
			elInfo.FeePerBlock = 0.003
		} else if elInfo.ElRewardIncreaseEth > 0.0015 {
			elInfo.FeePerBlock = 0.0015
		} else {
			elInfo.FeePerBlock = 0.0
		}
	}
	return elInfo
}

func (r *RewardEngine) logRecord(record ElRewardInfo) {
	r.logger.Info().
		Str("slotKey", record.Slot).
		Str("blockHah", record.BlockHash).
		Float64("blockHah", record.ElRewardIncreaseEth).
		Bool("isProxyWin", record.IsProxyWin).
		Msg("emit el reward event")
	r.fluentd.LogToFluentD(fluentstats.Record{
		Type: TypeRelayProxySlotStats,
		Data: record,
	}, time.Now().UTC(), r.nodeID, StatsRelayProxyElReward)
}
