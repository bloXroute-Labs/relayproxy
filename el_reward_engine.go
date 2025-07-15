package relayproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
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

type DataHeader struct {
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
	RelayURL                string `json:"-"`
}

type ElRewardInfo struct {
	Slot                            string                  `json:"slot"`
	SlotUID                         string                  `json:"slot_uid"`
	BlockNumber                     string                  `json:"block_number"`
	Bids                            map[string][]DataHeader `json:"bids"`
	SelectedProposerStartTimeUnixMs string                  `json:"selected_proposer_start_time_unix_ms"`
	BlockHash                       string                  `json:"block_hash"`
	IsProxyWin                      bool                    `json:"is_proxy_win"`
	IsWinningBidHighest             bool                    `json:"is_winning_bid_highest"`
	ElRewardIncreaseWei             *big.Int                `json:"el_reward_increase_wei"`
	ElRewardIncreaseEth             float64                 `json:"el_reward_increase_eth"`
	OnchainBidValue                 float64                 `json:"onchain_bid_value"`
	SecondHighestBidValue           float64                 `json:"second_highest_bid_value"`
	OnchainBidDeliveredRelay        []string                `json:"onchain_bid_delivered_relay"`
	SecondHighestBidDeliveredRelay  []string                `json:"second_highest_bid_delivered_relay"`
	IsPayloadReceived               bool                    `json:"is_payload_received"`
	ElRewardIncreasePercentage      uint64                  `json:"el_reward_increase_percentage"`
	ElRewardIncreasePercentPrecise  float64                 `json:"el_reward_increase_percent_precise"`
	EqualToProxyBidders             string                  `json:"equal_to_proxy_bidders"`
	IsEqualToProxyBid               bool                    `json:"is_equal_to_proxy_bid"`
	FeePerBlock                     float64                 `json:"fee_per_block"`
	Error                           string                  `json:"error"`
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
			r.logRecord(reward)
		case <-ctx.Done():
			return
		}
	}
}
func (r *RewardEngine) collectExternalRelayBids(slot uint64) map[string][]DataHeader {
	relayBids := make(map[string][]DataHeader)

	for baseURL, apiKey := range r.relayUrlsWithApiKeys {
		// Validate baseURL
		parsedURL, err := url.Parse(baseURL)
		if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
			r.logger.Error().Uint64("slot", slot).Str("relayURL", baseURL).Msg("invalid relay URL, skipping")
			continue
		}

		fullURL := fmt.Sprintf("%s%s%d", baseURL, proposerHeaderDeliveredURI, slot)
		req, err := http.NewRequest(http.MethodGet, fullURL, nil)
		if err != nil {
			r.logger.Error().Err(err).Uint64("slot", slot).Str("url", fullURL).Msg("failed to create proposer header delivered request")
			continue
		}
		req.Header.Set("X-API-Key", apiKey)
		resp, err := r.httpClient.Do(req)
		if err != nil {
			r.logger.Error().Err(err).Uint64("slot", slot).Str("url", fullURL).Msgf("http request failed to %s", fullURL)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			r.logger.Error().
				Uint64("slot", slot).
				Str("url", fullURL).
				Int("statusCode", resp.StatusCode).
				Str("body", string(body)).
				Msg("non-200 response from relay")
			resp.Body.Close()
			continue
		}

		body, err := io.ReadAll(resp.Body)
		errClose := resp.Body.Close()
		if err != nil {
			r.logger.Error().Err(err).Uint64("slot", slot).Str("url", fullURL).Msg("failed to read body from relay")
			continue
		}
		if errClose != nil {
			r.logger.Warn().Err(errClose).Str("url", fullURL).Msg("error closing response body")
		}

		var bids []DataHeader
		if err = json.Unmarshal(body, &bids); err != nil {
			r.logger.Error().Err(err).Uint64("slot", slot).Str("url", fullURL).Msg("failed to unmarshal data header")
			continue
		}
		if len(bids) == 0 {
			r.logger.Warn().Uint64("slot", slot).Str("url", fullURL).Msg("no bids received from relay")
			continue
		}
		for i := range bids {
			bids[i].RelayURL = baseURL
		}

		relayBids[baseURL] = bids
	}

	return relayBids
}

// TODO: Recovery option, move as a standalone script to calculate based on db and endpoints
func (r *RewardEngine) calculateElRewardInfo(slotStats SlotStatsRecord, groupedBids map[string][]DataHeader) ElRewardInfo {
	elInfo := ElRewardInfo{
		Slot:                            fmt.Sprintf("%d", slotStats.Slot),
		SlotUID:                         slotStats.HeaderSlotUID,
		BlockHash:                       slotStats.PayloadDeliveredBlockHash,
		SelectedProposerStartTimeUnixMs: slotStats.HeaderStartTimeUnixMs,
		IsPayloadReceived:               slotStats.PayloadSucceeded,
		IsProxyWin:                      slotStats.HeaderDeliveredBlockHash == slotStats.PayloadDeliveredBlockHash,
		Bids:                            make(map[string][]DataHeader),
		ElRewardIncreaseWei:             big.NewInt(0),
		OnchainBidDeliveredRelay:        make([]string, 0, 10),
		SecondHighestBidDeliveredRelay:  make([]string, 0, 10),
	}

	var matchedBids []DataHeader
	var errBuf []string
	for relayURL, bids := range groupedBids {
		elInfo.Bids[relayURL] = bids
		for _, bid := range bids {
			if bid.BlockHash == slotStats.PayloadDeliveredBlockHash {
				// this could be empty if max profit or regulated r-proxy delivered the bid
				elInfo.OnchainBidDeliveredRelay = append(elInfo.OnchainBidDeliveredRelay, bid.RelayURL)
			}
			if bid.ProposerSendTimestampMs == slotStats.HeaderStartTimeUnixMs {
				matchedBids = append(matchedBids, bid)
			}
		}
	}

	// If relay proxy lost the block, no need calculate el reward increase
	if !elInfo.IsProxyWin {
		winVal := new(big.Float)
		if _, ok := winVal.SetString(slotStats.PayloadBlockValue); !ok {
			errBuf = append(errBuf, "invalid payloadBlockValue")
			r.logger.Warn().
				Uint64("slot", slotStats.Slot).
				Str("blockValue", slotStats.PayloadBlockValue).
				Msg("invalid payloadBlockValue")
			return elInfo
		}
		onchainFloat, _ := winVal.Float64()
		elInfo.OnchainBidValue = onchainFloat
		elInfo.Error = fmt.Sprint(errBuf)
		return elInfo
	}

	if len(matchedBids) < 2 {
		return elInfo
	}

	sort.SliceStable(matchedBids, func(i, j int) bool {
		iVal, iOk := new(big.Float).SetString(matchedBids[i].ValueEth)
		if !iOk {
			errBuf = append(errBuf, fmt.Sprintf("invalid iVal.ValueEth: %s", matchedBids[i].ValueEth))
		}
		jVal, jOk := new(big.Float).SetString(matchedBids[j].ValueEth)
		if !jOk {
			errBuf = append(errBuf, fmt.Sprintf("invalid jVal.ValueEth: %s", matchedBids[j].ValueEth))
		}
		return iVal.Cmp(jVal) < 0
	})

	secondHighest := matchedBids[len(matchedBids)-1]

	winVal := new(big.Float)
	if _, ok := winVal.SetString(slotStats.PayloadBlockValue); !ok {
		errBuf = append(errBuf, "invalid payloadBlockValue")
		r.logger.Warn().
			Uint64("slot", slotStats.Slot).
			Str("payloadBlockValue", slotStats.PayloadBlockValue).
			Msg("invalid payloadBlockValue")
		return elInfo
	}

	secondVal := new(big.Float)
	if _, ok := secondVal.SetString(secondHighest.ValueEth); !ok {
		errBuf = append(errBuf, fmt.Sprintf("invalid secondHighest.ValueEth: %s", secondHighest.ValueEth))
		r.logger.Warn().
			Uint64("slot", slotStats.Slot).
			Str("secondHighestValueEth", secondHighest.ValueEth).
			Msg("invalid secondHighestValueEth")
		return elInfo
	}

	increase := new(big.Float).Sub(winVal, secondVal)
	percentPrecise := new(big.Float).Quo(increase, winVal)
	percentPrecise.Mul(percentPrecise, big.NewFloat(100))

	isEqual := winVal.Cmp(secondVal) == 0
	elInfo.IsEqualToProxyBid = isEqual
	if isEqual {
		elInfo.IsProxyWin = false
		elInfo.EqualToProxyBidders = secondHighest.RelayURL
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

	elInfo.SecondHighestBidDeliveredRelay = append(elInfo.SecondHighestBidDeliveredRelay, secondHighest.RelayURL)

	weiFactor := new(big.Float).SetFloat64(1e18)
	elRewardWei := new(big.Float).Mul(increase, weiFactor)
	elRewardWei.Int(elInfo.ElRewardIncreaseWei)

	switch {
	case elInfo.ElRewardIncreasePercentage <= 1:
		elInfo.FeePerBlock = 0.0
	case elInfo.ElRewardIncreasePercentage <= 5:
		if elInfo.ElRewardIncreaseEth >= 0.0015 {
			elInfo.FeePerBlock = 0.0015
		}
	case elInfo.ElRewardIncreasePercentage <= 9:
		switch {
		case elInfo.ElRewardIncreaseEth > 0.003:
			elInfo.FeePerBlock = 0.003
		case elInfo.ElRewardIncreaseEth > 0.0015:
			elInfo.FeePerBlock = 0.0015
		default:
			elInfo.FeePerBlock = 0.0
		}
	default:
		switch {
		case elInfo.ElRewardIncreaseEth > 0.005:
			elInfo.FeePerBlock = 0.005
		case elInfo.ElRewardIncreaseEth > 0.003:
			elInfo.FeePerBlock = 0.003
		case elInfo.ElRewardIncreaseEth > 0.0015:
			elInfo.FeePerBlock = 0.0015
		default:
			elInfo.FeePerBlock = 0.0
		}
	}

	elInfo.Error = fmt.Sprint(errBuf)
	return elInfo
}

func (r *RewardEngine) logRecord(record ElRewardInfo) {
	r.logger.Info().
		Str("slotKey", record.Slot).
		Str("blockHash", record.BlockHash).
		Float64("elRewardIncreaseEth", record.ElRewardIncreaseEth).
		Bool("isProxyWin", record.IsProxyWin).
		Msg("emit el reward event")
	r.fluentd.LogToFluentD(fluentstats.Record{
		Type: TypeRelayProxyElReward,
		Data: record,
	}, time.Now().UTC(), r.nodeID, StatsRelayProxyElReward)
}
