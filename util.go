package relayproxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	eth2Api "github.com/attestantio/go-eth2-client/api"
	eth2ApiV1Capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	eth2ApiV1Deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/ethereum/go-ethereum/params"
)

func GetIPXForwardedFor(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		if strings.Contains(forwarded, ",") { // return first entry of list of IPs
			return strings.Split(forwarded, ",")[0]
		}
		return forwarded
	}

	// Remove the port number if present
	// SplitHostPort splits a network address of the form "host:port",
	// "host%zone:port", "[host]:port" or "[host%zone]:port" into host or
	// host%zone and port.
	//
	// A literal IPv6 address in hostport must be enclosed in square
	// brackets, as in "[::1]:80", "[::1%lo0]:80".
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func ParseURL(r *http.Request) (*url.URL, error) {
	u, err := url.QueryUnescape(r.URL.String())
	if err != nil {
		return r.URL, fmt.Errorf("failed to decode url: %v, reason %v", r.URL.String(), err)
	}
	urlParsed, err := url.Parse(u)
	if err != nil {
		return r.URL, fmt.Errorf("failed to parse decoded url: %v, reason %v", r.URL.String(), err)
	}
	return urlParsed, nil
}

func GetAuth(r *http.Request, parsedURL *url.URL) string {
	//authHeader := r.Header.Get("Authorization")
	//if authHeader != "" {
	//	return authHeader
	//}
	auth := r.Header.Get("auth")
	if auth != "" {
		return auth
	}
	// fallback to query param
	return parsedURL.Query().Get("auth")
}

func GetOrgID(r *http.Request, parsedURL *url.URL) string {
	id := r.Header.Get("id")
	if id != "" {
		return id
	}

	// fallback to query param
	return parsedURL.Query().Get("id")
}

func DecodeAuth(in string) (AccountID, string, error) {
	if in == "" {
		return "", "", fmt.Errorf("empty auth header")
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return "", "", fmt.Errorf("invalid auth header")
	}
	data := strings.Split(string(decodedBytes), ":")
	if len(data) != 2 {
		return "", "", fmt.Errorf("invalid auth header")
	}
	return AccountID(data[0]), data[1], nil
}

// GetSleepParams returns the sleep time and max sleep time from the request
func GetSleepParams(parsedURL *url.URL, delayInMs, maxDelayInMs int64) (int64, int64, string) {

	sleepTime, sleepMax := delayInMs, maxDelayInMs

	sleep := parsedURL.Query().Get("sleep")
	if sleep != "" {
		sleepTime = AToI(sleep)
	}

	maxSleep := parsedURL.Query().Get("max_sleep")
	if maxSleep != "" {
		sleepMax = AToI(maxSleep)
	}

	return sleepTime, sleepMax, parsedURL.Query().Get("account_id")
}

// AToI converts a string to an int64
func AToI(value string) int64 {
	i, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return i
}

// GetSlotStartTime returns the time of the start of the slot
func GetSlotStartTime(beaconGenesisTime, slot, secondsPerSlot int64) time.Time {
	return time.Unix(beaconGenesisTime+(int64(slot)*secondsPerSlot), 0).UTC()
}
func CalculateCurrentSlot(beaconGenesisTime, secondsPerSlot int64) int64 {
	return ((time.Now().UTC().Unix() - beaconGenesisTime) / secondsPerSlot) + 1
}

type VersionedSignedBlindedBeaconBlock struct {
	eth2Api.VersionedSignedBlindedBeaconBlock
}

func (r *VersionedSignedBlindedBeaconBlock) MarshalJSON() ([]byte, error) {
	switch r.Version { //nolint:exhaustive
	case spec.DataVersionCapella:
		return json.Marshal(r.Capella)
	case spec.DataVersionDeneb:
		return json.Marshal(r.Deneb)
	default:
		return nil, fmt.Errorf("%s is not supported", r.Version)
	}
}

func (r *VersionedSignedBlindedBeaconBlock) UnmarshalJSON(input []byte) error {
	var err error

	denebBlock := new(eth2ApiV1Deneb.SignedBlindedBeaconBlock)
	if err = json.Unmarshal(input, denebBlock); err == nil {
		r.Version = spec.DataVersionDeneb
		r.Deneb = denebBlock
		return nil
	}

	capellaBlock := new(eth2ApiV1Capella.SignedBlindedBeaconBlock)
	if err = json.Unmarshal(input, capellaBlock); err == nil {
		r.Version = spec.DataVersionCapella
		r.Capella = capellaBlock
		return nil
	}
	return fmt.Errorf("failed to unmarshal SignedBlindedBeaconBlock : %v", err)
}

func weiToEther(wei *big.Int) string {
	f := new(big.Float)
	f.SetPrec(236) //  IEEE 754 octuple-precision binary floating-point format: binary256
	f.SetMode(big.ToNearestEven)
	fWei := new(big.Float)
	fWei.SetPrec(236) //  IEEE 754 octuple-precision binary floating-point format: binary256
	fWei.SetMode(big.ToNearestEven)
	return fmt.Sprintf("%.18f", f.Quo(fWei.SetInt(wei), big.NewFloat(params.Ether)))
}

func GetHost(url string) string {
	if strings.Contains(url, ":") {
		parts := strings.SplitN(url, ":", 2) // Use SplitN to ensure only the first colon splits the string
		return parts[0]
	}
	return url
}

func fastParseUint(s string) (uint64, error) {
	var n uint64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("invalid uint: %s", s)
		}
		n = n*10 + uint64(s[i]-'0') // Avoids allocations
	}
	return n, nil
}

func getBoostSendTimeAndLatency(receivedAt time.Time, mevBoostSendTimeUnixMS, commitBoostSendTimeUnixMS string) (boostSendTime string, latency int64) {
	var headerValue string
	if mevBoostSendTimeUnixMS != "" {
		headerValue = mevBoostSendTimeUnixMS
	}
	if commitBoostSendTimeUnixMS != "" {
		headerValue = commitBoostSendTimeUnixMS
	}

	boostSendTimeInt, err := strconv.ParseInt(headerValue, 10, 64)
	if err == nil {
		boostSendTime = time.UnixMilli(boostSendTimeInt).UTC().String()
		latency = receivedAt.UnixMilli() - boostSendTimeInt
	}
	return
}
