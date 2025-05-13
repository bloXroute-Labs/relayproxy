package relayproxy

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

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

func DecodeAuth(in string) (string, string, error) {
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
	return data[0], data[1], nil
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
		latency = receivedAt.UnixMilli() - boostSendTimeInt
	}
	boostSendTime = headerValue
	return
}
