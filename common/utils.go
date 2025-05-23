package common

import (
	"encoding/hex"
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/rs/zerolog"
	goacceptheaders "github.com/timewasted/go-accept-headers"
)

type UserAgentType string

const (
	MevBoostUserAgent    = UserAgentType("mev-boost")
	VouchUserAgent       = UserAgentType("vouch")
	KilnUserAgent        = UserAgentType("kiln")
	CommitBoostUserAgent = UserAgentType("commit-boost")
	UnknownUserAgent     = UserAgentType("unknown")

	MediaTypeJSON             = "application/json"
	MediaTypeOctetStream      = "application/octet-stream"
	HeaderAccept              = "Accept"
	HeaderContentType         = "Content-Type"
	HeaderBlxrContentType     = "Blxr-Extra-Content-Type"
	HeaderEthConsensusVersion = "Eth-Consensus-Version"
	HeaderUserAgent           = "User-Agent"
)

// DecodeExtraData returns a decoded string from block ExtraData
func DecodeExtraData(extraData []byte) string {
	extraDataString := hexutil.Bytes(extraData).String()
	decodedExtraData, err := hex.DecodeString(strings.TrimPrefix(extraDataString, "0x"))
	if err != nil {
		return ""
	}
	return string(decodedExtraData)
}

func GetUserAgentType(userAgent string) UserAgentType {
	uaLower := strings.ToLower(userAgent)
	if strings.Contains(uaLower, "mev-boost") {
		return MevBoostUserAgent
	} else if strings.Contains(uaLower, "vouch") {
		return VouchUserAgent
	} else if strings.Contains(uaLower, "kiln") {
		return KilnUserAgent
	} else if strings.Contains(uaLower, "commit-boost") {
		return CommitBoostUserAgent
	}
	return UnknownUserAgent
}

// All requests by default send and receive JSON, and as such should have either or both of the "Content-Type: application/json"
// and "Accept: application/json" headers.  In addition, some requests can send and receive data in the SSZ format.  The header
// "Content-Type: application/octet-stream" should be set in requests that contain SSZ data; a preference to receive SSZ data in
// response can be indicated by setting the "Accept: application/octet-stream;q=1.0,application/json;q=0.9" header.  Note that
// only a subset of requests can respond with data in SSZ format; these are noted in each individual request.

// When handling requests, the server should return a 415 status code if the "Content-Type" header in the request specifies a format
// that is not supported.  Similarly, it should return a 406 status code if it cannot produce a response in the format accepted by
// the client as specified in the "Accept" header; if no "Accept" header is provided then it is assumed to be "application/json".
// In any case, the server should indicate the format of the response by setting the corresponding "Content-Type" header.

func ParseBuilderContentType(req *http.Request) (bool, bool) {
	var (
		sszRequest  bool
		sszResponse bool
	)

	if mediaType, _, _ := mime.ParseMediaType(req.Header.Get(HeaderContentType)); mediaType == MediaTypeOctetStream ||
		req.Header.Get(HeaderContentType) == MediaTypeOctetStream {
		sszRequest = true
	}

	rawAcceptContentTypes := req.Header.Get(HeaderAccept)
	parsedAcceptContentTypes := goacceptheaders.Parse(rawAcceptContentTypes)
	preferredContentType, _ := parsedAcceptContentTypes.Negotiate(MediaTypeJSON, MediaTypeOctetStream)
	if preferredContentType == MediaTypeOctetStream || rawAcceptContentTypes == MediaTypeOctetStream {
		sszResponse = true
	}
	return sszRequest, sszResponse
}

func SlotStartTime(beaconGenesisTime, secondsPerSlot, slot int64) time.Time {
	return time.Unix(beaconGenesisTime+(slot*secondsPerSlot), 0).UTC()
}

func TimeOfFork(forkEpoch int64, genesisTime, secondsPerSlot int64) time.Time {
	if forkEpoch < 0 {
		return time.Time{}
	}

	epochSlot := forkEpoch * int64(32)
	return SlotStartTime(genesisTime, secondsPerSlot, epochSlot)
}

func CheckElectraEpochFork(curTime time.Time, beaconGenesisTime, secondsPerSlot, slotsPerEpoch, forkElectraEpoch int64, log zerolog.Logger) bool {
	if IsElectra {
		log.Info().Msg("isElectra")
		return true
	}
	electraTime := TimeOfFork(forkElectraEpoch, beaconGenesisTime, secondsPerSlot)

	curTimeUnix := curTime.Unix()
	subTime := curTimeUnix - beaconGenesisTime
	curSlot := subTime / secondsPerSlot
	curSlot++
	epoch := curSlot / slotsPerEpoch

	if epoch >= int64(forkElectraEpoch) {
		IsElectra = true
	}
	log.Info().
		Time("electraTime", electraTime.UTC()).
		Int64("electraSlot", forkElectraEpoch*32).
		Int64("proposalSlot", int64(curSlot)).
		Bool("isElectra", IsElectra).
		Dur("electraCountdownMin", time.Until(electraTime)/1000/60).
		Msg("electra fork time")

	return IsElectra
}

func SafeSplit(s string, sep string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(s, sep)
}

func SafeSplitSemicolonSeparatedCSV(s string) ([]string, error) {
	if s == "" {
		return []string{}, nil
	}

	csvStrs := strings.Split(s, ",")
	output := make([]string, 0)
	for _, csvStrs := range csvStrs {
		semicolonSplit := strings.Split(csvStrs, ";")
		if len(semicolonSplit) == 0 {
			return nil, fmt.Errorf("invalid semicolon separated CSV string %s", s)
		} else if len(semicolonSplit) == 1 {
			output = append(output, semicolonSplit[0])
		} else if len(semicolonSplit) == 2 {
			count := semicolonSplit[1]
			if count == "" {
				return nil, fmt.Errorf("invalid semicolon separated CSV string %s", s)
			}
			countInt, err := strconv.Atoi(count)
			if err != nil {
				return nil, fmt.Errorf("invalid semicolon separated CSV string %s", s)
			}

			str := semicolonSplit[0]
			for i := 0; i < countInt; i++ {
				output = append(output, str)
			}
		} else {
			return nil, fmt.Errorf("invalid semicolon separated CSV string %s", s)
		}
	}
	return output, nil
}
