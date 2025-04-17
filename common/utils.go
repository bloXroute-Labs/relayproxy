package common

import (
	"encoding/hex"
	"mime"
	"net/http"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
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
