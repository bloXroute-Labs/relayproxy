package relayproxy

import (
	"math/big"
	"net/http"
	"testing"
)

func TestGetIPXForwardedFor(t *testing.T) {
	tests := []struct {
		name           string
		requestHeaders map[string]string
		remoteAddr     string
		expectedIP     string
	}{
		{
			name: "X-Forwarded-For single IP",
			requestHeaders: map[string]string{
				"X-Forwarded-For": "192.168.1.1",
			},
			remoteAddr: "10.0.0.1:8080",
			expectedIP: "192.168.1.1",
		},
		{
			name: "X-Forwarded-For multiple IPs",
			requestHeaders: map[string]string{
				"X-Forwarded-For": "192.168.1.1, 10.0.0.1",
			},
			remoteAddr: "10.0.0.1:8080",
			expectedIP: "192.168.1.1",
		},
		{
			name:           "No X-Forwarded-For",
			requestHeaders: map[string]string{},
			remoteAddr:     "10.0.0.1:8080",
			expectedIP:     "10.0.0.1",
		},
		{
			name:           "RemoteAddr without port",
			requestHeaders: map[string]string{},
			remoteAddr:     "10.0.0.1",
			expectedIP:     "10.0.0.1",
		},
		{
			name: "X-Forwarded-For IPv6 single IP",
			requestHeaders: map[string]string{
				"X-Forwarded-For": "2002:db8::",
			},
			remoteAddr: "[2001:db8::]:8080",
			expectedIP: "2002:db8::",
		},
		{
			name: "X-Forwarded-For IPv6 multiple IPs",
			requestHeaders: map[string]string{
				"X-Forwarded-For": "2002:db8::, 2003:db8::",
			},
			remoteAddr: "[2001:db8::]:8080",
			expectedIP: "2002:db8::",
		},
		{
			name:           "No X-Forwarded-For IPv6",
			requestHeaders: map[string]string{},
			remoteAddr:     "[2001:db8:3333:4444:5555:6666:7777:8888::]:8080",
			expectedIP:     "2001:db8:3333:4444:5555:6666:7777:8888::",
		},
		{
			name:           "RemoteAddr IPv6 without port",
			requestHeaders: map[string]string{},
			remoteAddr:     "2001:db8::1234:5678",
			expectedIP:     "2001:db8::1234:5678",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com", nil)
			for key, value := range test.requestHeaders {
				req.Header.Set(key, value)
			}
			req.RemoteAddr = test.remoteAddr
			result := GetIPXForwardedFor(req)
			if result != test.expectedIP {
				t.Errorf("Expected IP %s, got %s", test.expectedIP, result)
			}
		})
	}
}
func Test_weiToEther(t *testing.T) {

	tests := []struct {
		wei *big.Int
		eth string
	}{
		{big.NewInt(1), "0.000000000000000001"}, // 1 wei
		{big.NewInt(1000000000000000000), "1.000000000000000000"},
		{big.NewInt(106981467163162217), "0.106981467163162217"},
		{big.NewInt(360909866365697452), "0.360909866365697452"},
		{big.NewInt(46983840577085104), "0.046983840577085104"},
	}
	for _, tt := range tests {
		//result := weiToEtherString(weiToEther(tt.wei))
		result := weiToEther(tt.wei)
		if result != tt.eth {
			t.Errorf("For wei %v, expected %s, got %s", tt.wei, tt.eth, result)
		}
	}
}
