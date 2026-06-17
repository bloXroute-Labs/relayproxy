package common

import (
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/bloXroute-Labs/relay-grpc/stat"
)

func NewReverseProxies(endpoints []string) ([]*httputil.ReverseProxy, error) {
	proxies := make([]*httputil.ReverseProxy, len(endpoints))
	for i, endpoint := range endpoints {
		target, err := url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to parse relay endpoint %s: %w", endpoint, err)
		}

		proxies[i] = &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = target.Scheme
				req.URL.Host = target.Host
				req.Host = target.Host
			},
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: 15 * time.Second,
				IdleConnTimeout:       30 * time.Second,
				MaxIdleConnsPerHost:   20,
			},
			FlushInterval: -1, // stream immediately, never buffer response body
		}
	}

	return proxies, nil
}

func ProxyToMEVRelay(
	w http.ResponseWriter,
	req *http.Request,
	proxies []*httputil.ReverseProxy,
	path string,
	performanceStats *stat.PerformanceStats,
) {
	start := time.Now().UTC()
	success := false
	defer func() {
		if performanceStats != nil {
			performanceStats.SetEndpointStats(
				path,
				uint64(time.Since(start).Microseconds()),
				success,
				100,
			)
		}
	}()

	if len(proxies) == 0 {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	proxy := proxies[rand.Intn(len(proxies))]
	proxy.ServeHTTP(w, req)
	success = true
}
