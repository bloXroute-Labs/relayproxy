package httpclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

type SSZ interface {
	SSZMarshaler
	SSZUnmarshaler
}

type SSZMarshaler interface {
	MarshalSSZ() ([]byte, error)
}

type SSZUnmarshaler interface {
	UnmarshalSSZ(buf []byte) error
}

var ErrHTTPErrorResponse = errors.New("got an HTTP error response")

func Fetch(method string, url string, payload any, dst any, headers *http.Header) (code int, duration int64, err error) {
	var req *http.Request
	if payload == nil {
		req, err = http.NewRequest(method, url, nil)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid request for %s: %w", url, err)
		}
	} else {
		var payloadBytes []byte
		payloadBytes, err = json.Marshal(payload)
		if err != nil {
			return 0, 0, fmt.Errorf("could not marshal json request: %w", err)
		}

		req, err = http.NewRequest(method, url, bytes.NewReader(payloadBytes))
		if err != nil {
			return 0, 0, fmt.Errorf("invalid request with payload for %s: %w", url, err)
		}

		// Set content-type
		req.Header.Set("Content-Type", "application/json")
	}

	if headers != nil {
		for k, v := range *headers {
			req.Header.Add(k, v[0])
		}
	}

	req.Header.Set("Accept", "application/json")

	return sendRequest(req, url, dst)
}

func FetchSSZ(method string, url string, payload SSZMarshaler, dst SSZUnmarshaler, headers *http.Header, includeAcceptHeader bool) (code int, duration int64, err error) {
	var req *http.Request
	if payload == nil {
		req, err = http.NewRequest(method, url, nil)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid request for %s: %w", url, err)
		}
	} else {
		var payloadBytes []byte
		payloadBytes, err = payload.MarshalSSZ()
		if err != nil {
			return 0, 0, fmt.Errorf("could not marshal ssz request: %w", err)
		}

		req, err = http.NewRequest(method, url, bytes.NewReader(payloadBytes))
		if err != nil {
			return 0, 0, fmt.Errorf("invalid request with payload for %s: %w", url, err)
		}

		// Set content-type
		req.Header.Set("Content-Type", "application/octet-stream")
	}

	if headers != nil {
		for k, v := range *headers {
			req.Header.Add(k, v[0])
		}
	}
	if includeAcceptHeader {
		req.Header.Set("Accept", "application/octet-stream")
	}

	return sendRequestSSZ(req, url, dst)
}

func FetchSSZMarshalled(method string, url string, payload []byte, dst SSZUnmarshaler, headers *http.Header, includeAcceptHeader bool) (code int, duration int64, err error) {
	var req *http.Request

	if payload == nil {
		req, err = http.NewRequest(method, url, nil)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid request for %s: %w", url, err)
		}
	} else {

		req, err = http.NewRequest(method, url, bytes.NewReader(payload))
		if err != nil {
			return 0, 0, fmt.Errorf("invalid request with payload for %s: %w", url, err)
		}

		// Set content-type
		req.Header.Set("Content-Type", "application/octet-stream")
	}

	if headers != nil {
		for k, v := range *headers {
			req.Header.Add(k, v[0])
		}
	}
	if includeAcceptHeader {
		req.Header.Set("Accept", "application/octet-stream")
	}

	return sendRequestSSZ(req, url, dst)
}

func sendRequest(req *http.Request, url string, dst any) (code int, duration int64, err error) {
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	duration = time.Since(start).Milliseconds()
	if err != nil {
		return 0, duration, fmt.Errorf("client refused for %s: %w", url, err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, duration, fmt.Errorf("could not read response body for %s: %w", url, err)
	}

	if resp.StatusCode >= http.StatusMultipleChoices {
		ec := &struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}{}
		if err = json.Unmarshal(bodyBytes, ec); err != nil {
			return resp.StatusCode, duration, fmt.Errorf("could not unmarshal error response from beacon node for %s from %s: %w", url, string(bodyBytes), err)
		}
		return resp.StatusCode, duration, fmt.Errorf("%w: %s", ErrHTTPErrorResponse, ec.Message)
	}

	if dst != nil {
		err = json.Unmarshal(bodyBytes, dst)
		if err != nil {
			return resp.StatusCode, duration, fmt.Errorf("could not unmarshal response for %s from %s: %w", url, string(bodyBytes), err)
		}
	}

	return resp.StatusCode, duration, nil
}

func sendRequestSSZ(req *http.Request, url string, dst SSZUnmarshaler) (code int, duration int64, err error) {
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	duration = time.Since(start).Milliseconds()
	if err != nil {
		return 0, duration, fmt.Errorf("client refused for %s: %w", url, err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, duration, fmt.Errorf("could not read response body for %s: %w", url, err)
	}

	if resp.StatusCode >= http.StatusMultipleChoices {
		ec := &struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}{}
		if err = json.Unmarshal(bodyBytes, ec); err != nil {
			return resp.StatusCode, duration, fmt.Errorf("could not unmarshal error response from beacon node for %s from %s: %w", url, string(bodyBytes), err)
		}
		return resp.StatusCode, duration, fmt.Errorf("%w: %s", ErrHTTPErrorResponse, ec.Message)
	}

	if dst != nil {
		err = dst.UnmarshalSSZ(bodyBytes)
		if err != nil {
			return resp.StatusCode, duration, fmt.Errorf("could not unmarshal response for %s from %s: %w", url, string(bodyBytes), err)
		}
	}

	return resp.StatusCode, duration, nil
}
