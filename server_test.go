package relayproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

type MockService struct {
	logger                    *zap.Logger
	RegisterValidatorFunc     func(ctx context.Context, outgoingctx context.Context, in *RegistrationParams)
	GetHeaderFunc             func(ctx context.Context, in *HeaderRequestParams)
	GetPayloadFunc            func(ctx context.Context, in *PayloadRequestParams)
	GetAccountsFunc           func(ctx context.Context) map[string]interface{}
	SetAccountsFunc           func(ctx context.Context)
	SendAccountFunc           func(accountID, validatorID string)
	GetDelaySettingsFunc      func(ctx context.Context) map[string]DelaySettings
	SetDelayForValidatorFunc  func(id string, delay, maxDelay int64)
	SetDelayForValidatorsFunc func(settings map[string]DelaySettings)
	DelayGetHeaderFunc        func(ctx context.Context, params DelayGetHeaderParams)
}

func (m *MockService) GetAccounts(ctx context.Context) map[string]any {
	if m.GetAccountsFunc != nil {
		return m.GetAccountsFunc(ctx)
	}
	return nil
}

func (m *MockService) SetAccounts(ctx context.Context) {
	if m.SetAccountsFunc != nil {
		m.SetAccountsFunc(ctx)
		return
	}
}

func (m *MockService) SendAccount(accountID, validatorID string) {
	if m.SendAccountFunc != nil {
		m.SendAccountFunc(accountID, validatorID)
		return
	}
}
func (m *MockService) GetDelaySettings(ctx context.Context) map[string]DelaySettings {
	if m.GetDelaySettingsFunc != nil {
		return m.GetDelaySettingsFunc(ctx)
	}
	return map[string]DelaySettings{}
}

func (m *MockService) SetDelayForValidator(id string, delay, maxDelay int64) {
	if m.SetDelayForValidatorFunc != nil {
		m.SetDelayForValidatorFunc(id, delay, maxDelay)
		return
	}
}

func (m *MockService) SetDelayForValidators(settings map[string]DelaySettings) {
	if m.SetDelayForValidatorsFunc != nil {
		m.SetDelayForValidatorsFunc(settings)
		return
	}
}

func (m *MockService) DelayGetHeader(ctx context.Context, in DelayGetHeaderParams) (DelayGetHeaderResponse, error) {
	if m.DelayGetHeaderFunc != nil {
		return m.DelayGetHeaderFunc(ctx, DelayGetHeaderParams{
			ReceivedAt:          in.ReceivedAt,
			Slot:                in.Slot,
			AccountID:           in.AccountID,
			Cluster:             in.Cluster,
			UserAgent:           in.UserAgent,
			ClientIP:            in.ClientIP,
			SlotWithParentHash:  in.SlotWithParentHash,
			BoostSendTimeUnixMS: in.BoostSendTimeUnixMS,
			Latency:             in.Latency,
		}), nil
	}
	return DelayGetHeaderResponse{}, nil
}

var _ IService = (*MockService)(nil)

func (m *MockService) RegisterValidator(ctx context.Context, outgoingCtx context.Context, in *RegistrationParams) (any, *LogMetric, error) {
	if m.RegisterValidatorFunc != nil {
		return m.RegisterValidatorFunc(ctx, outgoingCtx, in)
	}
	return nil, new(LogMetric), nil
}
func (m *MockService) GetHeader(ctx context.Context, in *HeaderRequestParams) (any, *LogMetric, error) {
	if m.GetHeaderFunc != nil {
		return m.GetHeaderFunc(ctx, in)
	}
	return nil, new(LogMetric), nil
}

func (m *MockService) GetPayload(ctx context.Context, in *PayloadRequestParams) (any, *LogMetric, error) {
	if m.GetPayloadFunc != nil {
		return m.GetPayloadFunc(ctx, in)
	}
	return nil, new(LogMetric), nil
}

func TestServer_HandleRegistration(t *testing.T) {
	testCases := map[string]struct {
		requestBody  []byte
		url          string
		mockService  *MockService
		expectedCode int
	}{
		"When registration succeeded": {
			requestBody: []byte(`{"key": "value"}`),
			url:         "/eth/v1/builder/validators?id=VG&auth=" + TestAuthHeader,
			mockService: &MockService{
				logger: zap.NewNop(),
				RegisterValidatorFunc: func(ctx context.Context, payload []byte, clientIP, authKey, validatorID string) (interface{}, *LogMetric, error) {
					return nil, nil, nil

				},
			},
			expectedCode: http.StatusOK,
		},
		"Registration should succeed when url contains escape char": {
			requestBody: []byte(`{"key": "value"}`),
			url:         "/eth/v1/builder/validators?id=VG%26auth=" + TestAuthHeader + "%26sleep=600%26max_sleep=1200",
			mockService: &MockService{
				logger: zap.NewNop(),
				RegisterValidatorFunc: func(ctx context.Context, payload []byte, clientIP, authKey, validatorID string) (interface{}, *LogMetric, error) {
					return nil, nil, nil

				},
			},
			expectedCode: http.StatusOK,
		},
		"When registration failed": {
			requestBody: []byte(`{"key": "value"}`),
			url:         "/eth/v1/builder/validators",
			mockService: &MockService{
				logger: zap.NewNop(),
				RegisterValidatorFunc: func(ctx context.Context, payload []byte, clientIP, authKey, validatorID string) (interface{}, *LogMetric, error) {
					return nil, nil, toErrorResp(http.StatusInternalServerError, "")
				},
			},
			expectedCode: http.StatusUnauthorized,
		},
	}

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			req, err := http.NewRequest("POST", tc.url, bytes.NewBuffer(tc.requestBody))
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			dataSvc := NewDataService()
			server := &Server{svc: tc.mockService, logger: zap.NewNop(), tracer: noop.NewTracerProvider().Tracer("test"), accountsLists: &AccountsLists{AccountIDToInfo: make(map[string]*AccountInfo), AccountNameToInfo: make(map[AccountName]*AccountInfo)}}
			go dataSvc.SetAccounts(context.Background())
			h := server.Middleware(http.HandlerFunc(server.HandleRegistration))
			h.ServeHTTP(rr, req)
			assert.Equal(t, rr.Code, tc.expectedCode)
		})
	}
}

func TestServer_HandleGetHeader(t *testing.T) {
	testCases := map[string]struct {
		slot           string
		parentHash     string
		pubKey         string
		mockService    *MockService
		expectedCode   int
		expectedOutput string
		ip             string
	}{
		"when getHeader succeeded": {
			slot:       "123",
			parentHash: "ph123",
			pubKey:     "pk123",
			mockService: &MockService{
				logger: zap.NewNop(),
				GetHeaderFunc: func(ctx context.Context, clientIP, slot, parentHash, pubKey, authHeader, validatorID string) (interface{}, *LogMetric, error) {

					return "getHeader", nil, nil
				},
			},
			expectedCode:   http.StatusOK,
			expectedOutput: "getHeader",
			ip:             "127.0.0.2",
		},
		"when getHeader failed": {
			slot:       "456",
			parentHash: "ph456",
			pubKey:     "pk456",
			mockService: &MockService{
				logger: zap.NewNop(),
				GetHeaderFunc: func(ctx context.Context, clientIP, slot, parentHash, pubKey, authHeader, validatorID string) (interface{}, *LogMetric, error) {
					return nil, nil, &ErrorResp{Code: http.StatusNoContent}
				},
			},
			expectedCode:   http.StatusNoContent,
			expectedOutput: "",
			ip:             "127.0.0.3",
		},
		"when getHeader failed with requested header not found": {
			slot:       "456",
			parentHash: "ph456",
			pubKey:     "pk456",
			mockService: &MockService{
				logger: zap.NewNop(),
				GetHeaderFunc: func(ctx context.Context, clientIP, slot, parentHash, pubKey, authHeader, validatorID string) (interface{}, *LogMetric, error) {
					return nil, nil, &ErrorResp{Code: http.StatusNoContent, Message: "header value is not present for the requested key slot"}
				},
			},
			expectedCode:   http.StatusNoContent,
			expectedOutput: "",
			ip:             "127.0.0.4",
		},
		"get header rate limit": {
			slot:       "456",
			parentHash: "ph456a",
			pubKey:     "pk456b",
			mockService: &MockService{
				logger: zap.NewNop(),
				GetHeaderFunc: func(ctx context.Context, clientIP, slot, parentHash, pubKey, authHeader, validatorID string) (interface{}, *LogMetric, error) {
					return nil, nil, &ErrorResp{Code: http.StatusTooManyRequests, Message: "only one getheader request allowed per slot per validator"}
				},
			},
			expectedCode:   http.StatusTooManyRequests,
			expectedOutput: "{\"code\":429,\"message\":\"only one getheader request allowed per slot per validator\"}",
			ip:             "127.0.0.4",
		},
	}

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			req, err := http.NewRequest("GET", fmt.Sprintf("/eth/v1/builder/header/%s/%s/%s?id=VG&auth="+TestAuthHeader, tc.slot, tc.parentHash, tc.pubKey), nil)
			if err != nil {
				t.Fatal(err)
			}
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("slot", tc.slot)
			rctx.URLParams.Add("parent_hash", tc.parentHash)
			rctx.URLParams.Add("pubkey", tc.pubKey)

			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
			req.Header.Add("X-Forwarded-For", tc.ip)
			rr := httptest.NewRecorder()
			server := &Server{svc: tc.mockService, logger: zap.NewNop(), tracer: noop.NewTracerProvider().Tracer("test"), accountsLists: &AccountsLists{AccountIDToInfo: make(map[string]*AccountInfo), AccountNameToInfo: make(map[AccountName]*AccountInfo)}}

			h := server.Middleware(http.HandlerFunc(server.HandleGetHeader))
			h.ServeHTTP(rr, req)

			assert.Equal(t, rr.Code, tc.expectedCode)
			if tc.expectedOutput != "" {
				out := strings.TrimSpace(rr.Body.String())
				out = strings.Trim(out, "\"")
				assert.Equal(t, out, tc.expectedOutput)
				return
			}
			assert.Equal(t, rr.Body.String(), tc.expectedOutput)
		})
	}
}

func TestServer_HandleGetPayload(t *testing.T) {
	testCases := map[string]struct {
		requestBody   []byte
		mockService   *MockService
		expectedCode  int
		expectedError string
	}{
		"When getPayload succeeded": {
			requestBody: []byte(`{"key": "value"}`),
			mockService: &MockService{
				logger: zap.NewNop(),
				GetPayloadFunc: func(ctx context.Context, payload []byte, clientIP, authHeader, validatorID string) (any, *LogMetric, error) {
					return nil, nil, nil
				},
			},
			expectedCode:  http.StatusOK,
			expectedError: "",
		},
		"When getPayload failed": {
			requestBody: []byte(`{"key": "value"}`),
			mockService: &MockService{
				logger: zap.NewNop(),
				GetPayloadFunc: func(ctx context.Context, payload []byte, clientIP, authHeader, validatorID string) (any, *LogMetric, error) {
					return nil, nil, toErrorResp(http.StatusInternalServerError, "failed to getPayload")
				},
			},
			expectedCode:  http.StatusInternalServerError,
			expectedError: "failed to getPayload",
		},
	}

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			req, err := http.NewRequest("POST", "/eth/v1/builder/blinded_blocks?id=VG&auth="+TestAuthHeader, bytes.NewBuffer(tc.requestBody))
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			server := &Server{svc: tc.mockService, logger: zap.NewNop(), tracer: noop.NewTracerProvider().Tracer("test"), accountsLists: &AccountsLists{AccountIDToInfo: make(map[string]*AccountInfo), AccountNameToInfo: make(map[AccountName]*AccountInfo)}}
			h := server.Middleware(http.HandlerFunc(server.HandleGetPayload))
			h.ServeHTTP(rr, req)

			assert.Equal(t, rr.Code, tc.expectedCode)
			out := new(ErrorResp)
			err = json.NewDecoder(rr.Body).Decode(out)
			assert.NoError(t, err)
			if tc.expectedError != "" {
				assert.Equal(t, out.Message, tc.expectedError)
			}
		})
	}
}

func TestServer_HandleSetDelays(t *testing.T) {
	testCases := map[string]struct {
		reqPostFunc       func() *http.Request
		expectedPostCode  int
		expectedPostError string
		reqGetFunc        func() *http.Request
		expectedGetOut    map[string]DelaySettings
		expectedGetCode   int
		expectedGetError  string
	}{
		"When set delay succeeded via req body": {
			reqPostFunc: func() *http.Request {
				body := []byte(`{"validatorA": {"sleep": 800, "max_sleep": 1200}, "validatorB": {"sleep": 750,"max_sleep": 900}}`)
				req, err := http.NewRequest(http.MethodPost, "/relay_proxy/v1/delay_settings", bytes.NewBuffer(body))
				if err != nil {
					t.Fatal(err)
				}
				return req
			},
			expectedPostCode:  http.StatusOK,
			expectedPostError: "",
			reqGetFunc: func() *http.Request {
				req, err := http.NewRequest(http.MethodGet, "/relay_proxy/v1/delay_settings", nil)
				if err != nil {
					t.Fatal(err)
				}
				return req
			},
			expectedGetOut: map[string]DelaySettings{
				"validatorA": {800, 1200},
				"validatorB": {750, 900},
			},
			expectedGetCode: http.StatusOK,
		},
		"When set delay succeeded via query param": {
			reqPostFunc: func() *http.Request {
				req, err := http.NewRequest(http.MethodPost, "/relay_proxy/v1/delay_settings", nil)
				if err != nil {
					t.Fatal(err)
				}
				q := req.URL.Query()
				q.Set("account_id", "validatorA")
				q.Set("sleep", "800")
				q.Set("max_sleep", "1200")
				req.URL.RawQuery = q.Encode()
				return req
			},
			expectedPostCode:  http.StatusOK,
			expectedPostError: "",
			reqGetFunc: func() *http.Request {
				req, err := http.NewRequest(http.MethodGet, "/relay_proxy/v1/delay_settings", nil)
				if err != nil {
					t.Fatal(err)
				}
				return req
			},
			expectedGetOut: map[string]DelaySettings{
				"validatorA": {800, 1200},
			},
			expectedGetCode: http.StatusOK,
		},
	}

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			rrPost := httptest.NewRecorder()
			dSvc := NewDataService()
			opts := make([]ServiceOption, 0)
			opts = append(opts, WithDataService(dSvc))
			svc := NewService(opts...)
			server := &Server{svc: svc, logger: zap.NewNop(), tracer: noop.NewTracerProvider().Tracer("test"), accountsLists: &AccountsLists{AccountIDToInfo: make(map[string]*AccountInfo), AccountNameToInfo: make(map[AccountName]*AccountInfo)}}
			server.HandleSetDelays(rrPost, tc.reqPostFunc())
			assert.Equal(t, rrPost.Code, tc.expectedPostCode)

			rrGet := httptest.NewRecorder()
			server.HandleGetDelays(rrGet, tc.reqGetFunc())
			assert.Equal(t, rrGet.Code, tc.expectedGetCode)
			out := make(map[string]DelaySettings)
			err := json.NewDecoder(rrGet.Body).Decode(&out)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedGetOut, out)
			//if tc.expectedError != "" {
			//	assert.Equal(t, out.Message, tc.expectedError)
			//}
		})
	}
}
func TestServer_Middleware(t *testing.T) {
	testCases := map[string]struct {
		setupRequest func() *http.Request
		setupServer  func() *Server
		expectedCode int
	}{
		"Allow access for authorized Account": {
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "/eth/v1/builder/status?id=VG&auth="+TestAuthHeader, nil)
				clientIP := "192.0.2.4"
				req.Header.Add("X-Forwarded-For", clientIP)
				return req
			},
			setupServer: func() *Server {
				return &Server{
					accessFilter: AccessFilter{
						Accounts: AccessList{
							AllowList: map[string]struct{}{"bf5c5d1b-7030-4f05-9ac3-217095e9d2b6": {}},
							BlockList: map[string]struct{}{},
						},
						IPs: AccessList{
							AllowList: map[string]struct{}{"127.0.0.1": {}},
							BlockList: map[string]struct{}{},
						},
					},
					logger: zaptest.NewLogger(t),
					accountsLists: &AccountsLists{AccountIDToInfo: make(map[string]*AccountInfo),
						AccountNameToInfo: make(map[AccountName]*AccountInfo)},
				}
			},
			expectedCode: http.StatusOK,
		},
		"Deny access for blocked Account": {
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "/eth/v1/builder/status?id=VG&auth="+TestAuthHeader, nil)
				clientIP := "192.0.2.3"
				req.Header.Add("X-Forwarded-For", clientIP)
				return req
			},
			setupServer: func() *Server {
				return &Server{
					accessFilter: AccessFilter{
						Accounts: AccessList{
							AllowList: map[string]struct{}{},
							BlockList: map[string]struct{}{"bf5c5d1b-7030-4f05-9ac3-217095e9d2b6": {}},
						},
						IPs: AccessList{
							AllowList: map[string]struct{}{},
							BlockList: map[string]struct{}{},
						},
					},
					logger: zaptest.NewLogger(t),
					accountsLists: &AccountsLists{AccountIDToInfo: make(map[string]*AccountInfo),
						AccountNameToInfo: make(map[AccountName]*AccountInfo)},
				}
			},
			expectedCode: http.StatusUnauthorized,
		},
		"Deny access for blocked ip": {
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "/eth/v1/builder/status?id=VG&auth="+TestAuthHeader, nil)
				clientIP := "192.0.2.1"
				req.Header.Add("X-Forwarded-For", clientIP)
				return req
			},
			setupServer: func() *Server {
				return &Server{
					accessFilter: AccessFilter{
						Accounts: AccessList{
							AllowList: map[string]struct{}{},
							BlockList: map[string]struct{}{},
						},
						IPs: AccessList{
							AllowList: map[string]struct{}{},
							BlockList: map[string]struct{}{"192.0.2.1": {}},
						},
					},
					logger: zaptest.NewLogger(t),
					accountsLists: &AccountsLists{AccountIDToInfo: make(map[string]*AccountInfo),
						AccountNameToInfo: make(map[AccountName]*AccountInfo)},
				}
			},
			expectedCode: http.StatusUnauthorized,
		},
	}

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			req := tc.setupRequest()
			server := tc.setupServer()
			rr := httptest.NewRecorder()
			handler := server.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			handler.ServeHTTP(rr, req)
			assert.Equal(t, tc.expectedCode, rr.Code)
		})
	}
}
