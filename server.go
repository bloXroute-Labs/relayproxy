package relayproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bloXroute-Labs/relayproxy/common"
	"github.com/bloXroute-Labs/relayproxy/fluentstats"
	gjson "github.com/goccy/go-json"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/metadata"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
)

// Router paths
const (
	AuthHeaderPrefix = "bearer "

	// methods
	getHeader       = "getHeader"
	getPayload      = "getPayload"
	preFetchPayload = "preFetchPayload"
	registration    = "registration"

	MEVBoostStartTimeUnixMS = "X-MEVBoost-StartTimeUnixMS"
	HeaderDateMilliseconds  = "Date-Milliseconds"
	VouchCluster            = "setup"
)

type contextKey string

var (
	keyParsedURL  contextKey = "parsedURL"
	keyAuthHeader contextKey = "authHeader"
	keyAccountID  contextKey = "accountID"
	keyClientIP   contextKey = "clientIP"
	keyOrgID      contextKey = "id"
)

type Server struct {
	logger        zerolog.Logger
	server        *http.Server
	svc           IService
	listenAddress string

	beaconGenesisTime int64
	secondsPerSlot    int64

	tracer       trace.Tracer
	fluentD      fluentstats.Stats
	accessFilter AccessFilter

	authHeaderP2P string // Added until vouch support query params

	ghRatelimit    GetHeaderRateLimitInfo
	accountsLists  *AccountsLists
	NodeID         string
	AdminAccountID string
}

type GetHeaderRateLimitInfo struct {
	lastGetHeaderRequest uint64
	slotToIPToGHRequest  *SyncMap[uint64, map[string]bool]
}

type DelaySettings struct {
	GetHeaderDelayMS    int64 `json:"sleep"`
	GetHeaderMaxDelayMS int64 `json:"max_sleep"`
}

type AccessFilter struct {
	Accounts AccessList
	IPs      AccessList
	SkipAuth bool
}
type AccessList struct {
	AllowList map[string]struct{}
	BlockList map[string]struct{}
}
type account struct {
	accountID, validatorID string
}

func New(opts ...ServerOption) *Server {
	server := new(Server)
	for _, opt := range opts {
		opt(server)
	}
	server.ghRatelimit = GetHeaderRateLimitInfo{
		lastGetHeaderRequest: 0,
		slotToIPToGHRequest:  NewIntegerMapOf[uint64, map[string]bool](),
	}

	return server
}

func (s *Server) Start() error {
	s.server = &http.Server{
		Addr:              s.listenAddress,
		Handler:           s.InitHandler(),
		ReadTimeout:       0,
		ReadHeaderTimeout: 0,
		WriteTimeout:      0,
		IdleTimeout:       10 * time.Second,
	}
	err := s.server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) InitHandler() *chi.Mux {
	handler := chi.NewRouter()
	handler.Group(func(r chi.Router) {
		r.Use(addCORS())
		r.With(s.MiddlewareAdmin).Get(common.PathDelaySettings, s.HandleGetDelays)
		r.With(s.MiddlewareAdmin).Options(common.PathDelaySettings, s.HandleOptions)
		r.With(s.MiddlewareAdmin).Post(common.PathDelaySettings, s.HandleSetDelays)
		r.With(s.MiddlewareAdmin).Get(common.PathGetAccounts, s.HandleGetAccounts)
	})

	handler.Get(common.PathNode, s.HandleNode)
	handler.Get(common.PathIndex, s.HandleStatus)
	handler.With(s.Middleware).Get(common.PathStatus, s.HandleStatus)
	handler.With(s.Middleware).Post(common.PathRegisterValidator, s.HandleRegistration)
	handler.With(s.MiddlewareGetHeader).Get(common.PathGetHeader, s.HandleGetHeader)
	handler.With(s.Middleware).Post(common.PathGetPayload, s.HandleGetPayload)
	s.logger.Info().Msg("Init relay proxy")
	return handler
}
func addCORS() func(next http.Handler) http.Handler {
	corsOpts := cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"*"},
	}
	return cors.Handler(corsOpts)
}

func (s *Server) Stop() {
	if s.server != nil {
		_ = s.server.Shutdown(context.Background())
	}
}

func (s *Server) MiddlewareAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.authorizeAdmin(w, r, next)
	})
}

func (s *Server) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.authorize(w, r, next, false)
	})
}

func (s *Server) MiddlewareGetHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.authorize(w, r, next, true)
	})
}

func (s *Server) authorizeAdmin(w http.ResponseWriter, r *http.Request, next http.Handler) {
	parsedURL, err := ParseURL(r)
	if err != nil {
		s.logger.Warn().Err(err).Msg("url parsing failed")
		// do not fail
	}
	authHeader := GetAuth(r, parsedURL)
	accountID, _, err := DecodeAuth(authHeader)
	if err != nil {
		s.writeErrorResponse(w, "failed to authorize", fmt.Errorf("failed to authorize and decode auth header : %v, url: %v, Err: %v", authHeader, parsedURL.String(), err), http.StatusUnauthorized)
		return
	}
	if accountID != s.AdminAccountID { // TODO:set admin account id
		s.writeErrorResponse(w, "access denied", fmt.Errorf("acdess denied accountID: %v, auth header %v, url: %v", accountID, authHeader, parsedURL.String()), http.StatusUnauthorized)
		return
	}
	next.ServeHTTP(w, r)
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request, next http.Handler, isGetHeader bool) {
	parsedURL, err := ParseURL(r)
	if err != nil {
		s.logger.Warn().Err(err).Msg("url parsing failed")
		// do not fail
	}
	id := GetOrgID(r, parsedURL)
	clientIP := GetIPXForwardedFor(r)
	authHeader := GetAuth(r, parsedURL)
	ctx := r.Context()
	ctx = context.WithValue(ctx, keyOrgID, id)
	if s.accessFilter.SkipAuth {
		ctx = context.WithValue(ctx, keyParsedURL, parsedURL)
		ctx = context.WithValue(ctx, keyClientIP, clientIP)
		ctx = context.WithValue(ctx, keyAuthHeader, authHeader)
		accountID, _, _ := DecodeAuth(authHeader)
		ctx = context.WithValue(ctx, keyAccountID, accountID)
		next.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	var (
		accountID     string
		isWhitelisted bool
	)
	if _, allowed := s.accessFilter.IPs.AllowList[clientIP]; !allowed {
		if _, blocked := s.accessFilter.IPs.BlockList[clientIP]; blocked {
			s.logger.Warn().
				Str("ip", clientIP).
				Str("id", id).
				Str("url", parsedURL.String()).
				Err(err).Msg("ip access denied")
			http.Error(w, "access denied", http.StatusUnauthorized)
			return
		}
		accountID, _, err = DecodeAuth(authHeader)
		if err != nil {
			s.logger.Warn().
				Str("authHeader", authHeader).
				Str("ip", clientIP).
				Str("id", id).
				Str("url", parsedURL.String()).
				Err(err).Msg("failed to decode auth header")
			s.logger.Warn().
				Str("ip", clientIP).
				Str("id", id).
				Str("url", parsedURL.String()).Err(err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if _, allowed = s.accessFilter.Accounts.AllowList[accountID]; !allowed {
			if _, blocked := s.accessFilter.Accounts.BlockList[accountID]; blocked {
				s.logger.Warn().
					Str("authHeader", authHeader).
					Str("accountID", accountID).
					Str("ip", clientIP).
					Str("id", id).
					Str("url", parsedURL.String()).
					Err(err).Msg("account access denied")
				http.Error(w, "access denied", http.StatusUnauthorized)
				return
			}
		}
		isWhitelisted = s.accountsLists.AccountIDToInfo[accountID] != nil &&
			s.accountsLists.AccountIDToInfo[accountID].IsWhitelisted
	} else {
		// fetch account id for ip allowed case
		//authHeader = GetAuth(r, parsedURL)
		authHeader = s.authHeaderP2P
		accountID, _, err = DecodeAuth(authHeader)
		if err != nil {
			// do not fail
			s.logger.Warn().
				Str("authHeader", authHeader).
				Str("accountID", accountID).
				Str("ip", clientIP).
				Str("url", parsedURL.String()).
				Err(err).Msg("failed to decode auth header")
		}
		if s.accountsLists.AccountIDToInfo[accountID] != nil {
			if customCtx := s.accountsLists.AccountIDToInfo[accountID].CustomCtx; customCtx != "" {
				ctx = context.WithValue(ctx, keyOrgID, customCtx)
			}
		}
		isWhitelisted = s.accountsLists.AccountIDToInfo[accountID] != nil &&
			s.accountsLists.AccountIDToInfo[accountID].IsWhitelisted
	}

	if isGetHeader && !isWhitelisted {
		currentSlot := uint64(CalculateCurrentSlot(s.beaconGenesisTime, s.secondsPerSlot))
		slotIPRequests, exists := s.ghRatelimit.slotToIPToGHRequest.Load(currentSlot)
		if !exists || slotIPRequests == nil {
			slotIPRequests = make(map[string]bool)
		} else {
			if slotIPRequests[clientIP] {
				s.logger.Warn().
					Str("authHeader", authHeader).
					Str("accountID", accountID).
					Str("ip", clientIP).
					Str("url", parsedURL.String()).
					Err(err).Msg("get header rate limit exceeded")
				// Not saying IP because that encourages people to work around the rate limit
				http.Error(w, "only one getheader request allowed per slot per validator", http.StatusTooManyRequests)
				return
			}
		}
		slotIPRequests[clientIP] = true
		s.ghRatelimit.slotToIPToGHRequest.Store(currentSlot, slotIPRequests)
		for j := s.ghRatelimit.lastGetHeaderRequest - 100; j < currentSlot-100; j++ {
			s.ghRatelimit.slotToIPToGHRequest.Delete(j)
		}
		s.ghRatelimit.lastGetHeaderRequest = currentSlot
	}
	ctx = context.WithValue(ctx, keyParsedURL, parsedURL)
	ctx = context.WithValue(ctx, keyClientIP, clientIP)
	ctx = context.WithValue(ctx, keyAuthHeader, authHeader)
	ctx = context.WithValue(ctx, keyAccountID, accountID)
	next.ServeHTTP(w, r.WithContext(ctx))
}

func (s *Server) HandleOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.WriteHeader(http.StatusOK)
}
func (s *Server) HandleStatus(w http.ResponseWriter, req *http.Request) {
	parentSpan := trace.SpanFromContext(req.Context())
	ctx := trace.ContextWithSpan(context.Background(), parentSpan)
	_, span := s.tracer.Start(ctx, "HandleStatus-start")
	defer span.End()
	parsedURL, err := ParseURL(req)
	if err != nil {
		s.logger.Warn().Err(err).Msg("url parsing failed")
		// do not fail
	}
	span.SetAttributes(
		attribute.String("reqHost", req.Host),
		attribute.String("method", req.Method),
		attribute.String("remoteAddr", req.RemoteAddr),
		attribute.String("requestURI", req.RequestURI),
		attribute.String("authHeader", GetAuth(req, parsedURL)),
		attribute.String("traceID", span.SpanContext().TraceID().String()),
	)

	s.writeSuccessResponse(w, []byte(`{}`))
}

func (s *Server) HandleNode(w http.ResponseWriter, req *http.Request) {
	parentSpan := trace.SpanFromContext(req.Context())
	ctx := trace.ContextWithSpan(context.Background(), parentSpan)
	_, span := s.tracer.Start(ctx, "HandleNode-start")
	defer span.End()
	parsedURL, err := ParseURL(req)
	if err != nil {
		s.logger.Warn().Err(err).Msg("url parsing failed")
		// do not fail
	}
	span.SetAttributes(
		attribute.String("reqHost", req.Host),
		attribute.String("method", req.Method),
		attribute.String("remoteAddr", req.RemoteAddr),
		attribute.String("requestURI", req.RequestURI),
		attribute.String("authHeader", GetAuth(req, parsedURL)),
		attribute.String("traceID", span.SpanContext().TraceID().String()),
	)

	s.writeSuccessResponse(w, []byte(s.NodeID))
}

func (s *Server) writeSuccessResponse(w http.ResponseWriter, resp []byte) {
	w.Header().Set(common.HeaderContentType, common.MediaTypeJSON)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}
func (s *Server) writeErrorResponse(w http.ResponseWriter, message string, err error, statusCode int) {
	s.logger.Warn().Err(err).Msg(message)
	http.Error(w, message, statusCode)
}
func (s *Server) HandleGetAccounts(w http.ResponseWriter, r *http.Request) {
	accounts := s.svc.GetAccounts(r.Context())
	out, err := json.Marshal(accounts)
	if err != nil {
		s.writeErrorResponse(w, "failed to fetch accounts", err, http.StatusInternalServerError)
		return
	}
	s.writeSuccessResponse(w, out)
}

func (s *Server) HandleGetDelays(w http.ResponseWriter, r *http.Request) {
	settings := s.svc.GetDelaySettings(r.Context())
	out, err := json.Marshal(settings)
	if err != nil {
		s.writeErrorResponse(w, "failed to fetch delay settings", err, http.StatusInternalServerError)
		return
	}
	s.writeSuccessResponse(w, out)
}
func (s *Server) HandleSetDelays(w http.ResponseWriter, r *http.Request) {
	parsedURL, err := ParseURL(r)
	if err != nil {
		s.logger.Warn().Err(err).Msg("url parsing failed")
	}

	delay, maxDelay, id := GetSleepParams(parsedURL, 0, 0)
	if id == "" || delay == 0 || maxDelay == 0 {
		bodyBytes, err := io.ReadAll(r.Body)
		if err == nil {
			var delaySettings map[string]DelaySettings
			if err = json.Unmarshal(bodyBytes, &delaySettings); err != nil {
				s.writeErrorResponse(w, "failed to update validators delay setting", err, http.StatusBadRequest)
				return
			}
			s.svc.SetDelayForValidators(delaySettings)
			s.writeSuccessResponse(w, []byte(`{"msg":"validators delay settings updated"}`))
			return

		}
		s.writeErrorResponse(w, "failed to update validators delay setting", err, http.StatusInternalServerError)
		return
	}
	s.svc.SetDelayForValidator(id, delay, maxDelay)
	s.writeSuccessResponse(w, []byte(`{"msg":"validator delay settings updated"}`))
}

func (s *Server) HandleRegistration(w http.ResponseWriter, r *http.Request) {
	parentSpan := trace.SpanFromContext(r.Context())
	parentSpanCtx := trace.ContextWithSpan(context.Background(), parentSpan)
	handleRegistrationCtx, handleRegistrationSpan := s.tracer.Start(parentSpanCtx, "handleRegistration-start")
	defer parentSpan.End()
	defer handleRegistrationSpan.End()

	receivedAt := time.Now().UTC()
	parsedURL := r.Context().Value(keyParsedURL).(*url.URL)
	clientIP := r.Context().Value(keyClientIP).(string)
	authHeader := r.Context().Value(keyAuthHeader).(string)
	validatorID := r.Context().Value(keyOrgID).(string)
	complianceList := strings.Join(parsedURL.Query()["compliance_list"], ",")
	skipOptimismQuery := parsedURL.Query().Get("skip_optimism")
	accountID := r.Context().Value(keyAccountID).(string)

	mevBoostSendTimeUnixMS := r.Header.Get(MEVBoostStartTimeUnixMS)
	commitBoostSendTimeUnixMS := r.Header.Get(HeaderDateMilliseconds)

	boostSendTime, latency := getBoostSendTimeAndLatency(receivedAt, mevBoostSendTimeUnixMS, commitBoostSendTimeUnixMS)
	sszRequest, _ := common.ParseBuilderContentType(r)
	outgoingCtx := context.Background()
	if sszRequest {
		outgoingCtx = metadata.AppendToOutgoingContext(outgoingCtx, common.HeaderBlxrContentType, common.MediaTypeOctetStream)
	}
	s.svc.SendAccount(accountID, validatorID)

	logMetric := NewLogMetric(
		map[string]any{
			"reqHost":        r.Host,
			"method":         r.Method,
			"userAgent":      r.Header.Get("User-Agent"),
			"clientIP":       clientIP,
			"remoteAddr":     r.RemoteAddr,
			"requestURI":     r.RequestURI,
			"parsedURL":      parsedURL.String(),
			"validatorID":    validatorID,
			"complianceList": complianceList,
			"skipOptimism":   skipOptimismQuery,
			"authHeader":     authHeader,
			"traceID":        handleRegistrationSpan.SpanContext().TraceID().String(),
			"boostSendTime":  boostSendTime,
			"latency":        latency,
		},
		[]attribute.KeyValue{
			attribute.String("reqHost", r.Host),
			attribute.String("method", r.Method),
			attribute.String("validatorID", validatorID),
			attribute.String("complianceList", complianceList),
			attribute.String("skipOptimism", skipOptimismQuery),
			attribute.String("clientIP", clientIP),
			attribute.String("remoteAddr", r.RemoteAddr),
			attribute.String("requestURI", r.RequestURI),
			attribute.String("authHeader", authHeader),
			attribute.String("traceID", handleRegistrationSpan.SpanContext().TraceID().String()),
			attribute.String("boostSendTime", boostSendTime),
			attribute.Int64("latency", latency),
		},
	)

	handleRegistrationSpan.SetAttributes(logMetric.GetAttributes()...)
	hasProposerMevProtect, err := GetProposerMevProtectQueryAny(parsedURL, s.logger, logMetric)
	if err != nil {
		handleRegistrationSpan.SetStatus(codes.Error, err.Error())
		logMetric.String("proxyError", err.Error())
		logMetric.Error(errors.New("could not read proposer_mev_protect"))
		respondError(handleRegistrationCtx, registration, w, toErrorResp(http.StatusInternalServerError, "could not parse boolean proposer_mev_protect", logMetric.GetFields()), s.logger, s.tracer, logMetric)
		return
	}
	isSkipOptimism := false
	if skipOptimismQuery != "" {
		var err error
		isSkipOptimism, err = strconv.ParseBool(skipOptimismQuery)
		if err != nil {
			handleRegistrationSpan.SetStatus(codes.Error, err.Error())
			logMetric.String("proxyError", err.Error())
			logMetric.Error(errors.New("could not read skip_optimism"))
			respondError(handleRegistrationCtx, registration, w, toErrorResp(http.StatusInternalServerError, "could not parse boolean skip_optimism: "+skipOptimismQuery, logMetric.GetFields()), s.logger, s.tracer, logMetric)
			return
		}
	}
	handleRegistrationSpan.SetAttributes(
		attribute.Bool("proposerMevProtect", hasProposerMevProtect),
	)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		handleRegistrationSpan.SetStatus(codes.Error, err.Error())
		logMetric.String("proxyError", err.Error())
		logMetric.Error(errors.New("could not read registration"))
		respondError(handleRegistrationCtx, registration, w, toErrorResp(http.StatusInternalServerError, "could not read registration", logMetric.GetFields()), s.logger, s.tracer, logMetric)
		return
	}
	handleRegistrationSpan.AddEvent("handleRegistration- svcRegisterValidator")
	go func() {
		_, lm, err := s.svc.RegisterValidator(handleRegistrationCtx, outgoingCtx, &RegistrationParams{
			ReceivedAt:         receivedAt,
			Payload:            bodyBytes,
			ClientIP:           clientIP,
			AuthHeader:         authHeader,
			ValidatorID:        validatorID,
			AccountID:          accountID,
			ComplianceList:     complianceList,
			ProposerMevProtect: hasProposerMevProtect,
			SkipOptimism:       isSkipOptimism,
		})
		logMetric.Merge(lm)
		if err != nil {
			handleRegistrationSpan.SetStatus(codes.Error, err.Error())
			respondError(handleRegistrationCtx, registration, w, err, s.logger, s.tracer, logMetric)
			return
		}
	}()

	respondOK(handleRegistrationCtx, registration, w, struct{}{}, s.logger, s.tracer, logMetric)
}

func (s *Server) HandleGetHeader(w http.ResponseWriter, r *http.Request) {
	parentSpan := trace.SpanFromContext(r.Context())
	parentSpanCtx := trace.ContextWithSpan(context.Background(), parentSpan)
	handleGetHeaderCtx, span := s.tracer.Start(parentSpanCtx, "handleGetHeader-start")
	defer parentSpan.End()
	defer span.End()

	receivedAt := time.Now().UTC()
	slot := chi.URLParam(r, "slot")
	parentHash := chi.URLParam(r, "parent_hash")
	pubKey := chi.URLParam(r, "pubkey")
	parsedURL := r.Context().Value(keyParsedURL).(*url.URL)
	clientIP := r.Context().Value(keyClientIP).(string)
	validatorID := r.Context().Value(keyOrgID).(string)
	authHeader := r.Context().Value(keyAuthHeader).(string)
	accountID := r.Context().Value(keyAccountID).(string)
	mevBoostSendTimeUnixMS := r.Header.Get(MEVBoostStartTimeUnixMS)
	commitBoostSendTimeUnixMS := r.Header.Get(HeaderDateMilliseconds)
	boostSendTime, latency := getBoostSendTimeAndLatency(receivedAt, mevBoostSendTimeUnixMS, commitBoostSendTimeUnixMS)
	cluster := r.Header.Get(VouchCluster)
	userAgent := r.Header.Get("User-Agent")
	headers := []string{}
	for k, v := range r.Header {
		headers = append(headers, k+"="+v[0])
	}
	_, sszResponse := common.ParseBuilderContentType(r)

	logMetric := NewLogMetric(
		map[string]any{
			"reqHost":                  r.Host,
			"method":                   r.Method,
			"userAgent":                userAgent,
			"remoteAddr":               r.RemoteAddr,
			"requestURI":               r.RequestURI,
			"parsedURL":                parsedURL.String(),
			"clientIP":                 clientIP,
			"validatorID":              validatorID,
			"accountID":                accountID,
			"authHeader":               authHeader,
			"traceID":                  span.SpanContext().TraceID().String(),
			"parentHash":               parentHash,
			"pubKey":                   pubKey,
			"getHeaderStartTimeUnixMS": boostSendTime,
			"latency":                  latency,
			"cluster":                  cluster,
			"sszResponse":              sszResponse,
			"headers":                  headers,
		},
		[]attribute.KeyValue{
			attribute.String("reqHost", r.Host),
			attribute.String("method", r.Method),
			attribute.String("clientIP", clientIP),
			attribute.String("remoteAddr", r.RemoteAddr),
			attribute.String("requestURI", r.RequestURI),
			attribute.String("validatorID", validatorID),
			attribute.String("accountID", accountID),
			attribute.String("authHeader", authHeader),
			attribute.String("parentHash", parentHash),
			attribute.String("pubKey", pubKey),
			attribute.String("traceID", span.SpanContext().TraceID().String()),
			attribute.String("getHeaderStartTimeUnixMS", boostSendTime),
			attribute.Int64("latency", latency),
			attribute.String("cluster", cluster),
			attribute.String("userAgent", userAgent),
			attribute.Bool("sszResponse", sszResponse),
			attribute.StringSlice("headers", headers),
		},
	)
	span.SetAttributes(logMetric.GetAttributes()...)
	span.AddEvent("handleGetHeader-svcGetHeader")
	out, lm, err := s.svc.GetHeader(handleGetHeaderCtx, &HeaderRequestParams{
		ReceivedAt:               receivedAt,
		GetHeaderStartTimeUnixMS: boostSendTime,
		Latency:                  latency,
		ClientIP:                 clientIP,
		Slot:                     slot,
		ParentHash:               parentHash,
		PubKey:                   pubKey,
		AuthHeader:               authHeader,
		ValidatorID:              validatorID,
		AccountID:                accountID,
		Cluster:                  cluster,
		UserAgent:                userAgent,
	})

	if err != nil {
		s.logger.Error().Err(err).Msg("Error in GetHeader")
		respondError(handleGetHeaderCtx, getHeader, w, err, s.logger, s.tracer, logMetric)
		return
	}

	if !sszResponse {
		s.logger.Info().Msg("Responding with JSON")
		respondOK(handleGetHeaderCtx, getHeader, w, out, s.logger, s.tracer, logMetric)
		return
	}

	versionedBid := new(common.VersionedSignedBuilderBid)
	if err = versionedBid.UnmarshalJSON(out.(json.RawMessage)); err != nil {
		s.logger.Error().Err(err).Msg("Failed to unmarshal JSON")
		respondError(handleGetHeaderCtx, getHeader, w, toErrorResp(http.StatusInternalServerError, err.Error(), lm.GetFields()), s.logger, s.tracer, logMetric)
		return
	}

	sszMarshal, err := versionedBid.MarshalSSZ()
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to marshal SSZ")
		respondOK(handleGetHeaderCtx, getHeader, w, out, s.logger, s.tracer, nil)
		return
	}

	w.Header().Set(common.HeaderEthConsensusVersion, versionedBid.Version.String())
	s.logger.Info().Msg("Responding with SSZ")
	s.respondOKWithContextSSZMarshalled(handleGetHeaderCtx, getHeader, w, sszMarshal, s.logger, s.tracer, logMetric)
}

func (s *Server) HandleGetPayload(w http.ResponseWriter, r *http.Request) {
	parentSpan := trace.SpanFromContext(r.Context())
	parentCtx := trace.ContextWithSpan(context.Background(), parentSpan)
	getPayloadCtx, span := s.tracer.Start(parentCtx, "handleGetPayload-start")
	defer parentSpan.End()
	defer span.End()

	receivedAt := time.Now().UTC()
	clientIP := r.Context().Value(keyClientIP).(string)
	parsedURL := r.Context().Value(keyParsedURL).(*url.URL)
	authHeader := r.Context().Value(keyAuthHeader).(string)
	validatorID := r.Context().Value(keyOrgID).(string)
	accountID := r.Context().Value(keyAccountID).(string)

	mevBoostSendTimeUnixMS := r.Header.Get(MEVBoostStartTimeUnixMS)
	commitBoostSendTimeUnixMS := r.Header.Get(HeaderDateMilliseconds)
	boostSendTime, latency := getBoostSendTimeAndLatency(receivedAt, mevBoostSendTimeUnixMS, commitBoostSendTimeUnixMS)
	cluster := r.Header.Get(VouchCluster)
	userAgent := r.Header.Get("User-Agent")

	headers := []string{}
	for k, v := range r.Header {
		headers = append(headers, k+"="+v[0])
	}
	sszRequest, sszResponse := common.ParseBuilderContentType(r)
	logMetric := NewLogMetric(
		map[string]any{
			"reqHost":                  r.Host,
			"method":                   r.Method,
			"remoteAddr":               r.RemoteAddr,
			"requestURI":               r.RequestURI,
			"parsedURL":                parsedURL.String(),
			"clientIP":                 clientIP,
			"validatorID":              validatorID,
			"accountID":                accountID,
			"authHeader":               authHeader,
			"traceID":                  span.SpanContext().TraceID().String(),
			"getHeaderStartTimeUnixMS": boostSendTime,
			"latency":                  latency,
			"cluster":                  cluster,
			"userAgent":                userAgent,
			"sszRequest":               sszRequest,
			"sszResponse":              sszResponse,
			"headers":                  headers,
		},
		[]attribute.KeyValue{
			attribute.String("reqHost", r.Host),
			attribute.String("method", r.Method),
			attribute.String("clientIP", clientIP),
			attribute.String("remoteAddr", r.RemoteAddr),
			attribute.String("requestURI", r.RequestURI),
			attribute.String("parsedURL", parsedURL.String()),
			attribute.String("validatorID", validatorID),
			attribute.String("accountID", accountID),
			attribute.String("authHeader", authHeader),
			attribute.String("traceID", span.SpanContext().TraceID().String()),
			attribute.String("getPayloadStartTimeUnixMS", boostSendTime),
			attribute.Int64("latency", latency),
			attribute.String("cluster", cluster),
			attribute.String("userAgent", userAgent),
			attribute.Bool("sszRequest", sszRequest),
			attribute.Bool("sszResponse", sszResponse),
			attribute.StringSlice("headers", headers),
		},
	)
	span.SetAttributes(logMetric.GetAttributes()...)

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		logMetric.String("proxyError", err.Error())
		logMetric.Error(errors.New("could not read registration"))
		respondError(getPayloadCtx, getPayload, w, toErrorResp(http.StatusInternalServerError, "could not read registration", logMetric.GetFields()), s.logger, s.tracer, logMetric)
		return
	}
	signedBlindedBeaconBlock := new(common.VersionedSignedBlindedBeaconBlock)
	if sszRequest {
		_, decodeSSZSpan := s.tracer.Start(getPayloadCtx, "handleGetPayload-decodeSSZ")
		err := signedBlindedBeaconBlock.UnmarshalSSZ(bodyBytes)
		if err != nil {
			decodeSSZSpan.End()
			respondError(getPayloadCtx, getPayload, w, toErrorResp(http.StatusInternalServerError, "failed to decode request payload", logMetric.GetFields()), s.logger, s.tracer, logMetric)
			return
		}
		decodeSSZSpan.End()
		_, encodeJSONSpan := s.tracer.Start(getPayloadCtx, "handleGetPayload-encodeJSON")
		bodyBytes, err = signedBlindedBeaconBlock.MarshalJSON()
		if err != nil {
			encodeJSONSpan.End()
			respondError(getPayloadCtx, getPayload, w, toErrorResp(http.StatusInternalServerError, "failed to marshal to json", logMetric.GetFields()), s.logger, s.tracer, logMetric)
			return
		}
		encodeJSONSpan.End()
	}
	span.AddEvent("handleGetPayload-svcGetPayload")
	out, lm, err := s.svc.GetPayload(getPayloadCtx, &PayloadRequestParams{
		ReceivedAt:                receivedAt,
		Payload:                   bodyBytes,
		ClientIP:                  clientIP,
		AuthHeader:                authHeader,
		ValidatorID:               validatorID,
		AccountID:                 accountID,
		GetPayloadStartTimeUnixMS: boostSendTime,
		Cluster:                   cluster,
		UserAgent:                 userAgent,
	})
	logMetric.Merge(lm)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		respondError(getPayloadCtx, getPayload, w, err, s.logger, s.tracer, logMetric)
		return
	}

	if !sszResponse {
		respondOK(getPayloadCtx, getPayload, w, out, s.logger, s.tracer, logMetric)
		return
	}
	payloadResponse := new(common.VersionedSubmitBlindedBlockResponse)
	if err := payloadResponse.UnmarshalJSON(out.(json.RawMessage)); err != nil {
		span.SetStatus(codes.Error, err.Error())
		respondError(getPayloadCtx, getPayload, w, toErrorResp(http.StatusInternalServerError, err.Error(), logMetric.GetFields()), s.logger, s.tracer, logMetric)
		return
	}
	outByte, err := payloadResponse.MarshalSSZ()
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal getHeader to ssz")
		span.SetStatus(codes.Error, err.Error())
		respondOK(getPayloadCtx, getPayload, w, out, s.logger, s.tracer, logMetric)
		return
	}

	w.Header().Set(common.HeaderEthConsensusVersion, payloadResponse.Version.String())
	s.respondOKWithContextSSZMarshalled(getPayloadCtx, getPayload, w, outByte, s.logger, s.tracer, logMetric)
}
func respondOK(ctx context.Context, method string, w http.ResponseWriter, response any, log zerolog.Logger, tracer trace.Tracer, logMetric *LogMetric) {
	_, span := tracer.Start(ctx, "respondOK-"+method)
	defer span.End()
	logMetric.Attributes(
		attribute.String("method", method),
		attribute.Int("responseCode", 200),
		attribute.String("traceID", span.SpanContext().TraceID().String()),
	)
	span.SetAttributes(logMetric.GetAttributes()...)

	w.Header().Set(common.HeaderContentType, common.MediaTypeJSON)

	if err := gjson.NewEncoder(w).Encode(response); err != nil {
		span.SetStatus(codes.Error, "couldn't write OK response")
		log.Error().Fields(logMetric.GetFields()).Err(err).Msg("couldn't write OK response")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	log.Info().Str("method", method).Fields(logMetric.GetFields()).Msg(method + " succeeded")

}

func respondError(ctx context.Context, method string, w http.ResponseWriter, err error, log zerolog.Logger, tracer trace.Tracer, logMetric *LogMetric) {

	_, span := tracer.Start(ctx, "respondError-"+method)
	defer span.End()
	logMetric.Attributes(
		attribute.String("method", method),
		attribute.String("Err", err.Error()),
		attribute.String("traceID", span.SpanContext().TraceID().String()),
	)
	span.SetAttributes(logMetric.GetAttributes()...)

	resp, ok := err.(*ErrorResp)
	span.SetAttributes(attribute.Int("responseCode", resp.ErrorCode()))
	if !ok {
		log.Error().Fields(logMetric.GetFields()).Str("method", method).Err(err).Msg("failed to typecast error response")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		span.SetStatus(codes.Error, "failed to typecast error response")
		return
	}
	w.WriteHeader(resp.Code)
	log.Error().Str("method", method).Fields(logMetric.GetFields()).Msg(method + " failed")
	if resp.Message != "" && resp.Code != http.StatusNoContent { // HTTP status "No Content" implies that no message body should be included in the response.
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			span.SetStatus(codes.Error, "couldn't write error response")
			log.Error().Fields(logMetric.GetFields()).Str("method", method).Err(err).Msg("couldn't write error response")
			_, _ = w.Write([]byte(``))
			return
		}
	}
}
func GetProposerMevProtectQueryAny(parsedURL *url.URL, log zerolog.Logger, logMetric *LogMetric) (bool, error) {
	proposerMevProtectQuery := parsedURL.Query().Get("proposer_mev_protect")
	proposerMevProtect, err := parseQuery("proposer_mev_protect", proposerMevProtectQuery, log, logMetric)
	if err != nil {
		return false, err
	}
	mevProtectQuery := parsedURL.Query().Get("mev_protect")
	mevProtect, parseErr := parseQuery("mev_protect", mevProtectQuery, log, logMetric)
	if parseErr != nil {
		log.Error().Err(err).Msg("failed to parse mev_protect")
		return false, err
	}
	mevGuardQuery := parsedURL.Query().Get("mev_guard")
	mevGuard, parseErr := parseQuery("mev_guard", mevGuardQuery, log, logMetric)
	if parseErr != nil {
		log.Error().Err(err).Msg("failed to parse mev_guard")
		return false, err
	}
	proposerMevGuardQuery := parsedURL.Query().Get("proposer_mev_guard")
	proposerMevGuard, parseErr := parseQuery("proposer_mev_guard", proposerMevGuardQuery, log, logMetric)
	if parseErr != nil {
		log.Error().Err(err).Msg("failed to parse mev_guard")
		return false, err
	}
	return proposerMevProtect || mevProtect || mevGuard || proposerMevGuard, nil
}
func parseQuery(query string, value string, log zerolog.Logger, logMetric *LogMetric) (bool, error) {
	if value == "" {
		return false, nil
	}
	logMetric.Attributes(
		attribute.String("query", query),
		attribute.String("value", value),
	)
	proposerMevProtect, err := strconv.ParseBool(value)
	if err != nil {
		log.With().Fields(logMetric.GetFields()).Err(err).Str("reason", "failed to parse proposer-mev-protect, setting proposer-mev-protect to false by default")
	}
	return proposerMevProtect, err
}

func (m *Server) respondOKWithContextSSZMarshalled(ctx context.Context, method string, w http.ResponseWriter, resBytes []byte, log zerolog.Logger, tracer trace.Tracer, logMetric *LogMetric) {
	_, span := tracer.Start(ctx, fmt.Sprintf("respondOKSSZ-%s", method))
	defer span.End()
	logMetric.Attributes(
		attribute.String("method", method),
		attribute.Int("responseCode", 200),
		attribute.String("traceID", span.SpanContext().TraceID().String()),
	)
	span.SetAttributes(logMetric.GetAttributes()...)

	w.Header().Set(common.HeaderContentType, common.MediaTypeOctetStream)

	_, writeHeaderSpan := m.tracer.Start(ctx, "writeHeader")
	w.WriteHeader(http.StatusOK)
	writeHeaderSpan.End()

	_, writeBytesSpan := m.tracer.Start(ctx, "writeBytes")
	_, err := w.Write(resBytes)
	writeBytesSpan.End()
	if err != nil {
		span.SetStatus(codes.Error, "couldn't write OK response")
		log.Error().Fields(logMetric.GetFields()).Str("method", method).Err(err).Msg("couldn't write error response")
		http.Error(w, "", http.StatusInternalServerError)
	}
	log.Info().Str("method", method).Fields(logMetric.GetFields()).Msg(method + " succeeded")
}
