package relayproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	gjson "github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/metadata"

	"github.com/bloXroute-Labs/relay-grpc/stat"
	"github.com/bloXroute-Labs/relayproxy/common"
	"github.com/bloXroute-Labs/relayproxy/fluentstats"
)

// Router paths
const (
	AuthHeaderPrefix = "bearer "

	// methods
	getHeader       = "getHeader"
	getPayload      = "getPayload"
	getPayloadV2    = "getPayloadV2"
	preFetchPayload = "preFetchPayload"
	registration    = "registration"

	MEVBoostStartTimeUnixMS = "X-MEVBoost-StartTimeUnixMS"
	HeaderDateMilliseconds  = "Date-Milliseconds"
	HeaderKeySlotUID        = "X-MEVBoost-SlotID"
	VouchCluster            = "setup"
	statsNamePerformance    = "performanceStats"

	// payload
	maxGetPayloadBody = int64(
		12 + // 3 offsets
			48*4096 + // max commitments
			48*4096 + // max proofs
			131072*6 + // up to 6 blobs (tune if you expect more)
			(2 << 20), // +2MiB headroom for payload/overheads
	)
	bodyReadTimeoutGetPayload   = 400 * time.Millisecond
	bodyReadTimeoutGetPayloadV2 = 400 * time.Millisecond

	// registration
	maxRegistrationBody         = int64(2 << 20) // 2 MiB; adjust as needed
	bodyReadTimeoutRegistration = 3 * time.Second
	ctxTimeoutRegistration      = 4 * time.Second
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

	ghRatelimit      GetHeaderRateLimitInfo
	accountsLists    *AccountsLists
	NodeID           string
	AdminAccountID   string
	performanceStats *stat.PerformanceStats

	getPayloadBodyPool sync.Pool
	// Callback
	OnHeaderDelivered func(
		VersionedSignedBuilderBid *common.VersionedSignedBuilderBid, Slot uint64,
		GetHeaderRequestID string,
		ProposerPubkey string,
		GetHeaderStartTimeUnixMS string,
		ExtraData string,
	) error
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

func NewServer(opts ...ServerOption) *Server {
	server := new(Server)

	for _, opt := range opts {
		opt(server)
	}

	server.ghRatelimit = GetHeaderRateLimitInfo{
		lastGetHeaderRequest: 0,
		slotToIPToGHRequest:  NewIntegerMapOf[uint64, map[string]bool](),
	}
	server.getPayloadBodyPool = sync.Pool{
		New: func() any { return make([]byte, 64<<10) }, // 64 KiB
	}
	return server
}

func (s *Server) Start() error {
	s.server = &http.Server{
		Addr:              s.listenAddress,
		Handler:           s.InitHandler(),
		ReadTimeout:       2 * time.Second,
		ReadHeaderTimeout: 500 * time.Millisecond,
		WriteTimeout:      4 * time.Second,
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
	handler.With(s.Middleware).Post(common.PathGetPayloadV2, s.HandleGetPayloadV2)
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
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	r = r.WithContext(ctx)

	receivedAt := time.Now().UTC()
	success := false
	defer func() {
		s.performanceStats.SetEndpointStats(
			common.PathRegisterValidator,
			uint64(time.Since(receivedAt).Microseconds()),
			success,
			100)
	}()

	parentSpan := trace.SpanFromContext(ctx)
	parentSpanCtx := trace.ContextWithSpan(context.Background(), parentSpan)
	handleRegistrationCtx, handleRegistrationSpan := s.tracer.Start(parentSpanCtx, "handleRegistration-start")
	defer parentSpan.End()
	defer handleRegistrationSpan.End()

	parsedURL := r.Context().Value(keyParsedURL).(*url.URL)
	clientIP := r.Context().Value(keyClientIP).(string)
	authHeader := r.Context().Value(keyAuthHeader).(string)
	validatorID := r.Context().Value(keyOrgID).(string)
	complianceList := strings.Join(parsedURL.Query()["compliance_list"], ",")
	skipOptimismQuery := parsedURL.Query().Get("skip_optimism")
	accountID := r.Context().Value(keyAccountID).(string)

	mevBoostSendTimeUnixMS := r.Header.Get(MEVBoostStartTimeUnixMS)
	commitBoostSendTimeUnixMS := r.Header.Get(HeaderDateMilliseconds)

	boostSendTime, sentAtUtc, latency := getBoostSendTimeAndLatency(receivedAt, mevBoostSendTimeUnixMS, commitBoostSendTimeUnixMS)
	sszRequest, _ := common.ParseBuilderContentType(r)
	outgoingCtx := context.Background()
	if sszRequest {
		outgoingCtx = metadata.AppendToOutgoingContext(outgoingCtx, common.HeaderBlxrContentType, common.MediaTypeOctetStream)
	}
	s.svc.SendAccount(accountID, validatorID)

	headers := make([]string, 0, len(r.Header))
	for k, v := range r.Header {
		headers = append(headers, k+"="+v[0])
	}

	log := s.logger.With().
		Str("reqHost", r.Host).
		Str("method", r.Method).
		Str("userAgent", r.Header.Get("User-Agent")).
		Str("clientIP", clientIP).
		Str("remoteAddr", r.RemoteAddr).
		Str("requestURI", r.RequestURI).
		Str("parsedURL", parsedURL.String()).
		Str("validatorID", validatorID).
		Str("complianceList", complianceList).
		Str("skipOptimism", skipOptimismQuery).
		Str("authHeader", authHeader).
		Str("traceID", handleRegistrationSpan.SpanContext().TraceID().String()).
		Str("boostSendTime", boostSendTime).
		Strs("headers", headers).
		Int64("latency", latency).
		Time("receivedAt", receivedAt).
		Str("receivedAtUtc", formatUTCms(receivedAt)).
		Str("sentAtUtc", sentAtUtc).
		Logger()

	handleRegistrationSpan.SetAttributes(
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
		attribute.StringSlice("headers", headers),
		attribute.Int64("receivedAt", receivedAt.UnixMilli()),
		attribute.String("receivedAtUtc", formatUTCms(receivedAt)),
		attribute.String("sentAtUtc", sentAtUtc),
	)
	log.Info().Msg("received registration")

	hasProposerMevProtect, err := GetProposerMevProtectQueryAny(parsedURL, &log)
	if err != nil {
		handleRegistrationSpan.SetStatus(codes.Error, err.Error())
		log.Error().Err(err).Msg("could not parse proposer_mev_protect query parameter")
		respondError(handleRegistrationCtx, handleRegistrationSpan, registration, w,
			toErrorResp(http.StatusInternalServerError, "could not parse boolean proposer_mev_protect"), &log, s.tracer)
		return
	}
	isSkipOptimism := false
	if skipOptimismQuery != "" {
		var perr error
		isSkipOptimism, perr = strconv.ParseBool(skipOptimismQuery)
		if perr != nil {
			handleRegistrationSpan.SetStatus(codes.Error, perr.Error())
			log.Error().Err(perr).Msg("could not parse skip_optimism query parameter")
			respondError(handleRegistrationCtx, handleRegistrationSpan, registration, w,
				toErrorResp(http.StatusInternalServerError, "could not parse boolean skip_optimism: "+skipOptimismQuery), &log, s.tracer)
			return
		}
	}
	handleRegistrationSpan.SetAttributes(
		attribute.Bool("proposerMevProtect", hasProposerMevProtect),
	)

	bodyBytes, err := s.readAllPooledCtx(ctx, w, r, maxRegistrationBody, bodyReadTimeoutRegistration)
	if err != nil {
		handleRegistrationSpan.SetStatus(codes.Error, err.Error())
		log.Error().Err(err).Msg("could not read registration")
		respondError(handleRegistrationCtx, handleRegistrationSpan, registration, w,
			toErrorResp(http.StatusInternalServerError, "could not read registration"), &log, s.tracer)
		return
	}

	handleRegistrationSpan.AddEvent("handleRegistration- svcRegisterValidator")
	go func() {
		_, err := s.svc.RegisterValidator(handleRegistrationCtx, &log, outgoingCtx, &RegistrationParams{
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
		if err != nil {
			handleRegistrationSpan.SetStatus(codes.Error, err.Error())
			handleRegistrationSpan.SetAttributes(attribute.String("error", err.Error()))
			log.Error().Err(err).Msg("error in RegisterValidator")
			return
		}
	}()

	if err := respondOK(handleRegistrationCtx, handleRegistrationSpan, registration, w, struct{}{}, &log, s.tracer, false); err == nil {
		success = true
	}
}

func (s *Server) HandleGetHeader(w http.ResponseWriter, r *http.Request) {
	const callerMethodName = "handleGetHeader"

	receivedAt := time.Now().UTC()
	success := false
	defer func() {
		if s.performanceStats != nil {
			s.performanceStats.SetEndpointStats(
				common.PathGetHeader,
				uint64(time.Since(receivedAt).Microseconds()),
				success,
				100,
			)
		}
	}()

	// Root span for this handler (don’t end any upstream parent span yourself).
	ctx := r.Context()
	ctx, span := s.tracer.Start(ctx, GetSpanName(callerMethodName, "START"))
	defer span.End()

	// -------- Preflight span --------
	preflightStart := time.Now()
	_, preflight := s.tracer.Start(ctx, GetSpanName(callerMethodName, "preflight"))

	// A) extractHeaderValues
	extractStart := time.Now()
	_, spanExtract := s.tracer.Start(ctx, GetSpanName(callerMethodName, "extractHeaderValues"))

	slot := chi.URLParam(r, "slot")
	parentHash := chi.URLParam(r, "parent_hash")
	pubKey := chi.URLParam(r, "pubkey")

	clientIP, _ := ctx.Value(keyClientIP).(string)
	parsedURL, _ := ctx.Value(keyParsedURL).(*url.URL)
	authHeader, _ := ctx.Value(keyAuthHeader).(string)
	validatorID, _ := ctx.Value(keyOrgID).(string)
	accountID, _ := ctx.Value(keyAccountID).(string)

	mevBoostSendTimeUnixMS := r.Header.Get(MEVBoostStartTimeUnixMS)
	commitBoostSendTimeUnixMS := r.Header.Get(HeaderDateMilliseconds)
	headerSlotUID := r.Header.Get(HeaderKeySlotUID)
	cluster := r.Header.Get(VouchCluster)
	userAgent := r.Header.Get("User-Agent")

	spanExtract.SetAttributes(
		attribute.String("clientIP", clientIP),
		attribute.String("parsedURL", func() string {
			if parsedURL != nil {
				return parsedURL.String()
			}
			return ""
		}()),
		attribute.String("validatorID", validatorID),
		attribute.String("accountID", accountID),
		attribute.String("authHeader", authHeader),
		attribute.String("path.slot", slot),
		attribute.String("path.parentHash", parentHash),
		attribute.String("path.pubKey", pubKey),
		attribute.String("hdr.MEVBoostStartTimeUnixMS", mevBoostSendTimeUnixMS),
		attribute.String("hdr.Date-Milliseconds", commitBoostSendTimeUnixMS),
		attribute.String("hdr.SlotUID", headerSlotUID),
		attribute.String("hdr.VouchCluster", cluster),
		attribute.String("hdr.User-Agent", userAgent),
		attribute.Int64("extract_headers_duration_ms", time.Since(extractStart).Milliseconds()),
	)
	spanExtract.End()

	// B) getBoostSendTimeAndLatency
	boostStart := time.Now()
	_, spanBoost := s.tracer.Start(ctx, GetSpanName(callerMethodName, "getBoostSendTimeAndLatency"))
	boostSendTime, sentAtUtc, latency := getBoostSendTimeAndLatency(
		receivedAt,
		mevBoostSendTimeUnixMS,
		commitBoostSendTimeUnixMS,
	)
	spanBoost.SetAttributes(
		attribute.String("boostSendTime", boostSendTime),
		attribute.String("sentAtUtc", sentAtUtc),
		attribute.Int64("latency_ms", latency),
		attribute.Int64("getBoostSendTimeAndLatency_latency_duration_ms", time.Since(boostStart).Milliseconds()),
	)
	spanBoost.End()

	// C) ParseBuilderContentType (only the response flag matters here)
	parseCTStart := time.Now()
	_, spanParseCT := s.tracer.Start(ctx, GetSpanName(callerMethodName, "ParseBuilderContentType"))
	_, sszResponse := common.ParseBuilderContentType(r)
	spanParseCT.SetAttributes(
		attribute.Bool("sszResponse", sszResponse),
		attribute.Int64("parse_content_type_duration_ms", time.Since(parseCTStart).Milliseconds()),
	)
	spanParseCT.End()

	// D) headerValuesLoop: materialize headers slice (for logs & debug)
	headerLoopStart := time.Now()
	_, spanHdrLoop := s.tracer.Start(ctx, GetSpanName(callerMethodName, "headerValuesLoop"))
	headers := make([]string, 0, len(r.Header))
	for k, v := range r.Header {
		if len(v) > 0 {
			headers = append(headers, k+"="+v[0])
		}
	}
	spanHdrLoop.SetAttributes(
		attribute.Int("header_count", len(headers)),
		attribute.Int64("collect_headers_duration_ms", time.Since(headerLoopStart).Milliseconds()),
	)
	spanHdrLoop.End()

	// E) set root attributes
	setAttrsStart := time.Now()
	_, spanSetAttrs := s.tracer.Start(ctx, GetSpanName(callerMethodName, "setRootAttributes"))
	keyStr := "slot-" + slot + "-parentHash-" + parentHash
	span.SetAttributes(
		attribute.String("reqHost", r.Host),
		attribute.String("method", r.Method),
		attribute.String("clientIP", clientIP),
		attribute.String("remoteAddr", r.RemoteAddr),
		attribute.String("requestURI", r.RequestURI),
		attribute.String("parsedURL", func() string {
			if parsedURL != nil {
				return parsedURL.String()
			}
			return ""
		}()),
		attribute.String("validatorID", validatorID),
		attribute.String("accountID", accountID),
		attribute.String("authHeader", authHeader),
		attribute.String("traceID", span.SpanContext().TraceID().String()),
		attribute.String("getHeaderStartTimeUnixMS", boostSendTime),
		attribute.Int64("latency_ms", latency),
		attribute.String("cluster", cluster),
		attribute.String("userAgent", userAgent),
		attribute.Bool("sszResponse", sszResponse),
		attribute.StringSlice("headers", headers),
		attribute.String("slotUID", headerSlotUID),
		attribute.String("methodName", getHeader),
		attribute.String("key", keyStr),
		attribute.String("slot", slot),
		attribute.String("parentHash", parentHash),
		attribute.String("pubKey", pubKey),
		attribute.Int64("receivedAt_ms", receivedAt.UnixMilli()),
		attribute.String("receivedAtUtc", formatUTCms(receivedAt)),
		attribute.String("sentAtUtc", sentAtUtc),
	)
	spanSetAttrs.SetAttributes(
		attribute.Int64("set_root_attrs_duration_ms", time.Since(setAttrsStart).Milliseconds()),
	)
	spanSetAttrs.End()

	preflight.SetAttributes(attribute.Int64("preflight_duration_ms", time.Since(preflightStart).Milliseconds()))
	preflight.End()

	// F) build structured logger bound to context
	buildLoggerStart := time.Now()
	_, spanBuildLogger := s.tracer.Start(ctx, GetSpanName(callerMethodName, "buildLogger"))
	log := s.logger.With().
		Str("reqHost", r.Host).
		Str("method", r.Method).
		Str("userAgent", userAgent).
		Str("clientIP", clientIP).
		Str("remoteAddr", r.RemoteAddr).
		Str("requestURI", r.RequestURI).
		Str("parsedURL", func() string {
			if parsedURL != nil {
				return parsedURL.String()
			}
			return ""
		}()).
		Str("validatorID", validatorID).
		Str("accountID", accountID).
		Str("authHeader", authHeader).
		Str("traceID", span.SpanContext().TraceID().String()).
		Str("parentHash", parentHash).
		Str("pubKey", pubKey).
		Str("getHeaderStartTimeUnixMS", boostSendTime).
		Int64("latency", latency).
		Str("cluster", cluster).
		Bool("sszResponse", sszResponse).
		Strs("headers", headers).
		Str("slotUID", headerSlotUID).
		Str("methodName", getHeader).
		Str("key", keyStr).
		Str("slot", slot).
		Str("receivedAtUtc", formatUTCms(receivedAt)).
		Str("sentAtUtc", sentAtUtc).
		Logger()
	spanBuildLogger.SetAttributes(
		attribute.Int64("build_logger_duration_ms", time.Since(buildLoggerStart).Milliseconds()),
	)
	spanBuildLogger.End()

	// -----------------------------
	// G) Service call
	// -----------------------------
	callStart := time.Now()
	_, spanSvc := s.tracer.Start(ctx, GetSpanName(callerMethodName, "svcGetHeader"))

	var (
		onHeaderDeliveredParams *common.OnHeaderDeliveredParams
		out                     json.RawMessage
		err                     error
	)

	out, onHeaderDeliveredParams, err = s.svc.GetHeader(
		span, // parent span for service internals
		ctx,
		&log,
		&HeaderRequestParams{
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
			SlotUID:                  headerSlotUID,
		},
	)
	spanSvc.SetAttributes(attribute.Int64("svc_get_header_duration_ms", time.Since(callStart).Milliseconds()))
	if err != nil {
		spanSvc.SetStatus(codes.Error, err.Error())
	}
	spanSvc.End()

	if err != nil {
		log.Error().Err(err).Msg("getHeader: service failed")
		span.SetAttributes(attribute.String("error", err.Error()))
		respondError(ctx, span, getHeader, w, err, &log, s.tracer)
		return
	}

	if onHeaderDeliveredParams != nil {
		span.SetAttributes(
			attribute.String("blockHash", onHeaderDeliveredParams.BlockHash),
		)
		log = log.With().
			Str("blockHash", onHeaderDeliveredParams.BlockHash).
			Logger()
	}

	// H) Callback (fire-and-forget), with its own child span
	go func(ctx context.Context, shp *common.OnHeaderDeliveredParams) {
		if shp == nil || s.OnHeaderDelivered == nil {
			log.Warn().Msg("getHeader: skipping callback")
			return
		}

		cbStart := time.Now()
		_, cbSpan := s.tracer.Start(ctx, GetSpanName(callerMethodName, "callback-OnHeaderDelivered"))
		defer func() {
			cbSpan.SetAttributes(attribute.Int64("callback_duration_ms", time.Since(cbStart).Milliseconds()))
			cbSpan.End()
		}()

		versionedBid := new(common.VersionedSignedBuilderBid)
		if uErr := versionedBid.UnmarshalJSON(shp.SignedHeaderResponse); uErr != nil {
			log.Error().Err(uErr).Msg("getHeader: failed to unmarshal signed header response")
			cbSpan.SetStatus(codes.Error, uErr.Error())
			return
		}

		if err := s.OnHeaderDelivered(
			versionedBid,
			shp.Slot,
			shp.GetHeaderRequestID,
			shp.ProposerPubkey,
			shp.GetHeaderStartTimeUnixMS,
			shp.ExtraData,
		); err != nil {
			log.Error().Err(err).Msg("getHeader: OnHeaderDelivered failed")
			cbSpan.SetStatus(codes.Error, err.Error())
		}

		// enrich the callback span with post-delivery attributes
		cbSpan.SetAttributes(
			attribute.Int64("sleep", shp.Sleep),
			attribute.Int64("maxSleep", shp.MaxSleep),
			attribute.Int64("msIntoSlot", shp.MsIntoSlot),
			attribute.Int64("msIntoSlotIncludingDelay", shp.MsIntoSlotWithDelay),
			attribute.String("blockHash", shp.BlockHash),
		)
	}(ctx, onHeaderDeliveredParams)

	out = []byte(`header disabled`)
	respondOK(ctx, span, getHeader, w, out, &log, s.tracer, true)

	// -----------------------------
	// I) Response encoding
	// -----------------------------
	//if !sszResponse {
	//	respondStart := time.Now()
	//	_, spanRespond := s.tracer.Start(ctx, GetSpanName(callerMethodName, "respondJSON"))
	//	log.Debug().Msg("Responding with JSON")
	//	if err := respondOK(ctx, span, getHeader, w, out, &log, s.tracer, true); err == nil {
	//		success = true
	//	}
	//	spanRespond.SetAttributes(attribute.Int64("respond_json_duration_ms", time.Since(respondStart).Milliseconds()))
	//	spanRespond.End()
	//	return
	//}
	//
	//// SSZ response path
	//sszMarshalStart := time.Now()
	//_, spanSSZ := s.tracer.Start(ctx, GetSpanName(callerMethodName, "marshalSSZ"))
	//versionedBid := new(common.VersionedSignedBuilderBid)
	//if err := versionedBid.UnmarshalJSON(out); err != nil {
	//	spanSSZ.SetStatus(codes.Error, err.Error())
	//	spanSSZ.SetAttributes(attribute.Int64("ssz_prep_duration_ms", time.Since(sszMarshalStart).Milliseconds()))
	//	spanSSZ.End()
	//
	//	log.Error().Err(err).Msg("getHeader: failed to unmarshal JSON before SSZ marshal")
	//	respondError(ctx, span, getHeader, w, toErrorResp(http.StatusInternalServerError, err.Error()), &log, s.tracer)
	//	return
	//}
	//sszBytes, err := versionedBid.MarshalSSZ()
	//if err != nil {
	//	spanSSZ.SetStatus(codes.Error, err.Error())
	//	spanSSZ.SetAttributes(attribute.Int64("ssz_marshal_duration_ms", time.Since(sszMarshalStart).Milliseconds()))
	//	spanSSZ.End()
	//
	//	log.Error().Err(err).Msg("getHeader: SSZ marshal failed; falling back to JSON")
	//	fallbackStart := time.Now()
	//	if err := respondOK(ctx, span, getHeader, w, out, &log, s.tracer, true); err == nil {
	//		success = true
	//	}
	//	span.SetAttributes(attribute.Int64("respond_json_fallback_duration_ms", time.Since(fallbackStart).Milliseconds()))
	//	return
	//}
	//spanSSZ.SetAttributes(attribute.Int64("ssz_full_marshal_duration_ms", time.Since(sszMarshalStart).Milliseconds()))
	//spanSSZ.End()
	//
	//w.Header().Set(common.HeaderEthConsensusVersion, versionedBid.Version.String())
	//
	//respondSSZStart := time.Now()
	//_, spanRespondSSZ := s.tracer.Start(ctx, GetSpanName(callerMethodName, "respondSSZ"))
	//log.Info().Msg("Responding with SSZ")
	//success = s.respondOKWithContextSSZMarshalled(ctx, span, getHeader, w, sszBytes, &log, s.tracer)
	//spanRespondSSZ.SetAttributes(attribute.Int64("respond_ssz_duration_ms", time.Since(respondSSZStart).Milliseconds()))
	//spanRespondSSZ.End()
}

func (s *Server) HandleGetPayload(w http.ResponseWriter, r *http.Request) {
	const callerMethodName = "handleGetPayload"

	receivedAt := time.Now().UTC()
	success := false
	defer func() {
		if s.performanceStats != nil {
			s.performanceStats.SetEndpointStats(
				common.PathGetPayload,
				uint64(time.Since(receivedAt).Microseconds()),
				success,
				100,
			)
		}
	}()

	// Root span for the handler.
	ctx := r.Context()
	ctx, span := s.tracer.Start(ctx, GetSpanName(callerMethodName, "START"))
	defer span.End()

	preflightStart := time.Now()
	_, preflight := s.tracer.Start(ctx, GetSpanName(callerMethodName, "preflight"))

	// A) extractHeaderValues
	extractStart := time.Now()
	_, spanExtract := s.tracer.Start(ctx, GetSpanName(callerMethodName, "extractHeaderValues"))

	clientIP, _ := ctx.Value(keyClientIP).(string)
	parsedURL, _ := ctx.Value(keyParsedURL).(*url.URL)
	authHeader, _ := ctx.Value(keyAuthHeader).(string)
	validatorID, _ := ctx.Value(keyOrgID).(string)
	accountID, _ := ctx.Value(keyAccountID).(string)

	mevBoostSendTimeUnixMS := r.Header.Get(MEVBoostStartTimeUnixMS)
	commitBoostSendTimeUnixMS := r.Header.Get(HeaderDateMilliseconds)
	headerSlotUID := r.Header.Get(HeaderKeySlotUID)
	cluster := r.Header.Get(VouchCluster)
	userAgent := r.Header.Get("User-Agent")

	spanExtract.SetAttributes(
		attribute.String("clientIP", clientIP),
		attribute.String("parsedURL", func() string {
			if parsedURL != nil {
				return parsedURL.String()
			}
			return ""
		}()),
		attribute.String("validatorID", validatorID),
		attribute.String("accountID", accountID),
		attribute.String("authHeader", authHeader),
		attribute.String("hdr.MEVBoostStartTimeUnixMS", mevBoostSendTimeUnixMS),
		attribute.String("hdr.Date-Milliseconds", commitBoostSendTimeUnixMS),
		attribute.String("hdr.SlotUID", headerSlotUID),
		attribute.String("hdr.VouchCluster", cluster),
		attribute.String("hdr.User-Agent", userAgent),
		attribute.Int64("duration_us", time.Since(extractStart).Microseconds()),
	)
	spanExtract.End()

	// B) getBoostSendTimeAndLatency
	boostStart := time.Now()
	_, spanBoost := s.tracer.Start(ctx, GetSpanName(callerMethodName, "getBoostSendTimeAndLatency"))
	boostSendTime, sentAtUtc, latency := getBoostSendTimeAndLatency(
		receivedAt,
		mevBoostSendTimeUnixMS,
		commitBoostSendTimeUnixMS,
	)
	spanBoost.SetAttributes(
		attribute.String("boostSendTime", boostSendTime),
		attribute.String("sentAtUtc", sentAtUtc),
		attribute.Int64("latency_ms", latency),
		attribute.Int64("duration_us", time.Since(boostStart).Microseconds()),
	)
	spanBoost.End()

	// C) ParseBuilderContentType
	parseCTStart := time.Now()
	_, spanParseCT := s.tracer.Start(ctx, GetSpanName(callerMethodName, "ParseBuilderContentType"))
	sszRequest, sszResponse := common.ParseBuilderContentType(r)
	spanParseCT.SetAttributes(
		attribute.Bool("sszRequest", sszRequest),
		attribute.Bool("sszResponse", sszResponse),
		attribute.Int64("duration_us", time.Since(parseCTStart).Microseconds()),
	)
	spanParseCT.End()

	// D) headerValuesLoop: materialize headers slice
	headerLoopStart := time.Now()
	_, spanHdrLoop := s.tracer.Start(ctx, GetSpanName(callerMethodName, "headerValuesLoop"))
	headers := make([]string, 0, len(r.Header))
	for k, v := range r.Header {
		if len(v) > 0 {
			headers = append(headers, k+"="+v[0])
		}
	}
	spanHdrLoop.SetAttributes(
		attribute.Int("header_count", len(headers)),
		attribute.Int64("duration_us", time.Since(headerLoopStart).Microseconds()),
	)
	spanHdrLoop.End()
	_, spanSetAttrs := s.tracer.Start(ctx, GetSpanName(callerMethodName, "setRootAttributes"))
	// Close preflight
	span.SetAttributes(
		attribute.String("reqHost", r.Host),
		attribute.String("method", r.Method),
		attribute.String("clientIP", clientIP),
		attribute.String("remoteAddr", r.RemoteAddr),
		attribute.String("requestURI", r.RequestURI),
		attribute.String("parsedURL", func() string {
			if parsedURL != nil {
				return parsedURL.String()
			}
			return ""
		}()),
		attribute.String("validatorID", validatorID),
		attribute.String("accountID", accountID),
		attribute.String("authHeader", authHeader),
		attribute.String("traceID", span.SpanContext().TraceID().String()),
		attribute.String("getPayloadStartTimeUnixMS", boostSendTime),
		attribute.Int64("latency_ms", latency),
		attribute.String("cluster", cluster),
		attribute.String("userAgent", userAgent),
		attribute.Bool("sszRequest", sszRequest),
		attribute.Bool("sszResponse", sszResponse),
		attribute.StringSlice("headers", headers),
		attribute.String("slotUID", headerSlotUID),
		attribute.Int64("receivedAt_ms", receivedAt.UnixMilli()),
		attribute.String("receivedAtUtc", formatUTCms(receivedAt)),
		attribute.String("sentAtUtc", sentAtUtc),
	)
	spanSetAttrs.End()

	preflight.SetAttributes(attribute.Int64("duration_us", time.Since(preflightStart).Microseconds()))
	preflight.End()

	_, spanBuildLogger := s.tracer.Start(ctx, GetSpanName(callerMethodName, "buildLogger"))
	// Logger with context
	log := s.logger.With().
		Str("reqHost", r.Host).
		Str("method", r.Method).
		Str("userAgent", userAgent).
		Str("clientIP", clientIP).
		Str("remoteAddr", r.RemoteAddr).
		Str("requestURI", r.RequestURI).
		Str("parsedURL", func() string {
			if parsedURL != nil {
				return parsedURL.String()
			}
			return ""
		}()).
		Str("validatorID", validatorID).
		Str("accountID", accountID).
		Str("authHeader", authHeader).
		Str("traceID", span.SpanContext().TraceID().String()).
		Str("getPayloadStartTimeUnixMS", boostSendTime).
		Int64("latency", latency).
		Str("cluster", cluster).
		Bool("sszRequest", sszRequest).
		Bool("sszResponse", sszResponse).
		Strs("headers", headers).
		Str("slotUID", headerSlotUID).
		Time("receivedAt", receivedAt).
		Str("receivedAtUtc", formatUTCms(receivedAt)).
		Str("sentAtUtc", sentAtUtc).
		Int64("maxBytes", maxGetPayloadBody).
		Int64("contentLength", r.ContentLength).
		Logger()
	spanBuildLogger.End()

	readStart := time.Now()
	_, spanRead := s.tracer.Start(ctx, GetSpanName(callerMethodName, "readBodyBytes"))
	bodyBytes, err := s.readAllPooledCtx(ctx, w, r, maxGetPayloadBody, bodyReadTimeoutGetPayload)
	spanRead.SetAttributes(attribute.Int64("duration_us", time.Since(readStart).Microseconds()))
	if err != nil {
		spanRead.SetStatus(codes.Error, err.Error())
		spanRead.End()

		log.Error().Err(err).Int64("bodyCap_ms", bodyReadTimeoutGetPayload.Milliseconds()).Msg("getPayload: read body failed")

		var mbe *http.MaxBytesError
		switch {
		case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
			respondError(ctx, span, getPayload, w, toErrorResp(http.StatusRequestTimeout, "request body read timeout"), &log, s.tracer)
		case errors.As(err, &mbe):
			respondError(ctx, span, getPayload, w, toErrorResp(http.StatusRequestEntityTooLarge, "body too large"), &log, s.tracer)
		default:
			respondError(ctx, span, getPayload, w, toErrorResp(http.StatusBadRequest, "failed to read getPayload body"), &log, s.tracer)
		}
		return
	}
	spanRead.End()

	// Prepare request (SSZ -> JSON canonicalization)
	if sszRequest {
		prepStart := time.Now()
		_, spanPrep := s.tracer.Start(ctx, GetSpanName(callerMethodName, "prepareRequest"))

		signedBlindedBeaconBlock := new(common.VersionedSignedBlindedBeaconBlock)

		_, spanDecode := s.tracer.Start(ctx, GetSpanName(callerMethodName, "decodeSSZ"))
		if err := signedBlindedBeaconBlock.UnmarshalSSZ(bodyBytes); err != nil {
			spanDecode.SetStatus(codes.Error, err.Error())
			spanDecode.End()
			spanPrep.SetStatus(codes.Error, "decodeSSZ failed")
			spanPrep.SetAttributes(attribute.Int64("duration_us", time.Since(prepStart).Microseconds()))
			spanPrep.End()

			log.Error().Err(err).Msg("failed to decode request payload")
			respondError(ctx, span, getPayload, w, toErrorResp(http.StatusInternalServerError, "failed to decode request payload"), &log, s.tracer)
			return
		}
		spanDecode.End()

		_, spanEncode := s.tracer.Start(ctx, GetSpanName(callerMethodName, "encodeJSON"))
		b, err := signedBlindedBeaconBlock.MarshalJSON()
		if err != nil {
			spanEncode.SetStatus(codes.Error, err.Error())
			spanEncode.End()
			spanPrep.SetStatus(codes.Error, "encodeJSON failed")
			spanPrep.SetAttributes(attribute.Int64("duration_us", time.Since(prepStart).Microseconds()))
			spanPrep.End()

			log.Error().Err(err).Msg("failed to marshal to json")
			respondError(ctx, span, getPayload, w, toErrorResp(http.StatusInternalServerError, "failed to marshal to json"), &log, s.tracer)
			return
		}
		spanEncode.End()

		bodyBytes = b
		spanPrep.SetAttributes(attribute.Int64("duration_us", time.Since(prepStart).Microseconds()))
		spanPrep.End()
	}

	// -----------------------------
	// Service call (replace AddEvent with a real child span)
	// -----------------------------
	callStart := time.Now()
	_, spanSvc := s.tracer.Start(ctx, GetSpanName(callerMethodName, "svcGetPayload"))
	versionedPayloadInfo, err := s.svc.GetPayload(ctx, &log, &PayloadRequestParams{
		ReceivedAt:                receivedAt,
		Payload:                   bodyBytes,
		ClientIP:                  clientIP,
		AuthHeader:                authHeader,
		ValidatorID:               validatorID,
		AccountID:                 accountID,
		GetPayloadStartTimeUnixMS: boostSendTime,
		Cluster:                   cluster,
		UserAgent:                 userAgent,
		SlotUID:                   headerSlotUID,
	})
	spanSvc.SetAttributes(attribute.Int64("duration_us", time.Since(callStart).Microseconds()))
	if err != nil {
		spanSvc.SetStatus(codes.Error, err.Error())
	}
	spanSvc.End()

	// -----------------------------
	// mergeLogMetric
	// -----------------------------
	_, spanMerge := s.tracer.Start(ctx, GetSpanName(callerMethodName, "mergeLogMetric"))
	if err != nil {
		spanMerge.End()

		log.Error().Err(err).Msg("Error in GetPayload")
		span.SetAttributes(attribute.String("error", err.Error()))
		span.SetStatus(codes.Error, err.Error())
		respondError(ctx, span, getPayload, w, err, &log, s.tracer)
		return
	}
	spanMerge.End()

	// -----------------------------
	// Respond
	// -----------------------------
	if !sszResponse {
		if err := respondOK(ctx, span, getPayload, w, versionedPayloadInfo.GetResponse(), &log, s.tracer, true); err == nil {
			success = true
		}
		return
	}

	// SSZ response path
	_, spanMarshal := s.tracer.Start(ctx, GetSpanName(callerMethodName, "marshalUnmarshal"))
	payloadResponse := new(common.VersionedSubmitBlindedBlockResponse)
	if err := payloadResponse.UnmarshalJSON(versionedPayloadInfo.GetResponse()); err != nil {
		spanMarshal.SetStatus(codes.Error, err.Error())
		spanMarshal.End()

		log.Error().Err(err).Msg("failed to unmarshal getHeader response")
		respondError(ctx, span, getPayload, w, toErrorResp(http.StatusInternalServerError, err.Error()), &log, s.tracer)
		return
	}
	outByte, err := payloadResponse.MarshalSSZ()
	if err != nil {
		spanMarshal.SetStatus(codes.Error, err.Error())
		spanMarshal.End()

		log.Error().Err(err).Msg("failed to marshal getHeader to ssz")
		// Fallback to JSON
		if err := respondOK(ctx, span, getPayload, w, versionedPayloadInfo.GetResponse(), &log, s.tracer, true); err == nil {
			success = true
		}
		return
	}
	spanMarshal.End()

	w.Header().Set(common.HeaderEthConsensusVersion, payloadResponse.Version.String())
	success = s.respondOKWithContextSSZMarshalled(ctx, span, getPayload, w, outByte, &log, s.tracer)
}

func (s *Server) HandleGetPayloadV2(w http.ResponseWriter, r *http.Request) {

	const callerMethodName = "handleGetPayloadV2"

	receivedAt := time.Now().UTC()
	success := false
	defer func() {
		s.performanceStats.SetEndpointStats(
			common.PathGetPayloadV2,
			uint64(time.Since(receivedAt).Microseconds()),
			success,
			100)
	}()

	// Keep inbound request context for deadlines/cancellation/metadata.
	ctx := r.Context()

	// Start a root span for this handler.
	ctx, span := s.tracer.Start(ctx, GetSpanName(callerMethodName, "START"))
	defer span.End()

	// Request-scoped metadata
	clientIP, _ := ctx.Value(keyClientIP).(string)
	parsedURL, _ := ctx.Value(keyParsedURL).(*url.URL)
	authHeader, _ := ctx.Value(keyAuthHeader).(string)
	validatorID, _ := ctx.Value(keyOrgID).(string)
	accountID, _ := ctx.Value(keyAccountID).(string)

	mevBoostSendTimeUnixMS := r.Header.Get(MEVBoostStartTimeUnixMS)
	commitBoostSendTimeUnixMS := r.Header.Get(HeaderDateMilliseconds)
	headerSlotUID := r.Header.Get(HeaderKeySlotUID)
	boostSendTime, sentAtUtc, latency := getBoostSendTimeAndLatency(receivedAt, mevBoostSendTimeUnixMS, commitBoostSendTimeUnixMS)
	cluster := r.Header.Get(VouchCluster)
	userAgent := r.Header.Get("User-Agent")

	// Collect headers (cheap)
	headers := make([]string, 0, len(r.Header))
	for k, v := range r.Header {
		if len(v) > 0 {
			headers = append(headers, k+"="+v[0])
		}
	}

	// Determine request/response content type expectations
	sszRequest, sszResponse := common.ParseBuilderContentType(r)

	log := s.logger.With().
		Str("reqHost", r.Host).
		Str("method", r.Method).
		Str("userAgent", userAgent).
		Str("clientIP", clientIP).
		Str("remoteAddr", r.RemoteAddr).
		Str("requestURI", r.RequestURI).
		Str("parsedURL", parsedURL.String()).
		Str("validatorID", validatorID).
		Str("accountID", accountID).
		Str("authHeader", authHeader).
		Str("traceID", span.SpanContext().TraceID().String()).
		Str("getPayloadStartTimeUnixMS", boostSendTime).
		Int64("latency", latency).
		Str("cluster", cluster).
		Bool("sszRequest", sszRequest).
		Bool("sszResponse", sszResponse).
		Strs("headers", headers).
		Str("slotUID", headerSlotUID).
		Time("receivedAt", receivedAt).
		Str("receivedAtUtc", formatUTCms(receivedAt)).
		Str("sentAtUtc", sentAtUtc).
		Logger()

	span.SetAttributes(
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
		attribute.String("slotUID", headerSlotUID),
		attribute.Int64("receivedAt", receivedAt.UnixMilli()),
		attribute.String("receivedAtUtc", formatUTCms(receivedAt)),
		attribute.String("sentAtUtc", sentAtUtc),
	)

	// --- read body
	_, readBodyBytesSpan := s.tracer.Start(ctx, GetSpanName(callerMethodName, "readBodyBytes"))
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		readBodyBytesSpan.SetStatus(codes.Error, err.Error())
		log.Error().Err(err).Msg("could not read getPayload")
		respondError(ctx, span, getPayloadV2, w, toErrorResp(http.StatusInternalServerError, "could not read getPayload"), &log, s.tracer)
		readBodyBytesSpan.End()
		return
	}
	readBodyBytesSpan.End()

	// --- decode SSZ if needed, then canonicalize to JSON for service
	signedBlindedBeaconBlock := new(common.VersionedSignedBlindedBeaconBlock)
	if sszRequest {
		_, decodeSSZSpan := s.tracer.Start(ctx, GetSpanName(callerMethodName, "decodeSSZ"))
		if err := signedBlindedBeaconBlock.UnmarshalSSZ(bodyBytes); err != nil {
			decodeSSZSpan.SetStatus(codes.Error, err.Error())
			log.Error().Err(err).Msg("failed to decode request payload")
			decodeSSZSpan.End()
			respondError(ctx, span, getPayloadV2, w, toErrorResp(http.StatusInternalServerError, "failed to decode request payload"), &log, s.tracer)
			return
		}
		decodeSSZSpan.End()

		_, encodeJSONSpan := s.tracer.Start(ctx, GetSpanName(callerMethodName, "encodeJSON"))
		b, err := signedBlindedBeaconBlock.MarshalJSON()
		if err != nil {
			encodeJSONSpan.SetStatus(codes.Error, err.Error())
			log.Error().Err(err).Msg("failed to marshal to json")
			encodeJSONSpan.End()
			respondError(ctx, span, getPayloadV2, w, toErrorResp(http.StatusInternalServerError, "failed to marshal to json"), &log, s.tracer)
			return
		}
		encodeJSONSpan.End()
		bodyBytes = b
	}

	span.AddEvent("handleGetPayload-svcGetPayloadV2")

	err = s.svc.GetPayloadV2(ctx, &log, &PayloadRequestParams{
		ReceivedAt:                receivedAt,
		Payload:                   bodyBytes,
		ClientIP:                  clientIP,
		AuthHeader:                authHeader,
		ValidatorID:               validatorID,
		AccountID:                 accountID,
		GetPayloadStartTimeUnixMS: boostSendTime,
		Cluster:                   cluster,
		UserAgent:                 userAgent,
		SlotUID:                   headerSlotUID,
	})

	// need to confirm eth consensusVersion
	//w.Header().Set(common.HeaderEthConsensusVersion, payloadResponse.Version.String())
	success = respondStatusAccepted(ctx, span, getPayloadV2, w, &log, s.tracer)
}

func respondStatusAccepted(ctx context.Context, parentSpan trace.Span, method string, w http.ResponseWriter, log *zerolog.Logger, tracer trace.Tracer) bool {
	_, span := tracer.Start(ctx, "respondStatusAccepted-"+method)
	defer span.End()
	parentSpan.SetAttributes(
		attribute.Int("responseCode", http.StatusAccepted),
	)
	log.Info().Str("method", method).Msg(method + " succeeded")
	w.Header().Set(common.HeaderContentType, common.MediaTypeJSON)
	w.WriteHeader(http.StatusAccepted)
	return true
}

func respondOK(ctx context.Context, parentSpan trace.Span, method string, w http.ResponseWriter, response any, log *zerolog.Logger, tracer trace.Tracer, logMessage bool) error {
	_, span := tracer.Start(ctx, GetSpanName(method, "respondOK"))
	defer span.End()
	parentSpan.SetAttributes(
		attribute.Int("responseCode", 200),
	)

	w.Header().Set(common.HeaderContentType, common.MediaTypeJSON)

	if err := gjson.NewEncoder(w).Encode(response); err != nil {
		span.SetStatus(codes.Error, "couldn't write OK response")
		log.Error().Err(err).Msg("couldn't write OK response")
		http.Error(w, "", http.StatusInternalServerError)
		return err
	}
	if logMessage {
		log.Info().Str("method", method).Msg(method + " succeeded")
	}
	return nil
}

func respondError(ctx context.Context, parentSpan trace.Span, method string, w http.ResponseWriter, err error, log *zerolog.Logger, tracer trace.Tracer) {

	_, span := tracer.Start(ctx, GetSpanName(method, "respondError"))
	defer span.End()

	resp, ok := err.(*ErrorResp)
	parentSpan.SetAttributes(
		attribute.String("Err", err.Error()),
		attribute.Int("responseCode", resp.ErrorCode()),
	)
	if !ok {
		log.Error().Str("method", method).Err(err).Msg("failed to typecast error response")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		span.SetStatus(codes.Error, "failed to typecast error response")
		return
	}
	w.WriteHeader(resp.Code)
	log.Error().Str("method", method).Msg(method + " failed")
	if resp.Message != "" && resp.Code != http.StatusNoContent { // HTTP status "No Content" implies that no message body should be included in the response.
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			span.SetStatus(codes.Error, "couldn't write error response")
			log.Error().Str("method", method).Err(err).Msg("couldn't write error response")
			_, _ = w.Write([]byte(``))
			return
		}
	}
}
func GetProposerMevProtectQueryAny(parsedURL *url.URL, log *zerolog.Logger) (bool, error) {
	proposerMevProtectQuery := parsedURL.Query().Get("proposer_mev_protect")
	proposerMevProtect, err := parseQuery("proposer_mev_protect", proposerMevProtectQuery, log)
	if err != nil {
		return false, err
	}
	mevProtectQuery := parsedURL.Query().Get("mev_protect")
	mevProtect, parseErr := parseQuery("mev_protect", mevProtectQuery, log)
	if parseErr != nil {
		log.Error().Err(err).Msg("failed to parse mev_protect")
		return false, err
	}
	mevGuardQuery := parsedURL.Query().Get("mev_guard")
	mevGuard, parseErr := parseQuery("mev_guard", mevGuardQuery, log)
	if parseErr != nil {
		log.Error().Err(err).Msg("failed to parse mev_guard")
		return false, err
	}
	proposerMevGuardQuery := parsedURL.Query().Get("proposer_mev_guard")
	proposerMevGuard, parseErr := parseQuery("proposer_mev_guard", proposerMevGuardQuery, log)
	if parseErr != nil {
		log.Error().Err(err).Msg("failed to parse mev_guard")
		return false, err
	}
	return proposerMevProtect || mevProtect || mevGuard || proposerMevGuard, nil
}
func parseQuery(query string, value string, log *zerolog.Logger) (bool, error) {
	if value == "" {
		return false, nil
	}
	proposerMevProtect, err := strconv.ParseBool(value)
	if err != nil {
		log.With().Str("query", query).Str("value", value).Err(err).Str("reason", "failed to parse proposer-mev-protect, setting proposer-mev-protect to false by default")
	}
	return proposerMevProtect, err
}

func (s *Server) respondOKWithContextSSZMarshalled(ctx context.Context, parentSpan trace.Span, method string, w http.ResponseWriter, resBytes []byte, log *zerolog.Logger, tracer trace.Tracer) bool {
	_, span := tracer.Start(ctx, GetSpanName(method, "respondOKSSZ"))
	defer span.End()
	parentSpan.SetAttributes(
		attribute.Int("responseCode", 200),
	)

	w.Header().Set(common.HeaderContentType, common.MediaTypeOctetStream)

	_, writeHeaderSpan := s.tracer.Start(ctx, "writeHeader")
	w.WriteHeader(http.StatusOK)
	writeHeaderSpan.End()

	_, writeBytesSpan := s.tracer.Start(ctx, "writeBytes")
	_, err := w.Write(resBytes)
	writeBytesSpan.End()
	if err != nil {
		span.SetStatus(codes.Error, "couldn't write OK response")
		log.Error().Str("method", method).Err(err).Msg("couldn't write error response")
		http.Error(w, "", http.StatusInternalServerError)
		return false
	}
	log.Info().Str("method", method).Msg(method + " succeeded")
	return true
}

// readAllPooledCtx reads r.Body fully with:
// - hard size cap via MaxBytesReader
// - per-call timeout via ctx (works for H1/H2)
// - pooled scratch buffer ([]byte) for fewer allocs
func (s *Server) readAllPooledCtx(ctx context.Context, w http.ResponseWriter, r *http.Request, max int64, timeout time.Duration) ([]byte, error) {
	// Hard cap
	r.Body = http.MaxBytesReader(w, r.Body, max)

	// Deadline for the read
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	type res struct {
		b   []byte
		err error
	}
	done := make(chan res, 1)

	go func() {
		defer r.Body.Close()

		var buf bytes.Buffer
		if r.ContentLength > 0 && r.ContentLength <= max {
			buf.Grow(int(r.ContentLength))
		}

		// === robust scratch buffer from pool
		scratch := s.getPayloadBodyPool.Get().([]byte)
		if len(scratch) == 0 {
			// safety: pool might hand back empty slice (or was never initialized)
			scratch = make([]byte, 64<<10) // 64 KiB
		}
		_, err := io.CopyBuffer(&buf, r.Body, scratch)

		// restore shape & return to pool
		if cap(scratch) > 0 {
			scratch = scratch[:cap(scratch)]
		}
		s.getPayloadBodyPool.Put(scratch)

		done <- res{b: buf.Bytes(), err: err}
	}()

	select {
	case r := <-done:
		return r.b, r.err

	case <-ctx.Done():
		// Abort the copy; Close() should unblock Read() on real http bodies.
		_ = r.Body.Close()

		// Give the goroutine a short grace period to finish after Close().
		select {
		case rr := <-done:
			// If the worker didn't see an error, surface the context timeout.
			if rr.err == nil {
				return rr.b, ctx.Err()
			}
			return nil, rr.err
		case <-time.After(1 * time.Second):
			// Defensive: if the underlying reader ignores Close(), return timeout.
			return nil, ctx.Err()
		}
	}
}
