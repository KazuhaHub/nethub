package device

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/clientip"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

const enrollPath = "/api/v1/devices/enroll"

type HTTPConfig struct {
	Origin         string
	TrustedProxies []netip.Prefix
	Logger         *slog.Logger
}

type HTTPServer struct {
	service  *Service
	origin   *auth.OriginPolicy
	clientIP *clientip.Resolver
	logger   *slog.Logger
	host     string
}

func NewHTTP(config HTTPConfig, service *Service) (*HTTPServer, error) {
	if service == nil || config.Logger == nil {
		return nil, errors.New("device service and logger are required")
	}
	origin, err := auth.NewOriginPolicy(config.Origin)
	if err != nil {
		return nil, err
	}
	resolver, err := clientip.New(config.TrustedProxies)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(config.Origin)
	return &HTTPServer{service: service, origin: origin, clientIP: resolver,
		logger: config.Logger, host: strings.TrimSuffix(strings.ToLower(u.Host), ":443")}, nil
}

func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	if strings.TrimSuffix(strings.ToLower(r.Host), ":443") != s.host {
		deviceError(w, r, 400, "invalid_request", "Unrecognized console host")
		return
	}
	if r.URL.Path != enrollPath || r.URL.EscapedPath() != enrollPath {
		deviceError(w, r, 404, "not_found", "Not found")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		deviceError(w, r, 405, "method_not_allowed", "Method not allowed")
		return
	}
	// Agents omit Origin. Browser callers must match the configured console.
	if !s.origin.Check(r, false) {
		deviceError(w, r, 403, "invalid_origin", "Unrecognized request origin")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		deviceError(w, r, 400, "invalid_request", "Query parameters are not accepted")
		return
	}
	ip, spoofed, err := s.clientIP.Resolve(r)
	if err != nil {
		deviceError(w, r, 400, "invalid_request", "Invalid client address")
		return
	}
	if spoofed {
		s.logger.Warn("Ignoring forwarding headers from an untrusted peer")
	}
	media, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(r.Header.Values("Content-Type")) != 1 ||
		parameters["charset"] != "" && !strings.EqualFold(parameters["charset"], "utf-8") ||
		len(r.Header.Values("Content-Encoding")) != 0 {
		deviceError(w, r, 415, "unsupported_media_type", "Use application/json with UTF-8 encoding")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, protocol.MaxBodyBytes))
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		deviceError(w, r, 413, "payload_too_large", "Request body exceeds 64 KiB")
		return
	}
	if err != nil {
		deviceError(w, r, 400, "invalid_request", "Invalid request body")
		return
	}
	input, err := protocol.DecodeEnroll(bytes.NewReader(data))
	if err != nil {
		s.failure(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	result, err := s.service.Enroll(ctx, input, ip)
	if err != nil {
		s.failure(w, r, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	// A lost response does not authorize replay of the consumed enrollment token.
	_ = json.NewEncoder(w).Encode(result)
}

func (s *HTTPServer) failure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, protocol.ErrIncompatibleVersion):
		deviceError(w, r, 400, "incompatible_protocol", "Unsupported device protocol; supported major is 1")
	case errors.Is(err, protocol.ErrInvalidRequest):
		deviceError(w, r, 400, "invalid_request", "Invalid device request")
	case errors.Is(err, ErrDenied):
		deviceError(w, r, 401, "enrollment_failed", "Enrollment failed")
	case errors.Is(err, ErrLimited):
		w.Header().Set("Retry-After", "60")
		deviceError(w, r, 429, "rate_limited", "Retry enrollment later")
	case errors.Is(err, ErrBusy):
		w.Header().Set("Retry-After", "1")
		deviceError(w, r, 429, "busy", "Retry enrollment later")
	default:
		// Never log request bodies, credentials, headers or dependency errors.
		s.logger.Error("Device enrollment unavailable")
		deviceError(w, r, 503, "unavailable", "Device enrollment unavailable")
	}
}

func deviceError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
	}
}
