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
	"github.com/KazuhaHub/nethub/server/internal/guicert"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

const enrollPath = "/api/v1/devices/enroll"

type HTTPConfig struct {
	Origin         string
	TrustedProxies []netip.Prefix
	Logger         *slog.Logger
	Certificates   *CertificateService
	RelayTrust     *RelayTrustService
}

type HTTPServer struct {
	service      *Service
	origin       *auth.OriginPolicy
	clientIP     *clientip.Resolver
	logger       *slog.Logger
	host         string
	certificates *CertificateService
	relayTrust   *RelayTrustService
}

func NewHTTP(config HTTPConfig, service *Service) (*HTTPServer, error) {
	if service == nil || config.Logger == nil {
		return nil, errors.New("device service and logger are required")
	}
	if config.Certificates != nil && config.Certificates.lifecycle != service {
		return nil, ErrUnavailable
	}
	if config.RelayTrust != nil && config.RelayTrust.lifecycle != service {
		return nil, ErrUnavailable
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
	return &HTTPServer{service: service, certificates: config.Certificates, relayTrust: config.RelayTrust, origin: origin, clientIP: resolver,
		logger: config.Logger, host: strings.TrimSuffix(strings.ToLower(u.Host), ":443")}, nil
}

func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	if r.URL.Path == "/healthz" && r.URL.EscapedPath() == "/healthz" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			deviceError(w, r, 405, "method_not_allowed", "Method not allowed")
			return
		}
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.URL.RawQuery != "" || r.URL.ForceQuery {
			deviceError(w, r, 400, "invalid_request", "Invalid health request")
			return
		}
		if err := s.service.Health(r.Context()); err != nil || s.certificates != nil && s.certificates.Health(r.Context()) != nil || s.relayTrust != nil && s.relayTrust.Health(r.Context()) != nil {
			deviceError(w, r, 503, "unavailable", "Device service unavailable")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, "ok")
		}
		return
	}
	if strings.TrimSuffix(strings.ToLower(r.Host), ":443") != s.host {
		deviceError(w, r, 400, "invalid_request", "Unrecognized console host")
		return
	}
	lifecycle := r.URL.Path == "/api/v1/devices/status" || r.URL.Path == "/api/v1/devices/unenroll"
	certificate := s.certificates != nil && (r.URL.Path == "/api/v1/devices/gui-certificate/settings" || r.URL.Path == "/api/v1/devices/gui-certificate/request" || r.URL.Path == "/api/v1/devices/gui-certificate/issued" || r.URL.Path == "/api/v1/devices/gui-certificate/applied")
	trust := s.relayTrust != nil && (r.URL.Path == "/api/v1/devices/relay-trust/settings" || r.URL.Path == "/api/v1/devices/relay-trust/applied")
	if r.URL.EscapedPath() != r.URL.Path || r.URL.Path != enrollPath && !lifecycle && !certificate && !trust {
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
	if trust {
		s.trust(w, r, data, ip)
		return
	}
	if certificate {
		s.certificate(w, r, data, ip)
		return
	}
	if lifecycle {
		s.lifecycle(w, r, data, ip)
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

func (s *HTTPServer) trust(w http.ResponseWriter, r *http.Request, data []byte, ip netip.Addr) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || !protocol.ValidDeviceSecret(strings.TrimPrefix(values[0], "Bearer ")) {
		deviceError(w, r, 401, "device_authentication_failed", "Device authentication failed")
		return
	}
	secret := strings.TrimPrefix(values[0], "Bearer ")
	var result any
	var err error
	if r.URL.Path == "/api/v1/devices/relay-trust/settings" {
		var identity protocol.Identity
		identity, err = protocol.DecodeRelayTrustSettings(bytes.NewReader(data))
		if err == nil {
			result, err = s.relayTrust.Settings(r.Context(), identity, secret, ip)
		}
	} else {
		var input protocol.RelayTrustAppliedRequest
		input, err = protocol.DecodeRelayTrustApplied(bytes.NewReader(data))
		if err == nil {
			result, err = s.relayTrust.Applied(r.Context(), input, secret, ip)
		}
	}
	if errors.Is(err, ErrDenied) {
		deviceError(w, r, 401, "device_authentication_failed", "Device authentication failed")
		return
	}
	if errors.Is(err, relaytrust.ErrChanged) {
		deviceError(w, r, 409, "relay_trust_changed", "Relay trust changed; fetch current trust before reporting")
		return
	}
	if err != nil {
		s.failure(w, r, err)
		return
	}
	_ = json.NewEncoder(w).Encode(result)
}

func (s *HTTPServer) certificate(w http.ResponseWriter, r *http.Request, data []byte, ip netip.Addr) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || !protocol.ValidDeviceSecret(strings.TrimPrefix(values[0], "Bearer ")) {
		deviceError(w, r, 401, "device_authentication_failed", "Device authentication failed")
		return
	}
	secret := strings.TrimPrefix(values[0], "Bearer ")
	var result any
	var err error
	if r.URL.Path == "/api/v1/devices/gui-certificate/settings" {
		var identity protocol.Identity
		identity, err = protocol.DecodeCertificateSettings(bytes.NewReader(data))
		if err == nil {
			result, err = s.certificates.Settings(r.Context(), identity, secret, ip)
		}
	} else if r.URL.Path == "/api/v1/devices/gui-certificate/applied" {
		var input protocol.CertificateAppliedRequest
		input, err = protocol.DecodeCertificateApplied(bytes.NewReader(data))
		if err == nil {
			result, err = s.certificates.Applied(r.Context(), input, secret, ip)
		}
	} else if r.URL.Path == "/api/v1/devices/gui-certificate/issued" {
		var input protocol.CertificateIssuedRequest
		input, err = protocol.DecodeCertificateIssued(bytes.NewReader(data))
		if err == nil {
			result, err = s.certificates.Issued(r.Context(), input, secret, ip)
		}
	} else {
		var input protocol.CertificateSubmit
		input, err = protocol.DecodeCertificateSubmit(bytes.NewReader(data))
		if err == nil {
			result, err = s.certificates.Submit(r.Context(), input, secret, ip)
		}
	}
	if errors.Is(err, ErrDenied) {
		deviceError(w, r, 401, "device_authentication_failed", "Device authentication failed")
		return
	}
	if err != nil {
		s.failure(w, r, err)
		return
	}
	_ = json.NewEncoder(w).Encode(result)
}

func (s *HTTPServer) lifecycle(w http.ResponseWriter, r *http.Request, data []byte, ip netip.Addr) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || !protocol.ValidDeviceSecret(strings.TrimPrefix(values[0], "Bearer ")) {
		deviceError(w, r, 401, "device_authentication_failed", "Device authentication failed")
		return
	}
	secret := strings.TrimPrefix(values[0], "Bearer ")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var result any
	var err error
	if r.URL.Path == "/api/v1/devices/status" {
		var input protocol.StatusRequest
		input, err = protocol.DecodeStatus(bytes.NewReader(data))
		if err == nil {
			result, err = s.service.Report(ctx, input, secret, ip)
		}
	} else {
		var input protocol.Identity
		input, err = protocol.DecodeIdentity(bytes.NewReader(data))
		if err == nil {
			result, err = s.service.Unenroll(ctx, input, secret, ip)
		}
	}
	if errors.Is(err, ErrDenied) {
		deviceError(w, r, 401, "device_authentication_failed", "Device authentication failed")
		return
	}
	if err != nil {
		s.failure(w, r, err)
		return
	}
	_ = json.NewEncoder(w).Encode(result)
}

func (s *HTTPServer) failure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, protocol.ErrRelayTrustVersion):
		deviceError(w, r, 400, "incompatible_protocol", "Relay trust operations require protocol 1.5 or later within major 1")
	case errors.Is(err, protocol.ErrCertificateApplicationVersion):
		deviceError(w, r, 400, "incompatible_protocol", "Certificate application reports require protocol 1.4 or later within major 1")
	case errors.Is(err, protocol.ErrCertificateDeliveryVersion):
		deviceError(w, r, 400, "incompatible_protocol", "Certificate delivery requires protocol 1.3 or later within major 1")
	case errors.Is(err, protocol.ErrCertificateVersion):
		deviceError(w, r, 400, "incompatible_protocol", "Certificate requests require protocol 1.2 or later within major 1")
	case errors.Is(err, guicert.ErrRequest):
		deviceError(w, r, 400, "invalid_certificate_request", "Invalid device certificate request")
	case errors.Is(err, guicert.ErrConflict):
		deviceError(w, r, 409, "certificate_request_conflict", "Device certificate request already bound")
	case errors.Is(err, protocol.ErrIncompatibleVersion):
		deviceError(w, r, 400, "incompatible_protocol", "Unsupported device protocol; supported major is 1")
	case errors.Is(err, protocol.ErrInvalidRequest):
		deviceError(w, r, 400, "invalid_request", "Invalid device request")
	case errors.Is(err, ErrDenied):
		deviceError(w, r, 401, "enrollment_failed", "Enrollment failed")
	case errors.Is(err, ErrLimited):
		w.Header().Set("Retry-After", "60")
		deviceError(w, r, 429, "rate_limited", "Retry device request later")
	case errors.Is(err, ErrBusy):
		w.Header().Set("Retry-After", "1")
		deviceError(w, r, 429, "busy", "Retry device request later")
	default:
		// Never log request bodies, credentials, headers or dependency errors.
		s.logger.Error("Device API unavailable")
		deviceError(w, r, 503, "unavailable", "Device API unavailable")
	}
}

func deviceError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
	}
}
