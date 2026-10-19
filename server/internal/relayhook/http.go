// Package relayhook authorizes the relay's internal HTTP callbacks.
package relayhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/boundedjson"
	"github.com/KazuhaHub/nethub/server/internal/claim"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

const Path = "/api/v1/frp/hooks"
const Budget = 500 * time.Millisecond

var ErrDenied = errors.New("relay identity denied")
var ErrUnavailable = errors.New("relay authorization unavailable")

type Repository interface {
	Authorize(context.Context, protocol.ClaimPayload) error
}

type Config struct {
	Peers  []netip.Addr
	Logger *slog.Logger
}

type Server struct {
	peers      map[netip.Addr]bool
	logger     *slog.Logger
	signer     *claim.Keyring
	repository Repository
	workers    chan struct{}
}

func New(config Config, repository Repository, signer *claim.Keyring) (*Server, error) {
	if config.Logger == nil || repository == nil || signer == nil || len(config.Peers) == 0 || len(config.Peers) > 16 {
		return nil, errors.New("relay callback peers, logger, repository and signer are required")
	}
	peers := make(map[netip.Addr]bool, len(config.Peers))
	for _, peer := range config.Peers {
		if !peer.IsValid() || peer.IsUnspecified() || peer.IsMulticast() || peer.Zone() != "" {
			return nil, errors.New("relay callback peers must be exact IP addresses")
		}
		peers[peer.Unmap()] = true
	}
	return &Server{peers: peers, repository: repository, signer: signer,
		logger: config.Logger, workers: make(chan struct{}, 64)}, nil
}

type response struct {
	Reject       bool   `json:"reject"`
	RejectReason string `json:"reject_reason,omitempty"`
	Unchange     bool   `json:"unchange,omitempty"`
}

func (s *Server) respond(w http.ResponseWriter, status int, operation, decision string) {
	result := response{Reject: decision != "allowed", Unchange: decision == "allowed"}
	if result.Reject {
		result.RejectReason = "not_authorized"
		if decision == "unavailable" || decision == "busy" {
			result.RejectReason = "unavailable"
		}
	}
	// Both fields are selected from fixed codes, never request or dependency text.
	s.logger.Info("Relay hook decision", "operation", operation, "decision", decision)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(result)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	deadline := time.Now().Add(Budget)
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(deadline)
	_ = controller.SetWriteDeadline(deadline.Add(Budget))
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	peer, parseError := netip.ParseAddr(host)
	if err != nil || parseError != nil || peer.Zone() != "" || !s.peers[peer.Unmap()] {
		s.respond(w, 403, "unknown", "untrusted_peer")
		return
	}
	if r.URL.Path != Path || r.URL.EscapedPath() != Path {
		s.respond(w, 404, "unknown", "invalid_request")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		s.respond(w, 405, "unknown", "invalid_request")
		return
	}
	select {
	case s.workers <- struct{}{}:
		defer func() { <-s.workers }()
	default:
		s.respond(w, 200, "unknown", "busy")
		return
	}
	media, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(r.Header.Values("Content-Type")) != 1 ||
		parameters["charset"] != "" && !strings.EqualFold(parameters["charset"], "utf-8") || len(r.Header.Values("Content-Encoding")) != 0 {
		s.respond(w, 200, "unknown", "invalid_request")
		return
	}
	object, err := boundedjson.Object(http.MaxBytesReader(w, r.Body, boundedjson.MaxBytes))
	if err != nil {
		s.respond(w, 200, "unknown", "invalid_request")
		return
	}
	operation, ok := text(object, "op")
	if !ok || operation != "Login" && operation != "NewProxy" {
		s.respond(w, 200, "unknown", "invalid_request")
		return
	}
	version, ok := text(object, "version")
	query, err := url.ParseQuery(r.URL.RawQuery)
	if !ok || version != "0.1.0" || err != nil || len(query) != 2 ||
		len(query["op"]) != 1 || query.Get("op") != operation ||
		len(query["version"]) != 1 || query.Get("version") != version {
		s.respond(w, 200, operation, "invalid_request")
		return
	}
	content, ok := nested(object, "content")
	if !ok {
		s.respond(w, 200, operation, "invalid_request")
		return
	}
	identity := content
	if operation == "NewProxy" {
		identity, ok = nested(content, "user")
		if !ok {
			s.respond(w, 200, operation, "invalid_request")
			return
		}
	}
	metas, ok := nested(identity, "metas")
	deviceID, idOK := text(metas, "device_id")
	encodedClaim, claimOK := text(metas, "domain_claim")
	if !ok || !idOK || !claimOK {
		s.respond(w, 200, operation, "invalid_claim")
		return
	}
	payload, err := s.signer.Verify(encodedClaim)
	if err != nil || payload.DeviceID != deviceID {
		s.respond(w, 200, operation, "invalid_claim")
		return
	}
	if operation == "NewProxy" && !proxyAllowed(content, payload.Subdomain) {
		s.respond(w, 200, operation, "proxy_policy")
		return
	}
	if ctx.Err() != nil {
		s.respond(w, 200, operation, "unavailable")
		return
	}
	err = s.repository.Authorize(ctx, payload)
	if err != nil || ctx.Err() != nil {
		decision := "unavailable"
		if errors.Is(err, ErrDenied) && ctx.Err() == nil {
			decision = "device_denied"
		}
		s.respond(w, 200, operation, decision)
		return
	}
	s.respond(w, 200, operation, "allowed")
}

func text(object map[string]json.RawMessage, key string) (string, bool) {
	var value string
	data, ok := object[key]
	if !ok || bytes.Equal(bytes.TrimSpace(data), []byte("null")) || json.Unmarshal(data, &value) != nil {
		return "", false
	}
	return value, true
}

func nested(object map[string]json.RawMessage, key string) (map[string]json.RawMessage, bool) {
	var value map[string]json.RawMessage
	data, ok := object[key]
	if !ok || json.Unmarshal(data, &value) != nil || value == nil {
		return nil, false
	}
	return value, true
}

func proxyAllowed(content map[string]json.RawMessage, assigned string) bool {
	proxyType, typeOK := text(content, "proxy_type")
	subdomain, domainOK := text(content, "subdomain")
	if !typeOK || !domainOK || proxyType != "https" || subdomain != assigned {
		return false
	}
	if data, present := content["custom_domains"]; present {
		var domains []string
		if json.Unmarshal(data, &domains) != nil || len(domains) != 0 {
			return false
		}
	}
	// Shared load-balancing groups are outside the single-device route contract.
	for _, key := range []string{"group", "group_key"} {
		if _, present := content[key]; present {
			if value, ok := text(content, key); !ok || value != "" {
				return false
			}
		}
	}
	return true
}
