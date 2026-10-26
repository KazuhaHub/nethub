package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/clientip"
	"github.com/KazuhaHub/nethub/server/internal/sso"
	"github.com/KazuhaHub/nethub/server/internal/webui"
)

const prefix = "/api/v1/console"

var hostnameLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type SSOBackend interface {
	Providers(context.Context) ([]sso.Choice, error)
	Start(context.Context, string, string) (sso.StartResult, error)
	Complete(ctx context.Context, slug, state, code, responseIssuer, browser string, ip netip.Addr, userAgent string) (auth.LoginResult, bool, error)
	Failed(context.Context, netip.Addr, string) error
}

type Config struct {
	Origin, DeviceDomain string
	TrustedProxies       []netip.Prefix
	Logger               *slog.Logger
	SSO                  SSOBackend
}

type Server struct {
	auth                                *auth.Service
	repository                          Repository
	origin                              *auth.OriginPolicy
	clientIP                            *clientip.Resolver
	logger                              *slog.Logger
	host, consoleHostname, deviceDomain string
	enrollLimits                        *auth.AttemptLimiter
	openLimits                          *auth.AttemptLimiter
	revokeLimits                        *auth.AttemptLimiter
	disconnectLimits                    *auth.AttemptLimiter
	inviteInspectLimits                 *auth.AttemptLimiter
	sso                                 SSOBackend
	ssoStartLimits, ssoCallbackLimits   *auth.AttemptLimiter
}

func New(config Config, service *auth.Service, repository Repository) (*Server, error) {
	if service == nil || repository == nil || config.Logger == nil {
		return nil, errors.New("console authentication, repository, and logger are required")
	}
	origin, err := auth.NewOriginPolicy(config.Origin)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(config.Origin)
	domain := strings.ToLower(config.DeviceDomain)
	if len(domain) > 253 || !strings.Contains(domain, ".") {
		return nil, errors.New("a device DNS domain is required")
	}
	for _, label := range strings.Split(domain, ".") {
		if !hostnameLabel.MatchString(label) {
			return nil, errors.New("invalid device DNS domain")
		}
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return nil, errors.New("device domain cannot be an IP address")
	}
	resolver, err := clientip.New(config.TrustedProxies)
	if err != nil {
		return nil, err
	}
	return &Server{auth: service, repository: repository, origin: origin, clientIP: resolver, logger: config.Logger,
		sso: config.SSO, ssoStartLimits: auth.NewAttemptLimiter(), ssoCallbackLimits: auth.NewAttemptLimiter(),
		host: strings.TrimSuffix(strings.ToLower(u.Host), ":443"), consoleHostname: strings.ToLower(u.Hostname()), deviceDomain: domain, enrollLimits: auth.NewAttemptLimiter(), openLimits: auth.NewAttemptLimiter(), revokeLimits: auth.NewAttemptLimiter(), disconnectLimits: auth.NewAttemptLimiter(), inviteInspectLimits: auth.NewAttemptLimiter()}, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if (r.Method == "GET" || r.Method == "HEAD") && (r.ContentLength != 0 || len(r.TransferEncoding) > 0) {
		writeError(w, r, 400, "invalid_request", "Read requests do not accept a body")
		return
	}
	if r.URL.Path == "/healthz" {
		if !allowMethod(w, r, "GET") {
			return
		}
		if err := s.repository.Health(ctx); err != nil {
			s.internal(w, r, "health")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.Method != "HEAD" {
			w.Write([]byte("ok"))
		}
		return
	}
	if strings.TrimSuffix(strings.ToLower(r.Host), ":443") != s.host {
		writeError(w, r, 400, "invalid_request", "Unrecognized console host")
		return
	}
	ip, spoof, err := s.clientIP.Resolve(r)
	if err != nil {
		writeError(w, r, 400, "invalid_request", "Invalid client address")
		return
	}
	if spoof {
		s.logger.Warn("Ignoring forwarding headers from an untrusted peer")
	}
	switch r.URL.Path {
	case prefix + "/login":
		if allowMethod(w, r, "POST") {
			s.login(w, r, ip)
		}
	case prefix + "/session":
		if allowMethod(w, r, "GET") {
			s.session(w, r)
		}
	case prefix + "/logout":
		if allowMethod(w, r, "POST") {
			s.logout(w, r, ip)
		}
	case prefix + "/devices":
		if allowMethod(w, r, "GET") {
			s.devices(w, r)
		}
	case prefix + "/users":
		if allowMethod(w, r, "GET") {
			s.users(w, r)
		}
	case prefix + "/oidc/providers":
		if allowMethod(w, r, "GET") {
			s.loginProviders(w, r)
		}
	case prefix + "/oidc-providers":
		switch r.Method {
		case "GET", "HEAD":
			s.oidcProviders(w, r)
		case "POST":
			s.createOIDCProvider(w, r, ip)
		default:
			w.Header().Set("Allow", "GET, HEAD, POST")
			writeError(w, r, 405, "method_not_allowed", "Method not allowed")
		}
	case prefix + "/saml-providers":
		switch r.Method {
		case "GET", "HEAD":
			s.samlProviders(w, r)
		case "POST":
			s.createSAMLProvider(w, r, ip)
		default:
			w.Header().Set("Allow", "GET, HEAD, POST")
			writeError(w, r, 405, "method_not_allowed", "Method not allowed")
		}
	case prefix + "/invites/inspect":
		if allowMethod(w, r, "POST") {
			s.inspectInvitation(w, r, ip)
		}
	case prefix + "/invites/accept":
		if allowMethod(w, r, "POST") {
			s.acceptInvitation(w, r, ip)
		}
	case prefix + "/invites":
		switch r.Method {
		case "GET", "HEAD":
			s.invitations(w, r)
		case "POST":
			s.issueInvitation(w, r, ip)
		default:
			w.Header().Set("Allow", "GET, HEAD, POST")
			writeError(w, r, 405, "method_not_allowed", "Method not allowed")
		}
	case prefix + "/enroll-tokens":
		if allowMethod(w, r, "POST") {
			s.enroll(w, r, ip)
		}
	default:
		if strings.HasPrefix(r.URL.Path, prefix+"/saml/") {
			s.samlMetadata(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, prefix+"/saml-providers/") {
			switch r.Method {
			case "PATCH", "DELETE":
				s.mutateSAMLProvider(w, r, ip)
			default:
				w.Header().Set("Allow", "PATCH, DELETE")
				writeError(w, r, 405, "method_not_allowed", "Method not allowed")
			}
			return
		}
		if strings.HasPrefix(r.URL.Path, prefix+"/oidc/") {
			s.oidcBrowser(w, r, ip)
			return
		}
		if strings.HasPrefix(r.URL.Path, prefix+"/oidc-providers/") {
			switch r.Method {
			case "PATCH", "DELETE":
				s.mutateOIDCProvider(w, r, ip)
			default:
				w.Header().Set("Allow", "PATCH, DELETE")
				writeError(w, r, 405, "method_not_allowed", "Method not allowed")
			}
			return
		}
		if strings.HasPrefix(r.URL.Path, prefix+"/invites/") {
			if allowMethod(w, r, "DELETE") {
				s.withdrawInvitation(w, r, ip)
			}
			return
		}
		if strings.HasPrefix(r.URL.Path, prefix+"/users/") {
			if allowMethod(w, r, "PATCH") {
				s.updateUser(w, r, ip)
			}
			return
		}
		if strings.HasPrefix(r.URL.Path, prefix+"/devices/") && strings.HasSuffix(r.URL.Path, "/disconnect") {
			if allowMethod(w, r, "POST") {
				s.requestDisconnect(w, r, ip)
			}
			return
		}
		if strings.HasPrefix(r.URL.Path, prefix+"/devices/") && strings.HasSuffix(r.URL.Path, "/revoke") {
			if allowMethod(w, r, "POST") {
				s.revokeDevice(w, r, ip)
			}
			return
		}
		if strings.HasPrefix(r.URL.Path, prefix+"/devices/") && strings.HasSuffix(r.URL.Path, "/open") {
			if allowMethod(w, r, "POST") {
				s.openDevice(w, r, ip)
			}
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeError(w, r, 404, "not_found", "Not found")
		} else {
			webui.Handler().ServeHTTP(w, r)
		}
	}
}

func allowMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method || method == "GET" && r.Method == "HEAD" {
		return true
	}
	allow := method
	if method == "GET" {
		allow = "GET, HEAD"
	}
	w.Header().Set("Allow", allow)
	writeError(w, r, 405, "method_not_allowed", "Method not allowed")
	return false
}

func (s *Server) internal(w http.ResponseWriter, r *http.Request, operation string) {
	// Never log bodies, cookie/header values, tokens, or raw database errors.
	s.logger.Error("Console operation failed", "operation", operation)
	writeError(w, r, 500, "internal", "The request could not be completed")
}
