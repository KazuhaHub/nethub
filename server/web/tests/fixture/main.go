// Standalone, loopback-only UI test fixture. Never linked into the product CLI.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/web"
)

type repository struct {
	mu         sync.Mutex
	hash       string
	sessions   map[string]auth.SessionRecord
	populated  bool
	shortToken bool
	revoked    bool
	disconnect *web.DeviceDisconnect
	alerts     []web.RelayAlert
}

func (r *repository) PasswordCandidate(_ context.Context, email string) (auth.Candidate, error) {
	if email != "ui-test@example.com" {
		return auth.Candidate{}, auth.ErrInvalidCredentials
	}
	return auth.Candidate{User: auth.User{ID: "00000000-0000-4000-8000-000000000001", Email: email, Role: "admin"}, PasswordHash: r.hash}, nil
}
func (r *repository) CreateSession(_ context.Context, c auth.Candidate, record auth.SessionRecord) (auth.SessionRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record.User = c.User
	r.sessions[string(record.TokenHash)] = record
	return record, nil
}
func (r *repository) LookupSession(_ context.Context, digest []byte, _ time.Duration) (auth.SessionRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, ok := r.sessions[string(digest)]
	if !ok {
		return auth.SessionRecord{}, auth.ErrUnauthenticated
	}
	return record, nil
}
func (r *repository) DeleteSession(_ context.Context, digest []byte, _ netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, string(digest))
	return nil
}
func (r *repository) LookupSessionPassive(ctx context.Context, digest []byte, idle time.Duration) (auth.SessionRecord, error) {
	return r.LookupSession(ctx, digest, idle)
}
func (r *repository) Health(context.Context) error                  { return nil }
func (r *repository) LoginFailed(context.Context, netip.Addr) error { return nil }
func (r *repository) Devices(_ context.Context, _ string, query web.DeviceQuery) (web.DevicePage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	page := web.DevicePage{Items: []web.Device{}, RelayAlerts: append([]web.RelayAlert(nil), r.alerts...)}
	if !r.populated {
		return page, nil
	}
	for i, name := range []string{"Branch office", "Home firewall", "Lab gateway"} {
		online := i != 1
		isRevoked := i == 0 && r.revoked
		if query.Online != nil && online != *query.Online || query.Revoked != nil && *query.Revoked != isRevoked {
			continue
		}
		now := time.Now().UTC()
		host := []string{"branch", "home", "lab"}[i] + ".router.example.com"
		until := now.Add(24 * time.Hour)
		certificate := web.GUICertificateStatus{State: "applied", AssignedHost: &host, ValidUntil: &until, ConfirmedAt: &now}
		if i == 2 {
			certificate = web.GUICertificateStatus{State: "pending"}
		}
		page.Items = append(page.Items, web.Device{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1), Label: name, Hostname: name, Subdomain: []string{"branch", "home", "lab"}[i], Platform: "opnsense", Online: online, LastSeenAt: &now, EnrolledAt: now, Owner: web.Owner{ID: "fixture", Email: "ui-test@example.com"}, Capabilities: []string{"remote.web"}, GUICertificate: certificate})
		page.Items[len(page.Items)-1].Revoked = isRevoked
		if i == 0 && r.disconnect != nil {
			value := *r.disconnect
			page.Items[len(page.Items)-1].Disconnect = &value
		}
	}
	return page, nil
}
func (r *repository) OpenDevice(_ context.Context, _, id string, _ netip.Addr) (web.DeviceAccess, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revoked {
		return web.DeviceAccess{}, web.ErrDeviceRevoked
	}
	if id != "00000000-0000-4000-8000-000000000001" {
		return web.DeviceAccess{}, web.ErrDeviceUnavailable
	}
	return web.DeviceAccess{Subdomain: "branch", ExpiresAt: time.Now().Add(30 * time.Minute)}, nil
}

func (r *repository) RevokeDevice(_ context.Context, _, id string, _ netip.Addr) (web.DeviceRevocation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id != "00000000-0000-4000-8000-000000000001" {
		return web.DeviceRevocation{}, web.ErrDeviceUnavailable
	}
	r.revoked = true
	return web.DeviceRevocation{Revoked: true, RevokedAt: time.Now().UTC()}, nil
}

func (r *repository) RequestDisconnect(_ context.Context, _, id string, _ netip.Addr) (web.DeviceDisconnect, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id != "00000000-0000-4000-8000-000000000001" {
		return web.DeviceDisconnect{}, web.ErrDeviceUnavailable
	}
	if !r.revoked {
		return web.DeviceDisconnect{}, web.ErrDeviceNotRevoked
	}
	if r.disconnect == nil {
		r.disconnect = &web.DeviceDisconnect{RequestID: "00000000-0000-4000-8000-000000000099", RequestedAt: time.Now().UTC(), State: "pending"}
	}
	return *r.disconnect, nil
}

func (r *repository) IssueEnrollToken(context.Context, string, netip.Addr) (web.EnrollToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return web.EnrollToken{}, err
	}
	ttl := 15 * time.Minute
	if r.shortToken {
		ttl = 2 * time.Second
	}
	return web.EnrollToken{Token: base64.RawURLEncoding.EncodeToString(raw), ExpiresAt: time.Now().Add(ttl)}, nil
}

func main() {
	if os.Getenv("NETHUB_UI_FIXTURE") != "1" {
		panic("UI fixture must be explicitly enabled")
	}
	hash, err := auth.HashPassword("isolated UI fixture passphrase")
	if err != nil {
		panic(err)
	}
	repository := &repository{hash: hash, sessions: map[string]auth.SessionRecord{}}
	service, err := auth.NewService(repository, auth.Config{})
	if err != nil {
		panic(err)
	}
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	handler, err := web.New(web.Config{Origin: origin, DeviceDomain: "router.example.com", Logger: slog.New(slog.NewJSONHandler(os.Stderr, nil))}, service, repository)
	if err != nil {
		panic(err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && len(r.URL.Path) > 6 && r.URL.Path[:6] == "/test/" {
			repository.mu.Lock()
			defer repository.mu.Unlock()
			switch r.URL.Path {
			case "/test/expire":
				repository.sessions = map[string]auth.SessionRecord{}
			case "/test/devices":
				repository.populated = true
			case "/test/short-token":
				repository.shortToken = true
			case "/test/disconnect-armed":
				if repository.disconnect == nil {
					http.Error(w, "not requested", 409)
					return
				}
				now := time.Now().UTC()
				repository.disconnect.ArmedAt = &now
				repository.disconnect.State = "armed"
			case "/test/relay-alerts":
				home := "00000000-0000-4000-8000-000000000002"
				branch := "00000000-0000-4000-8000-000000000001"
				now := time.Now().UTC()
				repository.alerts = []web.RelayAlert{
					{ID: "11111111-1111-4111-8111-111111111111", DeviceID: &home, Kind: "domain_mismatch", Response: "alarm_only", ConfirmedAt: now},
					{ID: "22222222-2222-4222-8222-222222222222", Kind: "unknown_proxy", Response: "alarm_only", ConfirmedAt: now},
					{ID: "33333333-3333-4333-8333-333333333333", DeviceID: &branch, Kind: "revoked_online", Response: "already_revoked", ConfirmedAt: now},
				}
			case "/test/member", "/test/admin":
				role := "member"
				if r.URL.Path == "/test/admin" {
					role = "admin"
				}
				for key, record := range repository.sessions {
					record.User.Role = role
					repository.sessions[key] = record
				}
			default:
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(204)
			return
		}
		handler.ServeHTTP(w, r)
	})
	server.StartTLS()
	defer server.Close()
	json.NewEncoder(os.Stdout).Encode(map[string]string{"origin": origin})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	if errors.Is(ctx.Err(), context.Canceled) {
		return
	}
}
