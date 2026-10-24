package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/clientip"
)

const openDeviceID = "f8721195-53c9-4528-93cd-3f9be56974c1"

func TestExplicitOpenUsesResolvedSourceAndAssignedURL(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		t.Run(map[bool]string{false: "ignored spoof", true: "trusted IPv6 proxy"}[trusted], func(t *testing.T) {
			server, repository, _ := newFixture(t)
			cookie, session := fixtureLogin(t, server)
			expires := time.Now().UTC().Add(30 * time.Minute)
			repository.access = DeviceAccess{Subdomain: "branch", ExpiresAt: expires}
			r := httptest.NewRequest("POST", "https://console.example.com"+prefix+"/devices/"+openDeviceID+"/open", strings.NewReader(`{}`))
			r.RemoteAddr = "192.0.2.100:1234"
			if trusted {
				resolver, err := clientip.New([]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
				if err != nil {
					t.Fatal(err)
				}
				server.clientIP = resolver
				r.RemoteAddr = "127.0.0.1:1234"
			}
			r.Header.Set("X-Forwarded-For", "2001:db8::1")
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", "https://console.example.com")
			r.Header.Set("X-CSRF-Token", session.CSRFToken)
			r.AddCookie(cookie)
			response := httptest.NewRecorder()
			server.ServeHTTP(response, r)
			wantIP := netip.MustParseAddr("192.0.2.100")
			if trusted {
				wantIP = netip.MustParseAddr("2001:db8::1")
			}
			var result DeviceAccess
			if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.URL != "https://branch.router.example.com:8443" || !result.ExpiresAt.Equal(expires) || repository.opened != 1 || repository.openID != openDeviceID || repository.lastIP != wantIP {
				t.Fatal("explicit access did not bind the actor's resolved source and assigned destination")
			}
			if strings.Contains(response.Body.String(), "subdomain") || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("access response exposed internal routing state or allowed caching")
			}
		})
	}
}

func TestExplicitOpenRejectsForgedInputsBeforeGrant(t *testing.T) {
	for name, input := range map[string]struct {
		method, path, body, origin, csrf string
		signedIn                         bool
		status                           int
	}{
		"unsigned":    {"POST", "", `{}`, "https://console.example.com", "valid", false, 401},
		"CSRF":        {"POST", "", `{}`, "https://console.example.com", "wrong", true, 403},
		"origin":      {"POST", "", `{}`, "https://foreign.example.com", "valid", true, 403},
		"IP body":     {"POST", "", `{"source_ip":"203.0.113.1"}`, "https://console.example.com", "valid", true, 400},
		"expiry body": {"POST", "", `{"expires_at":"2099-01-01"}`, "https://console.example.com", "valid", true, 400},
		"IP query":    {"POST", "?source_ip=203.0.113.1", `{}`, "https://console.example.com", "valid", true, 400},
		"GET":         {"GET", "", ``, "https://console.example.com", "valid", true, 405},
		"HEAD":        {"HEAD", "", ``, "https://console.example.com", "valid", true, 405},
	} {
		t.Run(name, func(t *testing.T) {
			server, repository, _ := newFixture(t)
			cookie, session := fixtureLogin(t, server)
			if !input.signedIn {
				cookie = nil
			}
			csrf := input.csrf
			if csrf == "valid" {
				csrf = session.CSRFToken
			}
			r := call(server, input.method, prefix+"/devices/"+openDeviceID+"/open"+input.path, input.body, cookie, map[string]string{"Origin": input.origin, "Content-Type": "application/json", "X-CSRF-Token": csrf})
			if r.Code != input.status || repository.opened != 0 {
				t.Fatal("rejected access request changed the grant", r.Code)
			}
		})
	}
}

func TestExplicitOpenUnavailableAndUnsafeDestination(t *testing.T) {
	for _, failure := range []error{ErrDeviceUnavailable, ErrDeviceRevoked, auth.ErrUnauthenticated, errors.New("private database diagnostic")} {
		server, repository, _ := newFixture(t)
		cookie, session := fixtureLogin(t, server)
		repository.openErr = failure
		r := call(server, "POST", prefix+"/devices/"+openDeviceID+"/open", `{}`, cookie, map[string]string{"Origin": "https://console.example.com", "Content-Type": "application/json", "X-CSRF-Token": session.CSRFToken})
		want := 500
		if errors.Is(failure, ErrDeviceUnavailable) {
			want = 404
		}
		if errors.Is(failure, auth.ErrUnauthenticated) {
			want = 401
		}
		if errors.Is(failure, ErrDeviceRevoked) {
			want = 409
		}
		if r.Code != want || strings.Contains(r.Body.String(), "private database diagnostic") {
			t.Fatal("access failure leaked protected state")
		}
	}
	for _, subdomain := range []string{"", "../foreign", "branch:443", "console.router.example.com"} {
		server, repository, _ := newFixture(t)
		cookie, session := fixtureLogin(t, server)
		repository.access = DeviceAccess{Subdomain: subdomain, ExpiresAt: time.Now().Add(time.Minute)}
		r := call(server, http.MethodPost, prefix+"/devices/"+openDeviceID+"/open", `{}`, cookie, map[string]string{"Origin": "https://console.example.com", "Content-Type": "application/json", "X-CSRF-Token": session.CSRFToken})
		if r.Code != 500 {
			t.Fatal("invalid assigned destination became an open redirect")
		}
	}
}

func TestExplicitOpenRequiresCanonicalIDAndBoundsAttempts(t *testing.T) {
	server, repository, _ := newFixture(t)
	cookie, session := fixtureLogin(t, server)
	headers := map[string]string{"Origin": "https://console.example.com", "Content-Type": "application/json", "X-CSRF-Token": session.CSRFToken}
	for _, id := range []string{"invalid", strings.ToUpper(openDeviceID), openDeviceID + "/extra"} {
		if r := call(server, "POST", prefix+"/devices/"+id+"/open", `{}`, cookie, headers); r.Code != 400 || repository.opened != 0 {
			t.Fatal("malformed device ID reached the grant operation")
		}
	}
	repository.access = DeviceAccess{Subdomain: "branch", ExpiresAt: time.Now().Add(30 * time.Minute)}
	for range 5 {
		if r := call(server, "POST", prefix+"/devices/"+openDeviceID+"/open", `{}`, cookie, headers); r.Code != 200 {
			t.Fatal("legitimate explicit open refused", r.Code)
		}
	}
	r := call(server, "POST", prefix+"/devices/"+openDeviceID+"/open", `{}`, cookie, headers)
	if r.Code != 429 || r.Header().Get("Retry-After") == "" || repository.opened != 5 {
		t.Fatal("excess requests continued renewing database grants")
	}
}
