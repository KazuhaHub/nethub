package web

import (
	"errors"
	"github.com/KazuhaHub/nethub/server/internal/auth"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRevocationRequiresExplicitAuthenticatedMutation(t *testing.T) {
	for _, test := range []struct {
		name, method, path, body string
		cookie, csrf             bool
		status                   int
	}{
		{"valid", "POST", "/devices/" + openDeviceID + "/revoke", "{}", true, true, 200},
		{"get", "GET", "/devices/" + openDeviceID + "/revoke", "", true, true, 405},
		{"anonymous", "POST", "/devices/" + openDeviceID + "/revoke", "{}", false, false, 401},
		{"csrf", "POST", "/devices/" + openDeviceID + "/revoke", "{}", true, false, 403},
		{"foreign-fields", "POST", "/devices/" + openDeviceID + "/revoke", `{"actor":"other"}`, true, true, 400},
		{"query", "POST", "/devices/" + openDeviceID + "/revoke?tenant=x", "{}", true, true, 400},
		{"id", "POST", "/devices/invalid/revoke", "{}", true, true, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, repository, _ := newFixture(t)
			cookie, session := fixtureLogin(t, server)
			repository.revocation = DeviceRevocation{Revoked: true, RevokedAt: time.Now().UTC()}
			r := httptest.NewRequest(test.method, "https://console.example.com"+prefix+test.path, strings.NewReader(test.body))
			r.RemoteAddr = "192.0.2.10:1234"
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", "https://console.example.com")
			if test.cookie {
				r.AddCookie(cookie)
			}
			if test.csrf {
				r.Header.Set("X-CSRF-Token", session.CSRFToken)
			}
			w := httptest.NewRecorder()
			server.ServeHTTP(w, r)
			if w.Code != test.status {
				t.Fatalf("status %d, want %d", w.Code, test.status)
			}
			if (repository.revoked == 1) != (test.status == 200) {
				t.Fatal("refused request reached revocation repository")
			}
			if test.status == 200 && w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("revocation response cacheable")
			}
		})
	}
}

func TestRevocationMapsAuthorityFailuresAndBoundsAttempts(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
	}{{ErrDeviceUnavailable, 404}, {auth.ErrUnauthenticated, 401}, {errors.New("private database diagnostic"), 500}} {
		server, repository, _ := newFixture(t)
		cookie, session := fixtureLogin(t, server)
		repository.revokeErr = test.err
		r := httptest.NewRequest("POST", "https://console.example.com"+prefix+"/devices/"+openDeviceID+"/revoke", strings.NewReader(`{}`))
		r.RemoteAddr = "192.0.2.10:1234"
		r.AddCookie(cookie)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://console.example.com")
		r.Header.Set("X-CSRF-Token", session.CSRFToken)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		if w.Code != test.status || strings.Contains(w.Body.String(), "private database") {
			t.Fatal("revocation authority error mapping leaked or changed status", w.Code)
		}
	}
	server, repository, _ := newFixture(t)
	cookie, session := fixtureLogin(t, server)
	repository.revocation = DeviceRevocation{Revoked: true, RevokedAt: time.Now().UTC()}
	for attempt := 0; attempt < 6; attempt++ {
		r := httptest.NewRequest("POST", "https://console.example.com"+prefix+"/devices/"+openDeviceID+"/revoke", strings.NewReader(`{}`))
		r.RemoteAddr = "192.0.2.10:1234"
		r.AddCookie(cookie)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://console.example.com")
		r.Header.Set("X-CSRF-Token", session.CSRFToken)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		want := 200
		if attempt == 5 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("attempt %d returned %d, want %d", attempt, w.Code, want)
		}
	}
	if repository.revoked != 5 {
		t.Fatal("rate-limited revocation reached storage")
	}
}
