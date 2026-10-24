package web

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDisconnectRequiresExplicitAuthenticatedMutation(t *testing.T) {
	for _, test := range []struct {
		name, method, path, body string
		cookie, csrf             bool
		failure                  error
		status                   int
	}{
		{"valid", "POST", "/devices/" + openDeviceID + "/disconnect", "{}", true, true, nil, 200},
		{"get", "GET", "/devices/" + openDeviceID + "/disconnect", "", true, true, nil, 405},
		{"anonymous", "POST", "/devices/" + openDeviceID + "/disconnect", "{}", false, false, nil, 401},
		{"csrf", "POST", "/devices/" + openDeviceID + "/disconnect", "{}", true, false, nil, 403},
		{"fields", "POST", "/devices/" + openDeviceID + "/disconnect", `{"device_id":"other"}`, true, true, nil, 400},
		{"active", "POST", "/devices/" + openDeviceID + "/disconnect", "{}", true, true, ErrDeviceNotRevoked, 409},
		{"foreign", "POST", "/devices/" + openDeviceID + "/disconnect", "{}", true, true, ErrDeviceUnavailable, 404},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, repo, _ := newFixture(t)
			cookie, session := fixtureLogin(t, server)
			repo.disconnect = DeviceDisconnect{RequestID: openDeviceID, RequestedAt: time.Now().UTC(), State: "pending"}
			repo.disconnectErr = test.failure
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
			if test.status < 400 && w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("request receipt cacheable")
			}
			if test.status == 401 || test.status == 403 || test.status == 405 || test.status == 400 {
				if repo.disconnected != 0 {
					t.Fatal("refused mutation reached request repository")
				}
			}
		})
	}
}
