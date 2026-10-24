package web

import (
	"encoding/json"
	"testing"
	"time"
)

func TestRelayAlertsRequireCurrentAdminAndCoherentReceipts(t *testing.T) {
	alert := RelayAlert{ID: "11111111-1111-4111-8111-111111111111", Kind: "unknown_proxy", Response: "alarm_only", ConfirmedAt: time.Now()}
	for _, test := range []struct {
		name, role string
		alerts     []RelayAlert
		status     int
		visible    bool
	}{
		{"admin", "admin", []RelayAlert{alert}, 200, true},
		{"member", "member", []RelayAlert{alert}, 200, false},
		{"duplicates", "admin", []RelayAlert{alert, alert}, 500, false},
		{"incoherent", "admin", []RelayAlert{{ID: alert.ID, Kind: "unknown_proxy", Response: "revoked", ConfirmedAt: alert.ConfirmedAt}}, 500, false},
		{"oversized", "admin", make([]RelayAlert, 101), 500, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, repository, _ := newFixture(t)
			cookie, _ := fixtureLogin(t, server)
			repository.mu.Lock()
			for key, record := range repository.sessions {
				record.User.Role = test.role
				repository.sessions[key] = record
			}
			repository.page.RelayAlerts = test.alerts
			repository.mu.Unlock()
			response := call(server, "GET", prefix+"/devices", "", cookie, nil)
			if response.Code != test.status {
				t.Fatalf("status %d", response.Code)
			}
			if response.Code == 200 {
				var page map[string]json.RawMessage
				if json.Unmarshal(response.Body.Bytes(), &page) != nil {
					t.Fatal("invalid inventory JSON")
				}
				_, present := page["relay_alerts"]
				if present != test.visible {
					t.Fatal("member projection leaked or admin alert disappeared")
				}
			}
		})
	}
}
