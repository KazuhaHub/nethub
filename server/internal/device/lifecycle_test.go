package device

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

type lifecycleRepository struct {
	fakeRepository
	credential                 Credential
	err                        error
	revoked                    bool
	lookups, reports, removals atomic.Int32
}

func (f *lifecycleRepository) DeviceCredential(context.Context, string) (Credential, error) {
	f.lookups.Add(1)
	return f.credential, f.err
}
func (f *lifecycleRepository) ReportDevice(context.Context, Credential, protocol.StatusRequest) (bool, error) {
	f.reports.Add(1)
	return f.revoked, nil
}
func (f *lifecycleRepository) UnenrollDevice(context.Context, Credential, protocol.Identity, netip.Addr) error {
	f.removals.Add(1)
	return nil
}

func TestLifecycleHTTPAuthenticationAndSelection(t *testing.T) {
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{41}, 32))
	hash, err := auth.HashPassword(secret)
	if err != nil {
		t.Fatal(err)
	}
	identity := protocol.Identity{AgentProtocolVersion: protocol.Version, DeviceID: "12345678-1234-1234-1234-123456789abc"}
	for _, path := range []string{"status", "unenroll"} {
		t.Run(path, func(t *testing.T) {
			repository := &lifecycleRepository{credential: Credential{TenantID: "fixture", Hash: hash}}
			service := fixtureService(t, repository)
			var log bytes.Buffer
			handler := testHTTP(t, service, &log)
			body := map[string]any{"agent_protocol_version": protocol.Version, "device_id": identity.DeviceID}
			if path == "status" {
				for k, v := range map[string]any{"platform_version": "fixture", "agent_version": "0.0.4", "service_state": "running", "last_reconcile_success": nil, "last_reconcile_at": nil} {
					body[k] = v
				}
			}
			post := func(authorization string, extra bool) *httptest.ResponseRecorder {
				data, _ := json.Marshal(body)
				r := requestHTTP(string(data))
				r.URL.Path = "/api/v1/devices/" + path
				r.Header.Set("Authorization", authorization)
				if extra {
					r.Header.Add("Authorization", authorization)
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			for _, value := range []string{"", "Basic " + secret, "Bearer " + strings.Repeat("a", 43), "Bearer " + secret + " "} {
				if w := post(value, false); w.Code != 401 {
					t.Fatalf("credential rejection status=%d", w.Code)
				}
			}
			if w := post("Bearer "+secret, true); w.Code != 401 {
				t.Fatal("repeated authorization accepted")
			}
			w := post("Bearer "+secret, false)
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d", w.Code)
			}
			var response map[string]any
			if json.Unmarshal(w.Body.Bytes(), &response) != nil || response["device_id"] != identity.DeviceID {
				t.Fatal("invalid public acknowledgement")
			}
			if path == "status" && repository.reports.Load() != 1 || path == "unenroll" && repository.removals.Load() != 1 {
				t.Fatal("wrong mutation count")
			}
			repository.err = ErrDenied
			if w := post("Bearer "+secret, false); w.Code != 401 {
				t.Fatal("unknown device accepted")
			}
			repository.err = errors.New("database private diagnostic " + secret)
			if w := post("Bearer "+secret, false); w.Code != 503 {
				t.Fatal("database failure accepted")
			}
			if strings.Contains(log.String(), secret) || strings.Contains(w.Body.String(), secret) {
				t.Fatal("credentials exposed")
			}
		})
	}
}

func TestLifecycleAdmissionIsBoundedAndSeparate(t *testing.T) {
	s := fixtureService(t, &fakeRepository{})
	now := s.now()
	ip := netip.MustParseAddr("192.0.2.25")
	for range 120 {
		if err := s.admitLifecycle(ip, now); err != nil {
			t.Fatal(err)
		}
	}
	if !errors.Is(s.admitLifecycle(ip, now), ErrLimited) {
		t.Fatal("lifecycle admission unbounded")
	}
	if err := s.admit(ip, now); err != nil {
		t.Fatal("reports consumed enrollment budget")
	}
}
