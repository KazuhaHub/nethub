package web

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func (f *fixtureRepository) Traffic(_ context.Context, _ string, query TrafficQuery) (TrafficPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.trafficReads++
	f.trafficQuery = query
	page := f.trafficPage
	if page.Month == "" {
		page = TrafficPage{Month: query.Month, InBytes: "0", OutBytes: "0", TotalBytes: "0", ResetEvents: "0", Items: []TrafficDevice{}}
	}
	return page, f.trafficErr
}

func (f *fixtureRepository) SetTrafficWarning(_ context.Context, _ string, value string, _ int64, _ netip.Addr) (TrafficWarning, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.trafficWrites++
	return TrafficWarning{WarningBytes: &value, Revision: 1}, f.trafficErr
}

func TestTrafficReportRequiresLiveAdministratorAndExactValues(t *testing.T) {
	server, repository, logs := newFixture(t)
	cookie, _ := fixtureLogin(t, server)
	if response := call(server, "GET", prefix+"/traffic", "", nil, nil); response.Code != 401 {
		t.Fatal("anonymous traffic report was available")
	}
	if response := call(server, "GET", prefix+"/traffic", "", cookie, nil); response.Code != 403 || repository.trafficReads != 0 {
		t.Fatal("member reached tenant traffic repository")
	}
	for key, session := range repository.sessions {
		session.Role = "admin"
		repository.sessions[key] = session
	}
	repository.trafficPage = TrafficPage{Month: "2026-10", InBytes: "9223372036854775807", OutBytes: "9223372036854775807", TotalBytes: "18446744073709551614", ResetEvents: "0", Items: []TrafficDevice{}}
	threshold := "18446744073709551613"
	repository.trafficPage.WarningBytes = &threshold
	repository.trafficPage.WarningRevision = 1
	response := call(server, "GET", prefix+"/traffic?month=2026-10&limit=1", "", cookie, nil)
	var page TrafficPage
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &page) != nil || page.TotalBytes != "18446744073709551614" || !page.Warning || page.WarningBytes == nil {
		t.Fatal("wide monthly totals or warning lost exactness")
	}
	if repository.trafficQuery.Month != "2026-10" || repository.trafficQuery.Limit != 1 {
		t.Fatal("traffic query lost explicit month or pagination")
	}
	before := repository.trafficReads
	for _, query := range []string{"?month=2026-1", "?month=0000-01", "?month=2026-13", "?month=2026-10&month=2026-09", "?limit=0", "?limit=201", "?cursor=not-a-cursor", "?tenant_id=foreign"} {
		if value := call(server, "GET", prefix+"/traffic"+query, "", cookie, nil); value.Code != 400 || repository.trafficReads != before {
			t.Fatal("invalid traffic query reached storage", query)
		}
	}
	repository.trafficPage.TotalBytes = "18446744073709552000"
	if value := call(server, "GET", prefix+"/traffic?month=2026-10", "", cookie, nil); value.Code != 500 || strings.Contains(value.Body.String(), "184467") {
		t.Fatal("inconsistent traffic projection was exposed")
	}
	if strings.Contains(logs.String(), "922337") {
		t.Fatal("traffic diagnostics exposed stored values")
	}
}

func TestTrafficWarningMutationIsExplicitAndConflictAware(t *testing.T) {
	server, repository, _ := newFixture(t)
	cookie, session := fixtureLogin(t, server)
	headers := map[string]string{"Content-Type": "application/json", "Origin": "https://console.example.com", "X-CSRF-Token": session.CSRFToken}
	body := `{"warning_bytes":"1000","expected_revision":0}`
	if response := call(server, "PATCH", prefix+"/traffic/settings", body, cookie, headers); response.Code != 403 || repository.trafficWrites != 0 {
		t.Fatal("member changed the tenant warning")
	}
	for key, value := range repository.sessions {
		value.Role = "admin"
		repository.sessions[key] = value
	}
	withoutCSRF := map[string]string{"Content-Type": "application/json", "Origin": "https://console.example.com"}
	if response := call(server, "PATCH", prefix+"/traffic/settings", body, cookie, withoutCSRF); response.Code != 403 || repository.trafficWrites != 0 {
		t.Fatal("warning mutation omitted CSRF")
	}
	for _, bad := range []string{`{}`, `{"warning_bytes":null,"expected_revision":0}`, `{"warning_bytes":"01","expected_revision":0}`, `{"warning_bytes":"1"}`, `{"warning_bytes":"1","expected_revision":-1}`, `{"warning_bytes":"1","expected_revision":0,"tenant_id":"other"}`} {
		if response := call(server, "PATCH", prefix+"/traffic/settings", bad, cookie, headers); response.Code != 400 || repository.trafficWrites != 0 {
			t.Fatal("invalid traffic setting reached storage")
		}
	}
	repository.trafficErr = ErrTrafficChanged
	if response := call(server, "PATCH", prefix+"/traffic/settings", body, cookie, headers); response.Code != 409 || !strings.Contains(response.Body.String(), `"traffic_changed"`) {
		t.Fatal("warning revision conflict was not explicit")
	}
	repository.trafficErr = nil
	if response := call(server, "PATCH", prefix+"/traffic/settings", body, cookie, headers); response.Code != 200 || !strings.Contains(response.Body.String(), `"warning_bytes":"1000"`) {
		t.Fatal("explicit warning mutation did not return the narrow setting")
	}
}
