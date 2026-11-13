package web

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func (f *fixtureRepository) Audit(context.Context, string, AuditQuery) (AuditPage, error) {
	return AuditPage{Items: []AuditEntry{}}, nil
}

type auditFixtureRepository struct {
	*fixtureRepository
	page AuditPage
	err  error
}

func (f *auditFixtureRepository) Audit(context.Context, string, AuditQuery) (AuditPage, error) {
	return f.page, f.err
}

func TestAuditCursorBindsAuthorityAndFiltersWithoutRoundingSequence(t *testing.T) {
	query := AuditQuery{Limit: 50, Action: "user.updated"}
	const sequence int64 = 9223372036854775807
	query.Cursor = AuditCursor("tenant:actor", query, sequence)
	if got, err := AuditBefore("tenant:actor", query); err != nil || got != sequence {
		t.Fatal("exact sequence did not survive the opaque cursor")
	}
	query.Limit = 1
	if _, err := AuditBefore("tenant:actor", query); err != nil {
		t.Fatal("page-size change invalidated an otherwise identical query")
	}
	if _, err := AuditBefore("other-tenant:actor", query); err == nil {
		t.Fatal("cross-tenant cursor was accepted")
	}
	if _, err := AuditBefore("tenant:other-actor", query); err == nil {
		t.Fatal("cross-actor cursor was accepted")
	}
	query.Action = "auth.login"
	if _, err := AuditBefore("tenant:actor", query); err == nil {
		t.Fatal("changed-filter cursor was accepted")
	}
	for _, raw := range []string{"1:x:0", "1:x:-1", "1:x:01", "1:x:9223372036854775808"} {
		query.Cursor = base64.RawURLEncoding.EncodeToString([]byte(raw))
		if _, err := AuditBefore("tenant:actor", query); err == nil {
			t.Fatal("invalid cursor was accepted")
		}
	}
}

func TestAuditHTTPQueryValidationAndAuthentication(t *testing.T) {
	server, _, _ := newFixture(t)
	if response := call(server, "GET", prefix+"/audit", "", nil, nil); response.Code != 401 {
		t.Fatal("anonymous audit read was available")
	}
	cookie, _ := fixtureLogin(t, server)
	for _, query := range []string{"limit=0", "limit=201", "limit=01", "limit=2&limit=2", "tenant_id=other", "action=", "action=%0A", "device_id=invalid", "since=bad", "since=2026-11-12T00:00:00Z&until=2026-11-11T00:00:00Z"} {
		if response := call(server, "GET", prefix+"/audit?"+query, "", cookie, nil); response.Code != 400 {
			t.Fatalf("invalid audit query returned %d", response.Code)
		}
	}
	if response := call(server, "GET", prefix+"/audit?user_id=00000000-0000-4000-8000-000000000001", "", cookie, nil); response.Code != 403 {
		t.Fatal("member used administrator-only actor filter")
	}
	if response := call(server, "GET", prefix+"/audit", "", cookie, nil); response.Code != 200 || !strings.Contains(response.Body.String(), `"items":[]`) {
		t.Fatal("authenticated empty audit response was not a stable page")
	}
	if response := call(server, "POST", prefix+"/audit", "{}", cookie, nil); response.Code != 405 {
		t.Fatal("audit endpoint accepted a write method")
	}
}

func TestAuditQueryRejectsEmptyOrReversedTimeWindow(t *testing.T) {
	now := time.Now().UTC()
	query := AuditQuery{Limit: 1, Since: &now, Until: &now}
	if query.Valid() {
		t.Fatal("empty time window was accepted")
	}
}

func TestAuditMemberResponseDoesNotExposeAnotherActorsAddress(t *testing.T) {
	server, repository, _ := newFixture(t)
	cookie, _ := fixtureLogin(t, server)
	own, other, ip := "fixture", "other-actor", "192.0.2.123"
	report := &auditFixtureRepository{fixtureRepository: repository, page: AuditPage{Items: []AuditEntry{
		{ActorType: "user", Actor: &own, ClientIP: &ip},
		{ActorType: "user", Actor: &other, ClientIP: &ip},
		{ActorType: "device", Actor: &own, ClientIP: &ip},
		{ActorType: "system", ClientIP: &ip},
	}}}
	server.repository = report
	response := call(server, "GET", prefix+"/audit", "", cookie, nil)
	if response.Code != 200 || strings.Count(response.Body.String(), ip) != 1 {
		t.Fatal("member address projection crossed actor-type or actor ownership")
	}
	report.err = ErrAuditInput
	if response := call(server, "GET", prefix+"/audit", "", cookie, nil); response.Code != 400 {
		t.Fatal("mismatched stored cursor was not a bounded client error")
	}
}
