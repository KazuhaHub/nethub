package store

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAuditDetailsProjectsOnlyTypedNonsecretFields(t *testing.T) {
	raw := []byte(`{"target_user_id":"00000000-0000-4000-8000-000000000001","role":"member","disabled":false,"sessions_revoked":2,"request_id":"00000000-0000-4000-8000-000000000002","expires_at":"2026-11-12T01:00:00+01:00","source_ip":"private-source-sentinel","secret":"private-secret-sentinel","entry_hash":"private-hash-sentinel","metadata":"private-metadata-sentinel"}`)
	details := auditDetails(raw)
	encoded, err := json.Marshal(details)
	if err != nil || details.TargetUserID == nil || details.Disabled == nil || *details.Disabled || details.SessionsRevoked == nil || *details.SessionsRevoked != 2 || details.ExpiresAt == nil || details.ExpiresAt.Hour() != 0 {
		t.Fatal("valid typed audit details were lost")
	}
	if strings.Contains(string(encoded), "sentinel") {
		t.Fatal("unlisted audit fields escaped the safe projection")
	}
	for _, raw := range []string{`{`, `{"disabled":null,"sessions_revoked":null}`, `{"target_user_id":"secret","role":"secret","disabled":"secret","sessions_revoked":-1,"expires_at":"secret","request_id":"secret"}`, strings.Repeat("x", 1025)} {
		encoded, err := json.Marshal(auditDetails([]byte(raw)))
		if err != nil || string(encoded) != "{}" {
			t.Fatal("malformed private payload did not produce empty safe details")
		}
	}
}
