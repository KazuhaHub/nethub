package relayprobe

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func tokenProbeCredential() LoginCredential {
	return LoginCredential{Token: strings.Repeat("a", 64), DeviceID: "12345678-1234-4123-8123-123456789abc", DomainClaim: "private-synthetic-claim"}
}

func tokenProbeMessage(credential LoginCredential, users chan<- string) func([]byte) bool {
	return func(raw []byte) bool {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || len(fields) != 5 || bytes.Contains(raw, []byte(credential.Token)) {
			return false
		}
		var login struct {
			Version, User, PrivilegeKey string
			Timestamp                   int64
			Metas                       map[string]string
		}
		if json.Unmarshal(fields["version"], &login.Version) != nil || json.Unmarshal(fields["user"], &login.User) != nil ||
			json.Unmarshal(fields["privilege_key"], &login.PrivilegeKey) != nil || json.Unmarshal(fields["timestamp"], &login.Timestamp) != nil ||
			json.Unmarshal(fields["metas"], &login.Metas) != nil {
			return false
		}
		if login.Version != ProtocolVersion || !regexp.MustCompile(`^nethub-token-probe-[a-f0-9-]{36}$`).MatchString(login.User) ||
			len(login.Metas) != 2 || login.Metas["device_id"] != credential.DeviceID || login.Metas["domain_claim"] != credential.DomainClaim ||
			login.Timestamp < time.Now().Add(-5*time.Second).Unix() || login.Timestamp > time.Now().Add(time.Second).Unix() {
			return false
		}
		sum := md5.Sum([]byte(credential.Token + strconv.FormatInt(login.Timestamp, 10)))
		if login.PrivilegeKey != hex.EncodeToString(sum[:]) {
			return false
		}
		if users != nil {
			users <- login.User
		}
		return true
	}
}

func TestTokenLoginUsesOneFreshControlWithoutProxyOrRawToken(t *testing.T) {
	credential := tokenProbeCredential()
	users := make(chan string, 8)
	for _, test := range []struct {
		name, response string
		accepted       bool
		valid          bool
	}{
		{"accepted", `{"version":"0.71.1","run_id":"0123456789abcdef"}`, true, true},
		{"token refused", `{"version":"0.71.1","error":"token in login doesn't match token from configuration"}`, false, true},
		{"policy refused", `{"version":"0.71.1","error":"not_authorized"}`, false, false},
		{"ambiguous error", `{"version":"0.71.1","error":"register control error"}`, false, false},
		{"mixed result", `{"version":"0.71.1","run_id":"0123456789abcdef","error":"token in login doesn't match token from configuration"}`, false, false},
		{"wrong version", `{"version":"0.71.2","run_id":"0123456789abcdef"}`, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			address, ca, done := loginFixture(t, '1', uint64(len(test.response)), test.response, false, tokenProbeMessage(credential, users))
			accepted, err := LoginToken(context.Background(), address, "127.0.0.1", ca, credential)
			if (err == nil) != test.valid || accepted != test.accepted {
				t.Fatal("unexpected closed admission result")
			}
			select {
			case valid := <-done:
				if !valid {
					t.Fatal("Login sent unexpected credential fields or additional messages")
				}
			case <-time.After(4 * time.Second):
				t.Fatal("token probe fixture did not stop")
			}
		})
	}
	close(users)
	seen := map[string]bool{}
	for user := range users {
		if seen[user] {
			t.Fatal("a probe reused its client identity")
		}
		seen[user] = true
	}
	if len(seen) != 6 {
		t.Fatal("probe identity receipt missing")
	}
}

func TestTokenLoginRejectsAmbiguousOrUnboundedReplies(t *testing.T) {
	for _, raw := range []string{
		`{}`, `null`, `[]`, `{"version":"0.71.1","run_id":"short"}`,
		`{"version":"0.71.1","version":"0.71.1","run_id":"0123456789abcdef"}`,
		`{"version":"0.71.1","run_id":null}`,
		`{"version":"0.71.1","run_id":"0123456789abcdef","private":"must-not-escape"}`,
		`{"version":"0.71.1","run_id":"0123456789abcdef"}{}`,
		strings.Repeat(" ", 4097) + `{"version":"0.71.1","run_id":"0123456789abcdef"}`,
	} {
		if accepted, err := tokenLoginResult([]byte(raw)); err != ErrProbe || accepted {
			t.Fatal("ambiguous Login reply was accepted")
		}
	}
}

func TestTokenCredentialFormattingAndErrorsDoNotDiscloseMaterial(t *testing.T) {
	credential := tokenProbeCredential()
	raw, err := json.Marshal(credential)
	if err != nil || string(raw) != "{}" {
		t.Fatal("credential JSON is not private")
	}
	for _, rendered := range []string{fmt.Sprintf("%v", credential), fmt.Sprintf("%+v", credential), fmt.Sprintf("%#v", credential)} {
		for _, value := range []string{credential.Token, credential.DeviceID, credential.DomainClaim} {
			if strings.Contains(rendered, value) {
				t.Fatal("credential formatting disclosed material")
			}
		}
	}
	for _, change := range []string{"token", "device", "claim", "oversized"} {
		bad := credential
		switch change {
		case "token":
			bad.Token = "private-invalid-token"
		case "device":
			bad.DeviceID = "private-invalid-device"
		case "claim":
			bad.DomainClaim = "private\nclaim"
		case "oversized":
			bad.DomainClaim = strings.Repeat("x", 3117)
		}
		if accepted, err := LoginToken(context.Background(), "127.0.0.1:1", "test.invalid", []byte("invalid"), bad); err != ErrProbe || accepted {
			t.Fatal("invalid credential did not return the fixed refusal")
		}
	}
}

func TestTokenLoginRequiresTrustedTLSAndHonorsCancellation(t *testing.T) {
	credential := tokenProbeCredential()
	address, ca, done := loginFixture(t, '1', 0, "", false, tokenProbeMessage(credential, nil))
	if accepted, err := LoginToken(context.Background(), address, "wrong.invalid", ca, credential); err != ErrProbe || accepted {
		t.Fatal("wrong-hostname TLS was accepted")
	}
	select {
	case sent := <-done:
		if sent {
			t.Fatal("untrusted TLS received a credential")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("wrong-hostname fixture did not stop")
	}
	address, ca, done = loginFixture(t, '1', 0, "", true, tokenProbeMessage(credential, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if accepted, err := LoginToken(ctx, address, "127.0.0.1", ca, credential); err != ErrProbe || accepted || time.Since(started) > 2*time.Second {
		t.Fatal("stalled Login ignored cancellation")
	}
	select {
	case valid := <-done:
		if !valid {
			t.Fatal("cancellation fixture did not receive the bounded Login")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("cancelled Login fixture did not stop")
	}
}
