package claim

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

func fixtureKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func fixturePayload() protocol.ClaimPayload {
	return protocol.ClaimPayload{DeviceID: "11111111-1111-4111-8111-111111111111", Subdomain: "test1234",
		TenantID: "22222222-2222-4222-8222-222222222222", IssuedAt: "2026-10-18T00:00:00.000001Z", KeyID: "initial"}
}

func fixtureRing(t testing.TB) *Keyring {
	t.Helper()
	ring, err := New("initial", map[string][]byte{"initial": fixtureKey()})
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

func fixtureToken(t testing.TB, ring *Keyring) string {
	t.Helper()
	payload := fixturePayload()
	issued, _ := time.Parse(timestampLayout, payload.IssuedAt)
	token, err := ring.Issue(payload.DeviceID, payload.Subdomain, payload.TenantID, issued)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// Reference encoder for intentionally malformed, but correctly signed payloads.
func signedJSON(data []byte, key []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString(data)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestGoldenSignatureAndSharedPayload(t *testing.T) {
	// Generated independently with Python's json/base64/hmac/hashlib standard library.
	const expected = "eyJkZXZpY2VfaWQiOiIxMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTEiLCJzdWJkb21haW4iOiJ0ZXN0MTIzNCIsInRlbmFudF9pZCI6IjIyMjIyMjIyLTIyMjItNDIyMi04MjIyLTIyMjIyMjIyMjIyMiIsImlzc3VlZF9hdCI6IjIwMjYtMTAtMThUMDA6MDA6MDAuMDAwMDAxWiIsImtleV9pZCI6ImluaXRpYWwifQ._0D21BoMfSR-iaLv8aMTl3Ui2fGjVQV8XwSgj4f_844"
	ring := fixtureRing(t)
	if token := fixtureToken(t, ring); token != expected {
		t.Fatal("signature differs from the independent known-answer vector")
	}
	got, err := ring.Verify(expected)
	if err != nil || got != fixturePayload() {
		t.Fatalf("valid claim rejected: %v", err)
	}
	data, err := os.ReadFile("../../../proto/examples/valid/domain-claim.json")
	var shared protocol.ClaimPayload
	if err != nil || json.Unmarshal(data, &shared) != nil || shared != got {
		t.Fatal("signed payload differs from the shared protocol example")
	}
}

func TestEveryPayloadFieldAndSignatureAreAuthenticated(t *testing.T) {
	ring := fixtureRing(t)
	token := fixtureToken(t, ring)
	parts := strings.Split(token, ".")
	data, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var payload map[string]string
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"device_id", "subdomain", "tenant_id", "issued_at", "key_id"} {
		changed := make(map[string]string)
		for key, value := range payload {
			changed[key] = value
		}
		changed[field] += "x"
		encoded, _ := json.Marshal(changed)
		mutated := base64.RawURLEncoding.EncodeToString(encoded) + "." + parts[1]
		if _, err := ring.Verify(mutated); !errors.Is(err, ErrInvalid) {
			t.Fatalf("tampered %s accepted", field)
		}
	}
	if _, err := ring.Verify(parts[0] + ".A" + parts[1][1:]); !errors.Is(err, ErrInvalid) {
		t.Fatal("tampered signature accepted")
	}
}

func TestRejectCorrectlySignedNoncanonicalOrInvalidPayloads(t *testing.T) {
	ring := fixtureRing(t)
	canonical, _ := json.Marshal(fixturePayload())
	value := string(canonical)
	var fields map[string]string
	if err := json.Unmarshal(canonical, &fields); err != nil {
		t.Fatal(err)
	}
	reordered, _ := json.Marshal(fields)
	cases := map[string]string{
		"leading_space": " " + value,
		"reordered":     string(reordered),
		"unknown":       strings.TrimSuffix(value, "}") + `,"other":true}`,
		"duplicate":     strings.TrimSuffix(value, "}") + `,"device_id":"11111111-1111-4111-8111-111111111111"}`,
		"case_folded":   strings.Replace(value, `"device_id"`, `"Device_ID"`, 1),
		"escaped":       strings.Replace(value, "test1234", `\u0074est1234`, 1),
		"extra_value":   value + `{}`,
		"malformed":     `{`, "null": `null`, "empty": `{}`,
		"unknown_key":    strings.Replace(value, "initial", "unrecognized", 1),
		"invalid_domain": strings.Replace(value, "test1234", "-test1234", 1),
		"invalid_uuid":   strings.Replace(value, "11111111-1111", "invalid-uuid", 1),
		"invalid_date":   strings.Replace(value, "2026-10-18", "2026-02-30", 1),
		"seconds_only":   strings.Replace(value, ".000001Z", "Z", 1),
		"nanoseconds":    strings.Replace(value, ".000001Z", ".000001001Z", 1),
		"utc_offset":     strings.Replace(value, ".000001Z", ".000001+00:00", 1),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			payload, err := ring.Verify(signedJSON([]byte(value), fixtureKey()))
			if !errors.Is(err, ErrInvalid) || payload != (protocol.ClaimPayload{}) {
				t.Fatal("invalid signed payload accepted or returned partial identity")
			}
		})
	}
}

func TestRejectAmbiguousBase64AndUnboundedTokens(t *testing.T) {
	ring := fixtureRing(t)
	token := fixtureToken(t, ring)
	parts := strings.Split(token, ".")
	for _, value := range []string{"", ".", token + ".", parts[0] + "=." + parts[1],
		parts[0] + "\n." + parts[1], token + "=", token[:len(token)-1],
		parts[0] + "." + parts[1][:42] + "5", strings.Repeat("A", maxTokenBytes+1)} {
		payload, err := ring.Verify(value)
		if !errors.Is(err, ErrInvalid) || payload != (protocol.ClaimPayload{}) || err.Error() != "invalid domain claim" {
			t.Fatal("invalid token accepted, exposed input, or returned a partial identity")
		}
	}
}

func TestKeyRotationAndDefensiveCopy(t *testing.T) {
	old := fixtureRing(t)
	oldToken := fixtureToken(t, old)
	newKey := []byte(strings.Repeat("n", 32))
	keys := map[string][]byte{"initial": fixtureKey(), "next": newKey}
	ring, err := New("next", keys)
	if err != nil {
		t.Fatal(err)
	}
	newToken := fixtureToken(t, ring)
	newKey[0] = 0
	delete(keys, "initial")
	if _, err := ring.Verify(oldToken); err != nil {
		t.Fatal("old verification key was not retained")
	}
	payload, err := ring.Verify(newToken)
	if err != nil || payload.KeyID != "next" || newToken != fixtureToken(t, ring) {
		t.Fatal("active key selection or defensive key snapshot failed")
	}
	onlyNew, _ := New("next", map[string][]byte{"next": []byte(strings.Repeat("n", 32))})
	if _, err := onlyNew.Verify(oldToken); !errors.Is(err, ErrInvalid) {
		t.Fatal("removed signing key still accepted")
	}
}

func TestRejectInvalidSigningInputs(t *testing.T) {
	for _, test := range []struct {
		active string
		keys   map[string][]byte
	}{{"initial", nil}, {"other", map[string][]byte{"initial": fixtureKey()}},
		{"bad\n", map[string][]byte{"bad\n": fixtureKey()}},
		{"initial", map[string][]byte{"initial": make([]byte, 31)}}} {
		if _, err := New(test.active, test.keys); !errors.Is(err, ErrKeyring) {
			t.Fatal("invalid key configuration accepted")
		}
	}
	ring := fixtureRing(t)
	payload := fixturePayload()
	issued, _ := time.Parse(timestampLayout, payload.IssuedAt)
	for _, test := range []struct {
		device, domain, tenant string
		issued                 time.Time
	}{{"bad", payload.Subdomain, payload.TenantID, issued},
		{payload.DeviceID, "bad\n", payload.TenantID, issued},
		{payload.DeviceID, payload.Subdomain, "bad", issued},
		{payload.DeviceID, payload.Subdomain, payload.TenantID, time.Time{}},
		{payload.DeviceID, payload.Subdomain, payload.TenantID, issued.Add(time.Nanosecond)}} {
		if token, err := ring.Issue(test.device, test.domain, test.tenant, test.issued); token != "" || !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid signing input accepted")
		}
	}
}

func TestMonotonicMicrosecondsAcrossSameSecondAndClockRollback(t *testing.T) {
	now := time.Date(2026, 10, 18, 0, 0, 0, 123456789, time.UTC)
	previous := time.Time{}
	ring := fixtureRing(t)
	payload := fixturePayload()
	seen := map[string]bool{}
	for range 100 {
		next, err := NextIssuedAt(now, previous)
		if err != nil || !next.After(previous) || next.Nanosecond()%1000 != 0 {
			t.Fatalf("issued_at did not advance at database precision: %v", err)
		}
		token, err := ring.Issue(payload.DeviceID, payload.Subdomain, payload.TenantID, next)
		if err != nil || seen[token] {
			t.Fatal("same-second rotation reused a claim")
		}
		seen[token] = true
		previous = next
	}
	next, err := NextIssuedAt(now.Add(-time.Hour), previous)
	if err != nil || next.Sub(previous) != time.Microsecond {
		t.Fatal("clock rollback reused an issued_at")
	}
	maximum := time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC)
	if _, err := NextIssuedAt(maximum, maximum); !errors.Is(err, ErrInvalid) {
		t.Fatal("timestamp overflow accepted")
	}
	if _, err := NextIssuedAt(now, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("non-database precision previous value accepted")
	}
}

func TestConcurrentSigningAndVerification(t *testing.T) {
	ring := fixtureRing(t)
	token := fixtureToken(t, ring)
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for range 20 {
				payload := fixturePayload()
				issued, _ := time.Parse(timestampLayout, payload.IssuedAt)
				if issuedToken, err := ring.Issue(payload.DeviceID, payload.Subdomain, payload.TenantID, issued); err != nil || issuedToken != token {
					t.Error("concurrent signing failed")
				}
				if _, err := ring.Verify(token); err != nil {
					t.Error("concurrent verification failed")
				}
			}
		})
	}
	workers.Wait()
}

func FuzzVerify(f *testing.F) {
	ring := fixtureRing(f)
	f.Add(fixtureToken(f, ring))
	f.Add("")
	f.Add("a.b")
	f.Add(strings.Repeat("x", maxTokenBytes+1))
	f.Fuzz(func(t *testing.T, token string) {
		payload, err := ring.Verify(token)
		if err != nil && payload != (protocol.ClaimPayload{}) {
			t.Fatal("failed verification returned identity")
		}
		if err == nil && validate(payload) != nil {
			t.Fatal("verification returned an invalid payload")
		}
	})
}
