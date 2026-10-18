package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionCookieAndCSRFIsolation(t *testing.T) {
	first, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newToken()
	if err != nil || len(first) != 43 || first == second {
		t.Fatal("session token entropy/encoding")
	}
	firstHash, _ := tokenHash(first)
	secondHash, _ := tokenHash(second)
	if len(firstHash) != 32 || bytes.Equal(firstHash, secondHash) {
		t.Fatal("session hashes are not distinct")
	}
	csrf := csrfFor(first)
	if csrf == first || csrf == csrfFor(second) || !CheckCSRF(Session{CSRFToken: csrf}, csrf) || CheckCSRF(Session{CSRFToken: csrf}, first) {
		t.Fatal("CSRF separation failed")
	}
	if bytes.Equal(firstHash, csrfHash(csrf)) {
		t.Fatal("session and CSRF digests are interchangeable")
	}
	expiry := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	cookie := SessionCookie(first, expiry)
	if cookie.Name != SessionCookieName || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "" || !cookie.Expires.Equal(expiry) {
		t.Fatal("unsafe session cookie attributes")
	}
	request := httptest.NewRequest("GET", "https://console.example.com/", nil)
	request.AddCookie(cookie)
	if got, err := ReadSessionToken(request); err != nil || got != first {
		t.Fatal("cannot read session cookie")
	}
	request.AddCookie(cookie)
	if _, err := ReadSessionToken(request); err == nil {
		t.Fatal("duplicate cookies accepted")
	}
	cleared := ClearSessionCookie()
	if cleared.MaxAge != -1 || cleared.Value != "" || !cleared.Secure || cleared.Domain != "" {
		t.Fatal("invalid cookie removal")
	}
	document, err := json.Marshal(LoginResult{Token: first, Session: Session{CSRFToken: csrf}})
	if err != nil || strings.Contains(string(document), first) {
		t.Fatal("session bearer leaked into JSON")
	}
	for _, invalid := range []string{"", first + "=", strings.Repeat("!", 43), first[:42] + "B"} {
		if _, err := tokenHash(invalid); err == nil {
			t.Fatal("noncanonical session bearer accepted")
		}
	}
}
