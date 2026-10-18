package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

const SessionCookieName = "__Host-nethub_session"

func newToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("session randomness unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func tokenHash(token string) ([]byte, error) {
	if len(token) != 43 {
		return nil, ErrUnauthenticated
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != 32 {
		return nil, ErrUnauthenticated
	}
	digest := sha256.Sum256(raw)
	return digest[:], nil
}

// csrfFor recovers the session's synchronizer token from its HttpOnly bearer.
// Neither raw value is persisted. Domain separation prevents treating the CSRF
// token itself as a session cookie; browser responses expose only the CSRF value.
func csrfFor(token string) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("nethub/session-csrf/v1"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func csrfHash(token string) []byte {
	digest := sha256.Sum256([]byte(token))
	return digest[:]
}

func SessionCookie(token string, expires time.Time) *http.Cookie {
	return &http.Cookie{Name: SessionCookieName, Value: token, Path: "/", HttpOnly: true,
		Secure: true, SameSite: http.SameSiteLaxMode, Expires: expires.UTC()}
}

func ClearSessionCookie() *http.Cookie {
	cookie := SessionCookie("", time.Unix(1, 0))
	cookie.MaxAge = -1
	return cookie
}

// ReadSessionToken rejects ambiguous duplicate cookies rather than selecting
// one based on header order.
func ReadSessionToken(request *http.Request) (string, error) {
	cookies := request.CookiesNamed(SessionCookieName)
	if len(cookies) != 1 {
		return "", ErrUnauthenticated
	}
	if _, err := tokenHash(cookies[0].Value); err != nil {
		return "", err
	}
	return cookies[0].Value, nil
}

func CheckCSRF(session Session, supplied string) bool {
	return len(supplied) == 43 && hmac.Equal([]byte(session.CSRFToken), []byte(supplied))
}
