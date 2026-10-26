package sso

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authoidc "github.com/KazuhaHub/authcore/oidc"
	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/go-jose/go-jose/v4"
)

type memoryFlow struct {
	input    FlowInput
	id       string
	consumed bool
}
type flowTestRepository struct {
	mu         sync.Mutex
	provider   LoginProvider
	flows      map[string]*memoryFlow
	identity   auth.ExternalIdentity
	admissions int
}

func (r *flowTestRepository) LoginProviders(context.Context) ([]Choice, error) {
	return []Choice{{Slug: r.provider.Slug, DisplayName: r.provider.DisplayName}}, nil
}
func (r *flowTestRepository) LoginProvider(_ context.Context, slug string) (LoginProvider, error) {
	if slug != r.provider.Slug {
		return LoginProvider{}, ErrFlow
	}
	return r.provider, nil
}
func (r *flowTestRepository) SaveOIDCFlow(_ context.Context, input FlowInput) (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.flows[input.State.Value] = &memoryFlow{input: input, id: fmt.Sprintf("00000000-0000-4000-8000-%012d", len(r.flows)+1)}
	return time.Now().Add(FlowLifetime), nil
}
func (r *flowTestRepository) ConsumeOIDCFlow(_ context.Context, slug, state string, browser []byte) (ConsumedFlow, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.flows[state]
	if f == nil || f.consumed || slug != f.input.Provider.Slug || !hmac.Equal(f.input.BrowserDigest, browser) {
		return ConsumedFlow{}, ErrFlow
	}
	f.consumed = true
	return ConsumedFlow{ID: f.id, Provider: f.input.Provider, State: f.input.State}, nil
}
func (*flowTestRepository) SSOFailed(context.Context, netip.Addr, string) error { return nil }
func (*flowTestRepository) PasswordCandidate(context.Context, string) (auth.Candidate, error) {
	return auth.Candidate{}, auth.ErrInvalidCredentials
}
func (*flowTestRepository) CreateSession(context.Context, auth.Candidate, auth.SessionRecord) (auth.SessionRecord, error) {
	return auth.SessionRecord{}, auth.ErrInvalidCredentials
}
func (*flowTestRepository) LookupSession(context.Context, []byte, time.Duration) (auth.SessionRecord, error) {
	return auth.SessionRecord{}, auth.ErrUnauthenticated
}
func (*flowTestRepository) LookupSessionPassive(context.Context, []byte, time.Duration) (auth.SessionRecord, error) {
	return auth.SessionRecord{}, auth.ErrUnauthenticated
}
func (*flowTestRepository) DeleteSession(context.Context, []byte, netip.Addr) error { return nil }
func (r *flowTestRepository) CreateExternalSession(_ context.Context, identity auth.ExternalIdentity, record auth.SessionRecord) (auth.SessionRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.admissions++
	r.identity = identity
	record.User = auth.User{ID: "bound-user", Email: "original@example.com", Role: "member"}
	return record, nil
}

type codeExpectation struct{ nonce, challenge string }
type serviceIDP struct {
	server                            *httptest.Server
	issuer                            atomic.Value
	mu                                sync.Mutex
	codes                             map[string]codeExpectation
	verified                          any
	badNonce, badSignature, dropReply bool
	tokenCalls                        atomic.Int64
}

func newServiceIDP(t *testing.T) *serviceIDP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &serviceIDP{codes: make(map[string]codeExpectation), verified: true}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		issuer := f.issuer.Load().(string)
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "response_types_supported": []string{"code"}, "id_token_signing_alg_values_supported": []string{"ES256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"}})
		case "/keys":
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "service-key", Algorithm: "ES256", Use: "sig"}}})
		case "/token":
			f.tokenCalls.Add(1)
			if r.Method != "POST" || r.ParseForm() != nil {
				http.Error(w, "invalid request", 400)
				return
			}
			client, secret, ok := r.BasicAuth()
			if !ok || client != "console" || secret != "service-fixture-client" {
				http.Error(w, "client refused", 401)
				return
			}
			f.mu.Lock()
			expected, exists := f.codes[r.Form.Get("code")]
			delete(f.codes, r.Form.Get("code"))
			verified := f.verified
			badNonce, badSignature, drop := f.badNonce, f.badSignature, f.dropReply
			f.mu.Unlock()
			hash := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if !exists || base64.RawURLEncoding.EncodeToString(hash[:]) != expected.challenge || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != "https://console.example/api/v1/console/oidc/first/callback" {
				http.Error(w, "code refused", 400)
				return
			}
			if drop {
				conn, _, e := w.(http.Hijacker).Hijack()
				if e == nil {
					conn.Close()
				}
				return
			}
			if badNonce {
				expected.nonce = "wrong-nonce"
			}
			signingKey := key
			if badSignature {
				signingKey = other
			}
			signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: signingKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "service-key"))
			if e != nil {
				http.Error(w, "signing unavailable", 500)
				return
			}
			claims, _ := json.Marshal(map[string]any{"iss": issuer, "sub": "stable-subject", "aud": "console", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": expected.nonce, "email": "changed@example.com", "email_verified": verified})
			signed, e := signer.Sign(claims)
			if e != nil {
				http.Error(w, "signing unavailable", 500)
				return
			}
			token, e := signed.CompactSerialize()
			if e != nil {
				http.Error(w, "signing unavailable", 500)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "service-fixture-access", "token_type": "Bearer", "id_token": token})
		default:
			http.NotFound(w, r)
		}
	}))
	f.issuer.Store(f.server.URL)
	t.Cleanup(f.server.Close)
	return f
}

func (f *serviceIDP) authorize(t *testing.T, start StartResult) (string, string) {
	t.Helper()
	u, e := url.Parse(start.RedirectURL)
	if e != nil {
		t.Fatal(e)
	}
	q := u.Query()
	if q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Fatal("missing authorization binding")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	code := fmt.Sprintf("service-code-%s", q.Get("state"))
	f.codes[code] = codeExpectation{nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
	return q.Get("state"), code
}

func TestServiceSignedTLSFlowAndSingleExchange(t *testing.T) {
	f := newServiceIDP(t)
	repository := &flowTestRepository{provider: LoginProvider{ID: "00000000-0000-4000-8000-000000000001", Slug: "first", DisplayName: "First", Revision: 1, Config: authoidc.Config{IssuerURL: f.server.URL, ClientID: "console", ClientSecret: "service-fixture-client"}}, flows: make(map[string]*memoryFlow)}
	sessions, err := auth.NewService(repository, auth.Config{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService("https://CONSOLE.example:443", repository, sessions, tlsOutbound(t, f.server))
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("192.0.2.228")
	start := func() (StartResult, string, string) {
		t.Helper()
		v, e := service.Start(context.Background(), "first", "")
		if e != nil {
			t.Fatal(e)
		}
		state, code := f.authorize(t, v)
		return v, state, code
	}
	begin, state, code := start()
	if _, consumed, e := service.Complete(context.Background(), "first", state, code, "", strings.Repeat("A", 43), ip, "test"); !errors.Is(e, ErrFlow) || consumed || f.tokenCalls.Load() != 0 {
		t.Fatal("wrong browser consumed or exchanged", e)
	}
	result, consumed, err := service.Complete(context.Background(), "first", state, code, f.server.URL, begin.BrowserToken, ip, "test")
	if err != nil || !consumed || result.Token == "" || result.User.ID != "bound-user" || f.tokenCalls.Load() != 1 || repository.identity.Issuer != f.server.URL || repository.identity.Subject != "stable-subject" || !repository.identity.EmailVerified {
		t.Fatal("signed TLS flow failed", err)
	}
	if _, consumed, e := service.Complete(context.Background(), "first", state, code, "", begin.BrowserToken, ip, "test"); !errors.Is(e, ErrFlow) || consumed || f.tokenCalls.Load() != 1 {
		t.Fatal("callback replay exchanged again", e)
	}
	for _, verified := range []any{false, "true", nil} {
		f.mu.Lock()
		f.verified = verified
		f.mu.Unlock()
		begin, state, code = start()
		if _, _, e := service.Complete(context.Background(), "first", state, code, "", begin.BrowserToken, ip, "test"); e != nil || repository.identity.EmailVerified {
			t.Fatal("unverified email promoted or bound login globally rejected", e)
		}
	}
	for _, failure := range []string{"nonce", "signature", "lost-reply"} {
		f.mu.Lock()
		f.verified = true
		f.badNonce = failure == "nonce"
		f.badSignature = failure == "signature"
		f.dropReply = failure == "lost-reply"
		f.mu.Unlock()
		begin, state, code = start()
		before := f.tokenCalls.Load()
		admissions := repository.admissions
		_, consumed, e := service.Complete(context.Background(), "first", state, code, "", begin.BrowserToken, ip, "test")
		if !errors.Is(e, ErrFlow) || !consumed || repository.admissions != admissions {
			t.Fatal("failed protocol admitted identity", failure, e)
		}
		wantReason := map[string]string{"nonce": "nonce_invalid", "signature": "token_invalid", "lost-reply": "exchange_failed"}[failure]
		if FailureReason(e) != wantReason || e.Error() != ErrFlow.Error() {
			t.Fatal("protocol audit category or public failure changed", failure)
		}
		if _, _, e := service.Complete(context.Background(), "first", state, code, "", begin.BrowserToken, ip, "test"); e == nil || f.tokenCalls.Load() != before+1 {
			t.Fatal("failed exchange retried", failure, e)
		}
	}
	f.mu.Lock()
	f.badNonce = false
	f.badSignature = false
	f.dropReply = false
	f.mu.Unlock()
	begin, state, _ = start()
	before := f.tokenCalls.Load()
	if _, consumed, e := service.Complete(context.Background(), "first", state, "", "", begin.BrowserToken, ip, "test"); e == nil || !consumed || f.tokenCalls.Load() != before {
		t.Fatal("provider refusal exchanged or retained its flow", e)
	}
	begin, state, code = start()
	before = f.tokenCalls.Load()
	if _, consumed, e := service.Complete(context.Background(), "first", state, code, "https://other.example", begin.BrowserToken, ip, "test"); e == nil || !consumed || f.tokenCalls.Load() != before {
		t.Fatal("wrong response issuer exchanged", e)
	}
	begin, state, code = start()
	before = f.tokenCalls.Load()
	var successes atomic.Int64
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, e := service.Complete(context.Background(), "first", state, code, "", begin.BrowserToken, ip, "test"); e == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || f.tokenCalls.Load() != before+1 {
		t.Fatal("concurrent callbacks exchanged or admitted more than once")
	}
	encoded, _ := json.Marshal(begin)
	if string(encoded) != "{}" || strings.Contains(fmt.Sprintf("%#v", begin), begin.BrowserToken) {
		t.Fatal("flow debug exposed browser or authorization material")
	}
}
