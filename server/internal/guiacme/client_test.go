package guiacme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type accountFixture struct {
	mu                       sync.Mutex
	server                   *httptest.Server
	key                      *ecdsa.PrivateKey
	registered               bool
	creates, lookups, orders int
	nonces                   map[string]bool
	sequence                 int
	terms                    string
	accountURI               string
	orderOrigin              string
	status                   string
	eab                      bool
	loseCreate               bool
	malformedDirectory       bool
	malformedAccount         bool
}

type counts struct{ creates, lookups, orders, requests int }

func (f *accountFixture) counts() counts {
	f.mu.Lock()
	defer f.mu.Unlock()
	return counts{f.creates, f.lookups, f.orders, f.sequence}
}

func fixture(t *testing.T) (*accountFixture, Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &accountFixture{key: key, nonces: map[string]bool{}, status: "valid"}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	f.terms = "https://terms.example.test/current"
	f.accountURI = f.server.URL + "/account/one"
	f.orderOrigin = f.server.URL
	roots := x509.NewCertPool()
	roots.AddCert(f.server.Certificate())
	return f, Config{DirectoryURL: f.server.URL + "/directory", Roots: roots, Key: key, ContactEmail: "admin@example.test"}
}

func (f *accountFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sequence++
	nonce := fmt.Sprintf("nonce-%d", f.sequence)
	f.nonces[nonce] = true
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/directory":
		if f.malformedDirectory {
			_, _ = w.Write([]byte(strings.Repeat("x", maxResponse+1)))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"newAccount": f.server.URL + "/new-account", "newNonce": f.server.URL + "/nonce",
			"newOrder": f.orderOrigin + "/new-order", "meta": map[string]any{"termsOfService": f.terms, "externalAccountRequired": f.eab},
		})
	case "/nonce":
		w.WriteHeader(http.StatusOK)
	case "/new-account":
		payload, valid := f.verify(r)
		if !valid {
			w.WriteHeader(400)
			return
		}
		if payload.OnlyReturnExisting {
			f.lookups++
			if !f.registered {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:accountDoesNotExist","detail":"private remote detail"}`))
				return
			}
		} else {
			if f.terms != "" && !payload.TermsAgreed || len(payload.Contact) != 1 || payload.Contact[0] != "mailto:admin@example.test" {
				w.WriteHeader(400)
				return
			}
			f.creates++
			f.registered = true
			if f.loseCreate {
				w.WriteHeader(503)
				_, _ = w.Write([]byte("private ambiguous registration"))
				return
			}
		}
		w.Header().Set("Location", f.accountURI)
		if !payload.OnlyReturnExisting {
			w.WriteHeader(201)
		}
		if f.malformedAccount {
			_, _ = w.Write([]byte(`{"private":"untrusted response"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": f.status, "orders": f.server.URL + "/account/one/orders"})
	case "/new-order":
		f.orders++
		w.WriteHeader(500)
	default:
		w.WriteHeader(404)
	}
}

type accountPayload struct {
	OnlyReturnExisting bool     `json:"onlyReturnExisting"`
	TermsAgreed        bool     `json:"termsOfServiceAgreed"`
	Contact            []string `json:"contact"`
}

// The fixture verifies the SDK's real JWS signature, key and single-use nonce;
// it is a TLS protocol fixture, not a substitute for a genuine ACME server.
func (f *accountFixture) verify(r *http.Request) (accountPayload, bool) {
	var jws struct{ Protected, Payload, Signature string }
	var payload accountPayload
	if r.Method != "POST" || r.Header.Get("Content-Type") != "application/jose+json" || json.NewDecoder(r.Body).Decode(&jws) != nil {
		return payload, false
	}
	header, e1 := base64.RawURLEncoding.DecodeString(jws.Protected)
	body, e2 := base64.RawURLEncoding.DecodeString(jws.Payload)
	sig, e3 := base64.RawURLEncoding.DecodeString(jws.Signature)
	var protected struct {
		Alg, Nonce, URL string
		JWK             struct{ Crv, Kty, X, Y string }
	}
	if e1 != nil || e2 != nil || e3 != nil || len(sig) != 64 || json.Unmarshal(header, &protected) != nil || json.Unmarshal(body, &payload) != nil || protected.Alg != "ES256" || protected.URL != f.server.URL+r.URL.Path || !f.nonces[protected.Nonce] || protected.JWK.Crv != "P-256" || protected.JWK.Kty != "EC" {
		return payload, false
	}
	delete(f.nonces, protected.Nonce)
	x, ex := base64.RawURLEncoding.DecodeString(protected.JWK.X)
	y, ey := base64.RawURLEncoding.DecodeString(protected.JWK.Y)
	digest := sha256.Sum256([]byte(jws.Protected + "." + jws.Payload))
	return payload, ex == nil && ey == nil && new(big.Int).SetBytes(x).Cmp(f.key.X) == 0 && new(big.Int).SetBytes(y).Cmp(f.key.Y) == 0 && ecdsa.Verify(&f.key.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

func TestAccountCreationRequiresCurrentExplicitConsent(t *testing.T) {
	f, config := fixture(t)
	c, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, registration := range []Registration{{}, {AllowCreate: true}, {AllowCreate: true, AcceptedTermsURL: "https://terms.example.test/old"}} {
		if _, err := c.EnsureAccount(context.Background(), registration); err != ErrConsent {
			t.Fatalf("consent: %v", err)
		}
	}
	if f.counts().creates != 0 {
		t.Fatal("registered without consent")
	}
	a, err := c.EnsureAccount(context.Background(), Registration{AllowCreate: true, AcceptedTermsURL: f.terms})
	if err != nil || a.URI != f.accountURI || f.counts().creates != 1 || f.counts().orders != 0 {
		t.Fatalf("registration: %v", err)
	}
	encoded, _ := json.Marshal(a)
	if string(encoded) != "{}" {
		t.Fatal("account identity in ordinary JSON")
	}
	for range 3 {
		a, err = c.EnsureAccount(context.Background(), Registration{ExpectedURI: a.URI})
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.counts().creates != 1 {
		t.Fatal("duplicate registration")
	}
}

func TestLostRegistrationResponseRecoversSameKey(t *testing.T) {
	f, config := fixture(t)
	f.loseCreate = true
	c, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.EnsureAccount(context.Background(), Registration{AllowCreate: true, AcceptedTermsURL: f.terms}); err != ErrRemote {
		t.Fatalf("lost response: %v", err)
	}
	// Simulate process recovery with the same previously stored key.
	next, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	a, err := next.EnsureAccount(context.Background(), Registration{})
	if err != nil || a.URI != f.accountURI || f.counts().creates != 1 || f.counts().lookups != 2 {
		t.Fatalf("recovery: %v", err)
	}
}

func TestKnownAccountNeverSilentlyReplaced(t *testing.T) {
	for _, mode := range []string{"missing", "changed", "revoked", "deactivated", "cross-origin", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			f, config := fixture(t)
			f.registered = mode != "missing"
			switch mode {
			case "changed":
				f.accountURI = f.server.URL + "/account/two"
			case "revoked", "deactivated":
				f.status = mode
			case "cross-origin":
				f.accountURI = "https://other.example.test/account/one"
			case "malformed":
				f.malformedAccount = true
			}
			c, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err := c.EnsureAccount(context.Background(), Registration{AllowCreate: true, AcceptedTermsURL: f.terms, ExpectedURI: f.server.URL + "/account/one"}); err != ErrAccount {
				t.Fatalf("identity: %v", err)
			}
			if f.counts().creates != 0 {
				t.Fatal("replaced existing identity")
			}
		})
	}
}

func TestDirectoryPolicyBeforeSignedAccountRequest(t *testing.T) {
	for _, mode := range []string{"cross-origin", "eab", "oversized", "untrusted-tls"} {
		t.Run(mode, func(t *testing.T) {
			f, config := fixture(t)
			switch mode {
			case "cross-origin":
				f.orderOrigin = "https://other.example.test"
			case "eab":
				f.eab = true
			case "oversized":
				f.malformedDirectory = true
			case "untrusted-tls":
				config.Roots = x509.NewCertPool()
			}
			c, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_, err = c.EnsureAccount(context.Background(), Registration{AllowCreate: true, AcceptedTermsURL: f.terms})
			want := ErrRemote
			if mode == "eab" {
				want = ErrAccount
			}
			if err != want || f.counts().creates != 0 || f.counts().orders != 0 {
				t.Fatalf("directory policy: %v", err)
			}
			if mode != "eab" && f.counts().lookups != 0 {
				t.Fatal("signed lookup before directory validation")
			}
		})
	}
}

func TestCancelledAccountDoesNotContactCA(t *testing.T) {
	f, config := fixture(t)
	c, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.EnsureAccount(ctx, Registration{}); err != ErrCancelled || f.counts().requests != 0 {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestConcurrentAccountSetupAndCancelledWaiter(t *testing.T) {
	f, config := fixture(t)
	c, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			if _, err := c.EnsureAccount(context.Background(), Registration{AllowCreate: true, AcceptedTermsURL: f.terms}); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	if f.counts().creates != 1 || f.counts().lookups != 8 {
		t.Fatal("concurrent setup did not reuse account")
	}
	// An occupied account gate must remain cancellable without a CA round trip.
	c.gate <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.EnsureAccount(ctx, Registration{}); err != ErrCancelled {
		t.Fatal("cancelled gate waiter")
	}
	<-c.gate
	if f.counts().lookups != 8 {
		t.Fatal("cancelled waiter contacted CA")
	}
}

func TestChangedTermsAreDiscoveredBeforeRegistration(t *testing.T) {
	f, config := fixture(t)
	c, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.EnsureAccount(context.Background(), Registration{}); err != ErrConsent {
		t.Fatal(err)
	}
	oldTerms := f.terms
	f.mu.Lock()
	f.terms = "https://terms.example.test/updated"
	f.mu.Unlock()
	if _, err := c.EnsureAccount(context.Background(), Registration{AllowCreate: true, AcceptedTermsURL: oldTerms}); err != ErrConsent || f.counts().creates != 0 {
		t.Fatal("old cached terms accepted")
	}
	if _, err := c.EnsureAccount(context.Background(), Registration{AllowCreate: true, AcceptedTermsURL: f.terms}); err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationWithoutAdvertisedTermsStillRequiresOptIn(t *testing.T) {
	f, config := fixture(t)
	f.terms = ""
	c, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.EnsureAccount(context.Background(), Registration{}); err != ErrConsent {
		t.Fatal("missing explicit registration consent")
	}
	if _, err := c.EnsureAccount(context.Background(), Registration{AllowCreate: true}); err != nil {
		t.Fatal(err)
	}
	if f.counts().creates != 1 {
		t.Fatal("registration count")
	}
}
