package guiacme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const orderHost = "abcdefgh.devices.example.test"

func orderRequest(t *testing.T) ([]byte, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{orderHost}}, key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), base64.RawURLEncoding.EncodeToString(public)
}

// This fixture verifies actual SDK ES256 KID requests and consumed nonces. It
// does not stand in for real CA challenge validation, issuance or deployment.
func verifyOrderMessage(f *accountFixture, r *http.Request) ([]byte, bool) {
	var jws struct{ Protected, Payload, Signature string }
	if r.Method != "POST" || r.Header.Get("Content-Type") != "application/jose+json" || json.NewDecoder(r.Body).Decode(&jws) != nil {
		return nil, false
	}
	header, e1 := base64.RawURLEncoding.DecodeString(jws.Protected)
	body, e2 := base64.RawURLEncoding.DecodeString(jws.Payload)
	signature, e3 := base64.RawURLEncoding.DecodeString(jws.Signature)
	var protected struct {
		Alg, Nonce, URL, KID string
		JWK                  json.RawMessage
	}
	if e1 != nil || e2 != nil || e3 != nil || len(signature) != 64 || json.Unmarshal(header, &protected) != nil ||
		protected.Alg != "ES256" || protected.KID != f.accountURI || len(protected.JWK) != 0 ||
		protected.URL != f.server.URL+r.URL.Path || !f.nonces[protected.Nonce] {
		return nil, false
	}
	delete(f.nonces, protected.Nonce)
	digest := sha256.Sum256([]byte(jws.Protected + "." + jws.Payload))
	valid := ecdsa.Verify(&f.key.PublicKey, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:]))
	return body, valid
}

type orderBehavior struct {
	mutate          func(map[string]any)
	authMutate      func(map[string]any)
	acceptMutate    func(map[string]any)
	locate          string
	lose            bool
	polls           int
	authReads       int
	accepts         int
	authValid       bool
	challengeStatus string
	loseAccept      bool
	finalization    func(http.ResponseWriter, *http.Request, []byte) bool
}

func orderFixture(t *testing.T) (*AccountStore, *accountFixture, *orderBehavior) {
	t.Helper()
	return orderFixtureWithAccount(t, nil)
}

func orderFixtureWithAccount(t *testing.T, configure func(*accountFixture)) (*AccountStore, *accountFixture, *orderBehavior) {
	t.Helper()
	s, f, _ := storeFixture(t)
	if configure != nil {
		f.mu.Lock()
		configure(f)
		f.mu.Unlock()
	}
	if _, err := s.EnsureAccount(context.Background(), true, f.terms); err != nil {
		t.Fatal(err)
	}
	b := &orderBehavior{}
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	f.mu.Lock()
	f.orderHandler = func(w http.ResponseWriter, r *http.Request) {
		body, valid := verifyOrderMessage(f, r)
		if !valid {
			w.WriteHeader(400)
			return
		}
		if b.finalization != nil && b.finalization(w, r, body) {
			return
		}
		challenge := func() map[string]any {
			status := b.challengeStatus
			if status == "" {
				status = "pending"
			}
			return map[string]any{"type": "http-01", "url": f.server.URL + "/challenge/one", "token": strings.Repeat("A", 43), "status": status}
		}
		if r.URL.Path == "/authz/one" && len(body) == 0 {
			b.authReads++
			status := "pending"
			if b.authValid {
				status = "valid"
			}
			response := map[string]any{"status": status, "identifier": map[string]string{"type": "dns", "value": orderHost}, "expires": expires, "challenges": []any{challenge()}}
			if b.authMutate != nil {
				b.authMutate(response)
			}
			_ = json.NewEncoder(w).Encode(response)
			return
		}
		if r.URL.Path == "/challenge/one" && string(body) == "{}" {
			b.accepts++
			b.challengeStatus = "processing"
			if b.loseAccept {
				w.WriteHeader(503)
				_, _ = w.Write([]byte("private ambiguous challenge response"))
				return
			}
			response := challenge()
			if b.acceptMutate != nil {
				b.acceptMutate(response)
			}
			_ = json.NewEncoder(w).Encode(response)
			return
		}
		if r.URL.Path == "/new-order" {
			var payload struct {
				Identifiers                  []struct{ Type, Value string }
				NotBefore, NotAfter, Profile string
			}
			if json.Unmarshal(body, &payload) != nil || len(payload.Identifiers) != 1 || payload.Identifiers[0].Type != "dns" ||
				payload.Identifiers[0].Value != orderHost || payload.NotBefore != "" || payload.NotAfter != "" || payload.Profile != "" {
				w.WriteHeader(400)
				return
			}
		} else if r.URL.Path == "/order/one" && len(body) == 0 {
			b.polls++
		} else {
			w.WriteHeader(404)
			return
		}
		if b.lose {
			w.WriteHeader(503)
			_, _ = w.Write([]byte("private ambiguous order response"))
			return
		}
		response := map[string]any{"status": "pending", "expires": expires,
			"identifiers":    []map[string]string{{"type": "dns", "value": orderHost}},
			"authorizations": []string{f.server.URL + "/authz/one"}, "finalize": f.server.URL + "/finalize/one"}
		if b.mutate != nil {
			b.mutate(response)
		}
		location := f.server.URL + "/order/one"
		if b.locate != "" {
			location = b.locate
		}
		w.Header().Set("Location", location)
		if r.URL.Path == "/new-order" {
			w.WriteHeader(201)
		}
		_ = json.NewEncoder(w).Encode(response)
	}
	f.mu.Unlock()
	return s, f, b
}

func TestOrderUsesPersistedAccountAndExactRequest(t *testing.T) {
	s, f, b := orderFixture(t)
	csr, public := orderRequest(t)
	before, _ := os.ReadFile(s.path("account.json"))
	order, err := s.CreateOrder(context.Background(), csr, orderHost, public)
	if err != nil || order.URI != f.server.URL+"/order/one" || order.Host != orderHost || order.Status != "pending" {
		t.Fatalf("create: %v", err)
	}
	block, _ := pem.Decode(csr)
	digest := sha256.Sum256(block.Bytes)
	if order.RequestFingerprint != hex.EncodeToString(digest[:]) {
		t.Fatal("request fingerprint was not bound")
	}
	for range 3 {
		observed, err := s.InspectOrder(context.Background(), order.URI, csr, orderHost, public)
		if err != nil || observed != order {
			t.Fatalf("same-order recovery: %v", err)
		}
	}
	if f.counts().orders != 1 || f.counts().creates != 1 || b.polls != 3 {
		t.Fatal("observation created another account/order")
	}
	after, _ := os.ReadFile(s.path("account.json"))
	if string(before) != string(after) {
		t.Fatal("order work changed account identity")
	}
	encoded, _ := json.Marshal(order)
	if string(encoded) != "{}" {
		t.Fatal("private order metadata appeared in ordinary JSON")
	}
}

func TestOrderRejectsUnboundRequestsBeforeNetwork(t *testing.T) {
	s, f, _ := orderFixture(t)
	csr, public := orderRequest(t)
	before := f.counts()
	for _, input := range []struct {
		csr          []byte
		host, public string
	}{{csr, orderHost, ""}, {csr, "other.devices.example.test", public}, {[]byte("invalid"), orderHost, public}} {
		if _, err := s.CreateOrder(context.Background(), input.csr, input.host, input.public); err != ErrOrder {
			t.Fatal("unbound request accepted")
		}
	}
	for _, uri := range []string{"", "http://untrusted.example.test/order", "https://untrusted.example.test/order"} {
		if _, err := s.InspectOrder(context.Background(), uri, csr, orderHost, public); err != ErrOrder {
			t.Fatal("unapproved order URI accepted")
		}
	}
	if f.counts() != before {
		t.Fatal("rejected input performed network work")
	}
}

func TestOrderCannotRegisterOrRepairMissingAccount(t *testing.T) {
	s, f, _ := storeFixture(t)
	csr, public := orderRequest(t)
	if _, err := s.CreateOrder(context.Background(), csr, orderHost, public); err != ErrAccount || f.counts().requests != 0 {
		t.Fatal("unregistered job attempted account creation")
	}
	if err := os.Remove(s.path("account.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOrder(context.Background(), csr, orderHost, public); err != ErrState || f.counts().requests != 0 {
		t.Fatal("missing account was repaired")
	}
}

func TestOrderRejectsMalformedAndChangedAuthority(t *testing.T) {
	for _, change := range []string{"host", "wildcard", "multiple", "ip", "status", "expired", "no-expiry", "authz", "finalize", "certificate", "profile", "location"} {
		t.Run(change, func(t *testing.T) {
			s, f, b := orderFixture(t)
			csr, public := orderRequest(t)
			f.mu.Lock()
			b.mutate = func(response map[string]any) {
				switch change {
				case "host", "wildcard":
					response["identifiers"] = []map[string]string{{"type": "dns", "value": "other.devices.example.test"}}
					if change == "wildcard" {
						response["identifiers"] = []map[string]string{{"type": "dns", "value": "*.devices.example.test"}}
					}
				case "multiple":
					response["identifiers"] = []map[string]string{{"type": "dns", "value": orderHost}, {"type": "dns", "value": orderHost}}
				case "ip":
					response["identifiers"] = []map[string]string{{"type": "ip", "value": orderHost}}
				case "status":
					response["status"] = "unknown"
				case "expired":
					response["expires"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
				case "no-expiry":
					delete(response, "expires")
				case "authz":
					response["authorizations"] = []string{"https://untrusted.example.test/authz"}
				case "finalize":
					response["finalize"] = "https://untrusted.example.test/finalize"
				case "certificate":
					response["status"] = "valid"
					response["certificate"] = "https://untrusted.example.test/certificate"
				case "profile":
					response["profile"] = "unrequested"
				}
			}
			if change == "location" {
				b.locate = f.server.URL + "/order/other"
			}
			f.mu.Unlock()
			if _, err := s.InspectOrder(context.Background(), f.server.URL+"/order/one", csr, orderHost, public); err != ErrOrder {
				t.Fatalf("changed authority accepted: %v", err)
			}
		})
	}
}

func TestOrderLostResponseHasNoHiddenRetry(t *testing.T) {
	s, f, b := orderFixture(t)
	csr, public := orderRequest(t)
	f.mu.Lock()
	b.lose = true
	f.mu.Unlock()
	_, err := s.CreateOrder(context.Background(), csr, orderHost, public)
	if err != ErrRemote || strings.Contains(err.Error(), "private") || f.counts().orders != 1 {
		t.Fatal("ambiguous request retried or exposed a remote diagnostic")
	}
	f.mu.Lock()
	b.lose = false
	f.mu.Unlock()
	if _, err := s.InspectOrder(context.Background(), f.server.URL+"/order/one", csr, orderHost, public); err != nil || f.counts().orders != 1 {
		t.Fatal("inspection created a replacement order")
	}
	f.mu.Lock()
	f.status = "deactivated"
	f.mu.Unlock()
	if _, err := s.CreateOrder(context.Background(), csr, orderHost, public); err != ErrAccount || f.counts().orders != 1 {
		t.Fatal("deactivated account submitted an order")
	}
}

func TestOrderStatusesAndAccountLease(t *testing.T) {
	s, f, b := orderFixture(t)
	csr, public := orderRequest(t)
	for _, status := range []string{"ready", "processing", "valid", "invalid"} {
		f.mu.Lock()
		b.mutate = func(response map[string]any) {
			response["status"] = status
			if status == "valid" {
				response["certificate"] = f.server.URL + "/certificate/one"
			}
			if status == "invalid" {
				response["error"] = map[string]string{"type": "urn:ietf:params:acme:error:rejectedIdentifier", "detail": "private diagnostic"}
			}
		}
		f.mu.Unlock()
		order, err := s.InspectOrder(context.Background(), f.server.URL+"/order/one", csr, orderHost, public)
		if err != nil || order.Status != status {
			t.Fatalf("bounded state observation: %v", err)
		}
	}
	before := f.counts()
	lease, err := s.lease(false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateOrder(context.Background(), csr, orderHost, public)
	accountRelease(lease)
	if err != ErrBusy || f.counts() != before {
		t.Fatal("order bypassed shared account lease")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.CreateOrder(ctx, csr, orderHost, public); err != ErrCancelled || f.counts() != before {
		t.Fatal("cancelled order performed network work")
	}
}

func TestOrderAcceptsOnlyBoundedAdvertisedDefaultProfiles(t *testing.T) {
	for _, profile := range []string{"default", "bad\nprofile", strings.Repeat("a", 65)} {
		t.Run(profile, func(t *testing.T) {
			s, f, b := orderFixture(t)
			csr, public := orderRequest(t)
			f.mu.Lock()
			f.profiles = map[string]string{profile: "https://docs.example.test/profile"}
			b.mutate = func(response map[string]any) { response["profile"] = profile }
			f.mu.Unlock()
			order, err := s.CreateOrder(context.Background(), csr, orderHost, public)
			if profile == "default" {
				if err != nil || order.Profile != profile {
					t.Fatal("advertised CA default profile rejected")
				}
			} else if err != ErrOrder {
				t.Fatal("unsafe profile metadata accepted")
			}
		})
	}
}
