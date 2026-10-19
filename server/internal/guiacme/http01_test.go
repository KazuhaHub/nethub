package guiacme

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func http01Fixture(t *testing.T) (*AccountStore, *accountFixture, *orderBehavior, Order, []byte, string) {
	t.Helper()
	s, f, b := orderFixture(t)
	csr, public := orderRequest(t)
	order, err := s.CreateOrder(context.Background(), csr, orderHost, public)
	if err != nil {
		t.Fatal(err)
	}
	return s, f, b, order, csr, public
}

func TestHTTP01PreparationAndIdempotentAcceptance(t *testing.T) {
	s, f, b, order, csr, public := http01Fixture(t)
	challenge, err := s.PrepareHTTP01(context.Background(), order, csr, public)
	if err != nil || challenge.Complete || challenge.Status != "pending" || !strings.HasPrefix(challenge.KeyAuthorization, challenge.Token+".") {
		t.Fatalf("prepare: %v", err)
	}
	f.mu.Lock()
	count := b.accepts
	f.mu.Unlock()
	if count != 0 {
		t.Fatal("preparation accepted a challenge")
	}
	if encoded, _ := json.Marshal(challenge); string(encoded) != "{}" {
		t.Fatal("challenge escaped through ordinary JSON")
	}
	accepted, err := s.AcceptHTTP01(context.Background(), challenge, csr, public)
	if err != nil || accepted.Status != "processing" {
		t.Fatalf("accept: %v", err)
	}
	if _, err := s.AcceptHTTP01(context.Background(), challenge, csr, public); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	count = b.accepts
	b.authValid = true
	f.mu.Unlock()
	if count != 1 {
		t.Fatal("processing challenge accepted again")
	}
	complete, err := s.AcceptHTTP01(context.Background(), challenge, csr, public)
	if err != nil || !complete.Complete {
		t.Fatal("validated authorization not recovered")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if b.accepts != 1 {
		t.Fatal("validated authorization accepted again")
	}
}

func TestHTTP01RejectsChangedPublicationProof(t *testing.T) {
	for _, mutation := range []string{"uri", "token", "key-authorization", "expired", "extended-expiry", "complete", "fingerprint"} {
		t.Run(mutation, func(t *testing.T) {
			s, f, b, order, csr, public := http01Fixture(t)
			proof, err := s.PrepareHTTP01(context.Background(), order, csr, public)
			if err != nil {
				t.Fatal(err)
			}
			before := f.counts()
			switch mutation {
			case "uri":
				proof.URI = f.server.URL + "/challenge/other"
			case "token":
				proof.Token = strings.Repeat("B", 43)
			case "key-authorization":
				proof.KeyAuthorization += "changed"
			case "expired":
				proof.ExpiresAt = time.Now().Add(-time.Hour)
			case "extended-expiry":
				proof.ExpiresAt = proof.ExpiresAt.Add(time.Hour)
			case "complete":
				proof.Complete = true
			case "fingerprint":
				proof.Order.RequestFingerprint = strings.Repeat("f", 64)
			}
			if _, err := s.AcceptHTTP01(context.Background(), proof, csr, public); err != ErrOrder {
				t.Fatalf("changed proof: %v", err)
			}
			if mutation == "fingerprint" && f.counts() != before {
				t.Fatal("invalid request fingerprint reached the network")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if b.accepts != 0 {
				t.Fatal("changed proof accepted")
			}
		})
	}
}

func TestHTTP01RejectsChangedOrderAndAuthorization(t *testing.T) {
	for _, mutation := range []string{"order-authz", "order-finalize", "identifier", "wildcard", "expired", "status", "missing-http", "duplicate-http", "token", "url", "challenge-error"} {
		t.Run(mutation, func(t *testing.T) {
			s, f, b, order, csr, public := http01Fixture(t)
			f.mu.Lock()
			if strings.HasPrefix(mutation, "order-") {
				b.mutate = func(response map[string]any) {
					if mutation == "order-authz" {
						response["authorizations"] = []string{f.server.URL + "/authz/other"}
					} else {
						response["finalize"] = f.server.URL + "/finalize/other"
					}
				}
			} else {
				b.authMutate = func(response map[string]any) {
					challenges := response["challenges"].([]any)
					challenge := challenges[0].(map[string]any)
					switch mutation {
					case "identifier":
						response["identifier"] = map[string]string{"type": "dns", "value": "other.devices.example.test"}
					case "wildcard":
						response["wildcard"] = true
					case "expired":
						response["expires"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
					case "status":
						response["status"] = "invalid"
					case "missing-http":
						challenge["type"] = "dns-01"
					case "duplicate-http":
						response["challenges"] = []any{challenge, challenge}
					case "token":
						challenge["token"] = "bad/token"
					case "url":
						challenge["url"] = "https://untrusted.example.test/challenge"
					case "challenge-error":
						challenge["error"] = map[string]string{"type": "urn:ietf:params:acme:error:rejectedIdentifier", "detail": "private diagnostic"}
					}
				}
			}
			f.mu.Unlock()
			if _, err := s.PrepareHTTP01(context.Background(), order, csr, public); err != ErrOrder {
				t.Fatalf("changed authority: %v", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if b.accepts != 0 {
				t.Fatal("invalid authorization accepted")
			}
		})
	}
}

func TestHTTP01LostAcceptanceReplyRecoversWithoutReposting(t *testing.T) {
	s, f, b, order, csr, public := http01Fixture(t)
	proof, err := s.PrepareHTTP01(context.Background(), order, csr, public)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	b.loseAccept = true
	f.mu.Unlock()
	if _, err := s.AcceptHTTP01(context.Background(), proof, csr, public); err != ErrRemote {
		t.Fatal("ambiguous acceptance not bounded")
	}
	f.mu.Lock()
	b.loseAccept = false
	f.mu.Unlock()
	current, err := s.AcceptHTTP01(context.Background(), proof, csr, public)
	if err != nil || current.Status != "processing" {
		t.Fatalf("recovery: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if b.accepts != 1 {
		t.Fatal("ambiguous acceptance was repeated")
	}
}

func TestHTTP01RejectsChangedAcceptanceResponse(t *testing.T) {
	s, f, b, order, csr, public := http01Fixture(t)
	proof, err := s.PrepareHTTP01(context.Background(), order, csr, public)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	b.acceptMutate = func(response map[string]any) { response["url"] = f.server.URL + "/challenge/other" }
	f.mu.Unlock()
	if _, err := s.AcceptHTTP01(context.Background(), proof, csr, public); err != ErrOrder {
		t.Fatal("changed challenge response accepted")
	}
	f.mu.Lock()
	count := b.accepts
	f.mu.Unlock()
	if count != 1 {
		t.Fatal("unexpected accept attempt count")
	}
	if _, err := s.AcceptHTTP01(context.Background(), proof, csr, public); err != nil {
		t.Fatal("processing state could not be recovered")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if b.accepts != 1 {
		t.Fatal("changed response recovery repeated acceptance")
	}
}
