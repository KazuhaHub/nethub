package guiacme

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/crypto/acme"
)

func TestDNS01BoundRecordAndAcceptance(t *testing.T) {
	s, f, b, order, csr, public := http01Fixture(t)
	ctx := context.Background()
	if _, err := s.PrepareDNS01(ctx, order, csr, public); err != ErrOrder {
		t.Fatalf("HTTP-only authorization: %v", err)
	}

	f.mu.Lock()
	asDNS := func(challenge map[string]any) { challenge["type"] = "dns-01" }
	b.authMutate = func(auth map[string]any) {
		asDNS(auth["challenges"].([]any)[0].(map[string]any))
	}
	b.acceptMutate = asDNS
	f.mu.Unlock()

	proof, err := s.PrepareDNS01(ctx, order, csr, public)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	sdk := acme.Client{Key: key}
	want, err := sdk.DNS01ChallengeRecord(strings.Repeat("A", 43))
	if err != nil {
		t.Fatal(err)
	}
	name, value, required := proof.Record()
	if !required || name != "_acme-challenge."+order.Host+"." || len(value) != 43 || value != want {
		t.Fatal("incorrect DNS TXT proof")
	}
	if encoded, _ := json.Marshal(proof); string(encoded) != "{}" {
		t.Fatal("challenge escaped through ordinary JSON")
	}

	changed := proof
	changed.KeyAuthorization = "changed"
	if _, err := s.AcceptDNS01(ctx, changed, csr, public); err != ErrOrder {
		t.Fatalf("changed TXT proof: %v", err)
	}
	for range 2 {
		accepted, err := s.AcceptDNS01(ctx, proof, csr, public)
		if err != nil || accepted.Status != acme.StatusProcessing {
			t.Fatalf("accept: %v", err)
		}
	}
	f.mu.Lock()
	count := b.accepts
	b.authValid = true
	f.mu.Unlock()
	if count != 1 {
		t.Fatalf("accepted %d times", count)
	}
	complete, err := s.PrepareDNS01(ctx, order, csr, public)
	if _, _, needed := complete.Record(); err != nil || needed || !complete.Complete {
		t.Fatalf("validated authorization: %v", err)
	}
}
