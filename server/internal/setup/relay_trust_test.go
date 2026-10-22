package setup

import (
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaycert"
)

func TestPublicTrustPublicationCannotRetireConfiguredIssuer(t *testing.T) {
	now := time.Now()
	old, err := relaycert.Create("relay.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	next, err := relaycert.Create("relay.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, public := range [][]byte{old.CA, append(append([]byte{}, next.CA...), old.CA...)} {
		if _, err := relayTrustCandidate(public, old.CA, now); err != nil {
			t.Fatal("configured issuer was not retained", err)
		}
	}
	for _, public := range [][]byte{nil, next.CA, old.CAKey, append(append([]byte{}, old.CA...), old.CA...)} {
		if _, err := relayTrustCandidate(public, old.CA, now); err == nil {
			t.Fatal("unbacked, private, duplicate or empty material accepted")
		}
	}
	later := now.Add(11 * 365 * 24 * time.Hour)
	fresh, err := relaycert.Create("relay.example.test", later)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relayTrustCandidate(fresh.CA, old.CA, later); err == nil {
		t.Fatal("expired authority silently replaced through public publication")
	}
}

func TestRelayTrustOperationRequiresExplicitPublicationIntent(t *testing.T) {
	for _, o := range []RelayTrustOptions{{Action: "current"}, {Action: "publish", BundleFile: "/private/public.pem", Initialize: true},
		{Action: "publish", BundleFile: "/private/public.pem", ExpectedGeneration: "11111111-1111-4111-8111-111111111111"}} {
		if !validRelayTrustOperation(o) {
			t.Fatal("explicit operation refused")
		}
	}
	for _, o := range []RelayTrustOptions{{}, {Action: "unknown"}, {Action: "publish", Initialize: true},
		{Action: "publish", BundleFile: "/private/public.pem"},
		{Action: "publish", BundleFile: "/private/public.pem", Initialize: true, ExpectedGeneration: "11111111-1111-4111-8111-111111111111"},
		{Action: "current", BundleFile: "/private/public.pem"}, {Action: "current", Initialize: true}} {
		if validRelayTrustOperation(o) {
			t.Fatal("implicit or ambiguous operation accepted")
		}
	}
	for _, id := range []string{"not-a-generation", "00000000-0000-0000-0000-000000000000", "'"} {
		if validRelayTrustOperation(RelayTrustOptions{Action: "publish", BundleFile: "/private/public.pem", ExpectedGeneration: id}) {
			t.Fatal("malformed generation admitted before host inspection")
		}
	}
}
