package guiissuer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guiacme"
)

func progressFixture(t *testing.T) (Snapshot, *guiacme.AccountStore, guiacme.Order, time.Time) {
	t.Helper()
	raw, now := snapshotFixture(t)
	data, _ := json.Marshal(raw)
	work, err := DecodeSnapshot(data, "devices.example.com", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	account, err := guiacme.NewAccountStore(filepath.Join(t.TempDir(), "account"), guiacme.Config{DirectoryURL: "https://acme.example.test/directory", ContactEmail: "issuer@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	order := guiacme.Order{URI: "https://acme.example.test/order/one", Host: work.Host, RequestFingerprint: work.CSRFingerprint, Status: "pending", AuthorizationURL: "https://acme.example.test/authz/one", FinalizeURL: "https://acme.example.test/finalize/one", Expires: now.Add(time.Hour)}
	return work, account, order, now
}

func progressFrame(t *testing.T, p Progress, work Snapshot, account *guiacme.AccountStore) []byte {
	t.Helper()
	data, err := EncodeProgress(p, work, account.AllowsURL)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := json.Marshal(struct {
		Phase      string          `json:"phase"`
		Checkpoint json.RawMessage `json:"checkpoint"`
	}{p.Phase, data})
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestExplicitProgressRoundTripRetainsOriginalOrderAndProof(t *testing.T) {
	work, account, order, now := progressFixture(t)
	proof := guiacme.HTTP01{Order: order, URI: "https://acme.example.test/challenge/one", Token: strings.Repeat("A", 22), KeyAuthorization: strings.Repeat("A", 22) + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{31}, 32)), Status: "processing", ExpiresAt: now.Add(5 * time.Minute)}
	for _, phase := range []string{"order_intent", "order_saved", "proof_saved", "proof_live", "validating", "finalizing"} {
		p := Progress{Phase: phase}
		if phase != "order_intent" {
			copy := order
			p.Order = &copy
		}
		if phase == "proof_saved" || phase == "proof_live" || phase == "validating" || phase == "finalizing" {
			p.Proof = &proof
			p.Generation = strings.Repeat("a", 32)
		}
		if phase == "finalizing" {
			p.Order.Status = "ready"
			p.Retired = true
		}
		frame := progressFrame(t, p, work, account)
		result, err := DecodeProgress(frame, work, account.AllowsURL)
		if err != nil || result.Phase != phase {
			t.Fatal("checkpoint round trip failed", err)
		}
		if p.Order != nil && !sameOrderIdentity(*p.Order, *result.Order) {
			t.Fatal("checkpoint changed the order identity")
		}
		if p.Proof != nil && (result.Proof.URI != proof.URI || result.Proof.Token != proof.Token || result.Proof.KeyAuthorization != proof.KeyAuthorization || result.Generation != p.Generation || result.Retired != p.Retired) {
			t.Fatal("checkpoint discarded original publication metadata")
		}
		ordinary, _ := json.Marshal(p)
		if string(ordinary) != "{}" {
			t.Fatal("private checkpoint reached ordinary status JSON")
		}
	}
}

func TestProgressRejectsUnapprovedOrMismatchedOrderAndPublication(t *testing.T) {
	for _, change := range []func(*Progress){
		func(p *Progress) { p.Order.URI = "https://external.example.test/order" },
		func(p *Progress) { p.Order.AuthorizationURL = "http://acme.example.test/authz" },
		func(p *Progress) { p.Order.Host = "other.example.com" },
		func(p *Progress) { p.Order.RequestFingerprint = strings.Repeat("0", 64) },
		func(p *Progress) { p.Order.Profile = strings.Repeat("x", 65) },
		func(p *Progress) { p.Order.Status = "invalid" },
		func(p *Progress) { p.Order.CertificateURL = "https://acme.example.test/cert" },
		func(p *Progress) { p.Phase = "finalizing" },
	} {
		work, account, order, _ := progressFixture(t)
		p := Progress{Phase: "order_saved", Order: &order}
		change(&p)
		if _, err := EncodeProgress(p, work, account.AllowsURL); err == nil {
			t.Fatal("unsafe checkpoint admitted")
		}
	}
	work, account, order, now := progressFixture(t)
	p := Progress{Phase: "proof_live", Order: &order, Proof: &guiacme.HTTP01{Order: order, URI: "https://acme.example.test/challenge/one", Token: strings.Repeat("A", 22), KeyAuthorization: strings.Repeat("A", 22) + "." + strings.Repeat("A", 42) + "B", Status: "pending", ExpiresAt: now.Add(time.Minute)}, Generation: strings.Repeat("b", 32)}
	if _, err := EncodeProgress(p, work, account.AllowsURL); err == nil {
		t.Fatal("noncanonical account thumbprint admitted")
	}
	if _, err := EncodeProgress(Progress{Phase: "order_intent"}, work, nil); err == nil {
		t.Fatal("missing protected URL policy admitted")
	}
	good := progressFrame(t, Progress{Phase: "order_saved", Order: &order}, work, account)
	for _, bad := range [][]byte{append(good, []byte("{}")...), []byte(strings.TrimSuffix(string(good), "}") + `,"phase":"finalizing"}`), []byte(strings.Replace(string(good), `"profile":""`, `"profile":null`, 1)), []byte(strings.Replace(string(good), `"uri":`, `"URI":`, 1))} {
		if _, err := DecodeProgress(bad, work, account.AllowsURL); err == nil {
			t.Fatal("ambiguous/missing checkpoint identity accepted")
		}
	}
}

func TestExpiredPublicationRemainsAvailableForExactCleanup(t *testing.T) {
	work, account, order, now := progressFixture(t)
	p := Progress{Phase: "proof_live", Order: &order, Proof: &guiacme.HTTP01{Order: order, URI: "https://acme.example.test/challenge/old", Token: strings.Repeat("A", 22), KeyAuthorization: strings.Repeat("A", 22) + "." + strings.Repeat("A", 43), Status: "pending", ExpiresAt: now.Add(-time.Minute)}, Generation: strings.Repeat("c", 32)}
	frame := progressFrame(t, p, work, account)
	restored, err := DecodeProgress(frame, work, account.AllowsURL)
	if err != nil || restored.Proof.ExpiresAt != p.Proof.ExpiresAt || restored.Generation != p.Generation {
		t.Fatal("stale publication could not be retired by exact identity", err)
	}
}
