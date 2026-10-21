package relaytrust

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func generationFixture(t *testing.T) (generationRecord, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	b, err := Parse(rootFixture(t, 1, now, nil), now)
	if err != nil {
		t.Fatal(err)
	}
	start, end := b.Window()
	return generationRecord{ID: "11111111-1111-4111-8111-111111111111", Number: 1, ServerName: "relay.example.test", CAPEM: b.PEM(), Fingerprint: b.Fingerprint(), Roots: b.RootFingerprints(), NotBefore: start, ValidUntil: end, PublishedAt: now}, now
}

func TestGenerationRevalidatesIndependentIdentityAndMaterial(t *testing.T) {
	raw, now := generationFixture(t)
	encode := func(r generationRecord) []byte {
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	g, err := DecodeGeneration(encode(raw), raw.ServerName, now)
	if err != nil || g.ID != raw.ID || g.Number != 1 {
		t.Fatal(err)
	}
	for _, change := range []func(*generationRecord){
		func(r *generationRecord) { r.ID = "00000000-0000-0000-0000-000000000000" },
		func(r *generationRecord) { r.Number = 0 }, func(r *generationRecord) { r.ServerName = "other.example.test" },
		func(r *generationRecord) { r.CAPEM = "\n" + r.CAPEM }, func(r *generationRecord) { r.Fingerprint = strings.Repeat("0", 64) },
		func(r *generationRecord) { r.Roots = []string{strings.Repeat("0", 64)} },
		func(r *generationRecord) { r.NotBefore = r.NotBefore.Add(time.Second) },
		func(r *generationRecord) { r.ValidUntil = r.ValidUntil.Add(time.Second) },
		func(r *generationRecord) { r.PublishedAt = now.Add(6 * time.Second) },
		func(r *generationRecord) { r.PublishedAt = time.Time{} },
	} {
		bad := raw
		change(&bad)
		if _, err := DecodeGeneration(encode(bad), raw.ServerName, now); err != ErrGeneration {
			t.Fatal("mismatched generation accepted")
		}
	}
	data := string(encode(raw))
	data = strings.TrimSuffix(data, "}") + `,"generation":2}`
	if _, err := DecodeGeneration([]byte(data), raw.ServerName, now); err != ErrGeneration {
		t.Fatal("duplicate generation accepted")
	}
	data = strings.TrimSuffix(string(encode(raw)), "}") + `,"extra":true}`
	if _, err := DecodeGeneration([]byte(data), raw.ServerName, now); err != ErrGeneration {
		t.Fatal("unknown private snapshot field accepted")
	}
	if _, err := DecodeGeneration(encode(raw), raw.ServerName, raw.ValidUntil); err != ErrGeneration {
		t.Fatal("expired generation accepted")
	}
}

func TestPublisherUsesBoundedPrivateSQLAndFencesResponses(t *testing.T) {
	raw, now := generationFixture(t)
	response, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	p := Publisher{ServerName: raw.ServerName, Now: func() time.Time { return now }, Run: func(ctx context.Context, input []byte) ([]byte, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 16*time.Second {
			t.Fatal("unbounded publication SQL")
		}
		if !strings.Contains(string(input), "SET SESSION AUTHORIZATION nethub_issuer;") || !strings.Contains(string(input), "SET log_min_error_statement=panic;") {
			t.Fatal("private SQL identity/log protection missing")
		}
		if strings.Contains(string(input), "BEGIN CERTIFICATE") {
			t.Fatal("public PEM embedded unencoded in SQL")
		}
		return response, nil
	}}
	if _, err := p.Publish(context.Background(), "", raw.CAPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Current(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"null", "null\nnull", "diagnostic", strings.Repeat("x", 131073)} {
		response = []byte(value)
		if _, err := p.Publish(context.Background(), raw.ID, raw.CAPEM); err != ErrGeneration {
			t.Fatal("ambiguous publication accepted")
		}
	}
	response = []byte("null")
	if current, err := p.Current(context.Background()); err != nil || current != nil {
		t.Fatal("empty current trust differs", err)
	}
	before := calls
	if _, err := p.Publish(context.Background(), "quote'", raw.CAPEM); err != ErrGeneration || calls != before {
		t.Fatal("untrusted CAS entered SQL")
	}
	p.ServerName = "relay.example.test'"
	if _, err := p.Current(context.Background()); err != ErrGeneration || calls != before {
		t.Fatal("untrusted hostname entered SQL")
	}
	p.ServerName = raw.ServerName
	p.Run = func(context.Context, []byte) ([]byte, error) {
		return []byte("sensitive diagnostic"), errors.New("sensitive runner")
	}
	if _, err := p.Current(context.Background()); err != ErrGeneration {
		t.Fatal("raw runner error escaped")
	}
}
