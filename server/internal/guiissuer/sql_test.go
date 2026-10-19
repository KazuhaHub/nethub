package guiissuer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPrivateSQLStoreFencesVersionsAndBoundIdentity(t *testing.T) {
	raw, now := snapshotFixture(t)
	w, account, _, _ := progressFixture(t)
	marshal := func() []byte { b, _ := json.Marshal(raw); return b }
	var input string
	s := SQLStore{Domain: "devices.example.com", AllowsURL: account.AllowsURL, Now: func() time.Time { return now }, Run: func(ctx context.Context, b []byte) ([]byte, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 16*time.Second {
			t.Fatal("SQL operation unbounded")
		}
		input = string(b)
		return marshal(), nil
	}}
	// Both fixtures use the same public request, but independent wall clocks.
	w, err := DecodeSnapshot(marshal(), s.Domain, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.Claim(context.Background())
	if err != nil || claimed.Lease.ID != w.Lease.ID {
		t.Fatal("claim failed", err)
	}
	if !strings.Contains(input, "SET log_statement=none;") || strings.Index(input, "SET log_min_error_statement=panic;") > strings.Index(input, "SET SESSION AUTHORIZATION") {
		t.Fatal("private logging settings not set before role reduction")
	}
	if !strings.Contains(input, "SET statement_timeout='10s';") || !strings.Contains(input, "SET lock_timeout='5s';") {
		t.Fatal("database work outlives disconnected runner")
	}
	raw.Job.Version++
	renewed, err := s.Renew(context.Background(), w)
	if err != nil || renewed.Lease.Version != w.Lease.Version+1 {
		t.Fatal("renew failed", err)
	}
	raw.Job.Version++
	if _, err := s.Renew(context.Background(), w); !errors.Is(err, ErrDatabase) {
		t.Fatal("version jump accepted")
	}
	raw.Job.Version--
	raw.Job.RequestID = "00000000-0000-0000-0000-000000000001"
	if _, err := s.Renew(context.Background(), w); !errors.Is(err, ErrDatabase) {
		t.Fatal("changed binding accepted")
	}
}

func TestPrivateSQLStoreRejectsAmbiguousOutputAndUntrustedArguments(t *testing.T) {
	w, account, _, now := progressFixture(t)
	called := 0
	response := []byte("null")
	s := SQLStore{Domain: "devices.example.com", AllowsURL: account.AllowsURL, Now: func() time.Time { return now }, Run: func(context.Context, []byte) ([]byte, error) { called++; return response, nil }}
	if got, err := s.Claim(context.Background()); err != nil || got != nil {
		t.Fatal("empty queue mismatch")
	}
	for _, b := range [][]byte{nil, []byte("null\nnull"), bytes.Repeat([]byte("x"), 131073)} {
		response = b
		if _, err := s.Claim(context.Background()); !errors.Is(err, ErrDatabase) {
			t.Fatal("ambiguous output accepted")
		}
	}
	before := called
	w.Lease.Token = "'quoted'"
	if _, err := s.Renew(context.Background(), w); err == nil || called != before {
		t.Fatal("untrusted lease entered SQL")
	}
	w, _, _, _ = progressFixture(t)
	if err := s.Release(context.Background(), w, "waiting');SELECT secret"); err == nil || called != before {
		t.Fatal("untrusted reason entered SQL")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Claim(ctx); err == nil || called != before {
		t.Fatal("cancelled context started SQL")
	}
	s.Run = func(context.Context, []byte) ([]byte, error) {
		return []byte("sensitive database diagnostic"), errors.New("sensitive runner error")
	}
	if _, err := s.Claim(context.Background()); err != ErrDatabase {
		t.Fatal("private runner diagnostic escaped")
	}
}

func TestPrivateSQLStoreUsesExplicitCheckpointAndCompletionCodecs(t *testing.T) {
	w, p, chain, roots, allows, now := materialFixture(t)
	var input string
	s := SQLStore{Domain: "devices.example.com", AllowsURL: allows, Now: func() time.Time { return now }, Run: func(_ context.Context, b []byte) ([]byte, error) { input = string(b); return []byte("null"), nil }}
	if _, err := s.Save(context.Background(), w, p); err != ErrDatabase {
		t.Fatal("fenced save accepted")
	}
	if strings.Contains(input, p.Order.URI) || !strings.Contains(input, "convert_from(decode('") {
		t.Fatal("checkpoint embedded as SQL text")
	}
	m, err := PrepareMaterial(w, p, chain, roots, allows, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Finish(context.Background(), w, m); err != ErrDatabase || strings.Contains(input, "BEGIN CERTIFICATE") {
		t.Fatal("completion codec did not fence null or encode public bytes")
	}
	// Material validation is covered independently; this check refuses an
	// invalid completion without giving malformed public bytes to PostgreSQL.
	input = ""
	if _, err := s.Finish(context.Background(), w, Material{}); err != ErrMaterial || input != "" {
		t.Fatal("invalid completion entered SQL")
	}
}
