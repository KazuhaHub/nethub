package relaytrust

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCancellationReceiptBindsIntentAndRejectsAmbiguousResponses(t *testing.T) {
	base, now := switchFixture()
	c := Cancellation{SwitchRequest: base.SwitchRequest, ServerName: base.ServerName, IntentDigest: strings.Repeat("e", 64), CancelledAt: now}
	encode := func(v Cancellation) []byte {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if !c.Valid(base.ServerName, now) {
		t.Fatal("valid cancellation refused")
	}
	for _, change := range []func(*Cancellation){
		func(v *Cancellation) { v.ID = "00000000-0000-0000-0000-000000000000" }, func(v *Cancellation) { v.NextRoot = v.PreviousRoot },
		func(v *Cancellation) { v.NextLeaf = v.PreviousLeaf }, func(v *Cancellation) { v.IntentDigest = "invalid" },
		func(v *Cancellation) { v.ServerName = "other.example.test" }, func(v *Cancellation) { v.CancelledAt = now.Add(6 * time.Second) }, func(v *Cancellation) { v.CancelledAt = time.Time{} },
	} {
		bad := c
		change(&bad)
		if _, err := decodeCancellation(encode(bad), base.ServerName, now); err == nil {
			t.Fatal("invalid cancellation accepted")
		}
	}
	for _, raw := range []string{"null", strings.TrimSuffix(string(encode(c)), "}") + `,"intent_sha256":"changed"}`, strings.TrimSuffix(string(encode(c)), "}") + `,"extra":true}`} {
		if _, err := decodeCancellation([]byte(raw), base.ServerName, now); err == nil {
			t.Fatal("ambiguous cancellation receipt accepted")
		}
	}
	calls := 0
	p := Publisher{ServerName: c.ServerName, Now: func() time.Time { return now }, Run: func(ctx context.Context, statement []byte) ([]byte, error) {
		calls++
		if _, ok := ctx.Deadline(); !ok || !strings.Contains(string(statement), "SET SESSION AUTHORIZATION nethub_issuer;") {
			t.Fatal("unbounded or unrestricted cancellation query")
		}
		return encode(c), nil
	}}
	if _, err := p.CancelSwitch(context.Background(), c.SwitchRequest, c.IntentDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ReadCancellation(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	before := calls
	if _, err := p.CancelSwitch(context.Background(), c.SwitchRequest, "'"); err == nil || calls != before {
		t.Fatal("invalid cancellation reached SQL")
	}
	rebound := c.SwitchRequest
	rebound.NextLeaf = rebound.NextRoot
	if _, err := p.CancelSwitch(context.Background(), rebound, c.IntentDigest); err == nil {
		t.Fatal("rebound cancellation response accepted")
	}
}
