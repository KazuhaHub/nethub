package relaytrust

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func switchFixture() (Switch, time.Time) {
	now := time.Now().UTC().Truncate(time.Second)
	return Switch{SwitchRequest: SwitchRequest{
		ID: "11111111-1111-4111-8111-111111111111", GenerationID: "22222222-2222-4222-8222-222222222222",
		PreviousRoot: strings.Repeat("a", 64), NextRoot: strings.Repeat("b", 64), PreviousLeaf: strings.Repeat("c", 64), NextLeaf: strings.Repeat("d", 64)},
		ServerName: "relay.example.test", Phase: "pending", CreatedAt: now}, now
}

func TestSwitchReceiptRefusesIncompleteAndReboundStates(t *testing.T) {
	base, now := switchFixture()
	encode := func(s Switch) []byte {
		t.Helper()
		data, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if _, err := decodeSwitch(encode(base), base.ServerName, now); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Switch){
		func(s *Switch) { s.ID = "00000000-0000-0000-0000-000000000000" },
		func(s *Switch) { s.NextRoot = s.PreviousRoot }, func(s *Switch) { s.NextLeaf = s.PreviousLeaf },
		func(s *Switch) { s.ServerName = "other.example.test" }, func(s *Switch) { s.Phase = "committed" },
		func(s *Switch) { s.Phase = "expired" }, func(s *Switch) { s.FinishedAt = &now },
		func(s *Switch) { s.ObservedLeaf = &s.NextLeaf }, func(s *Switch) { s.CreatedAt = now.Add(6 * time.Second) },
	} {
		bad := base
		change(&bad)
		if _, err := decodeSwitch(encode(bad), base.ServerName, now); err != ErrGeneration {
			t.Fatal("invalid switch receipt accepted")
		}
	}
	for _, phase := range []string{"committed", "rolled_back"} {
		done := base
		done.Phase = phase
		done.FinishedAt = &now
		observed := done.NextLeaf
		if phase == "rolled_back" {
			observed = done.PreviousLeaf
		}
		done.ObservedLeaf = &observed
		if _, err := decodeSwitch(encode(done), base.ServerName, now); err != nil {
			t.Fatal(err)
		}
		wrong := base.NextRoot
		done.ObservedLeaf = &wrong
		if _, err := decodeSwitch(encode(done), base.ServerName, now); err == nil {
			t.Fatal("wrong terminal leaf accepted")
		}
	}
	for _, suffix := range []string{`,"phase":"committed"}`, `,"extra":true}`} {
		if _, err := decodeSwitch([]byte(strings.TrimSuffix(string(encode(base)), "}")+suffix), base.ServerName, now); err == nil {
			t.Fatal("duplicate or unknown switch field accepted")
		}
	}
	// Pending state has no deadline: elapsed wall time cannot clear the fence.
	if _, err := decodeSwitch(encode(base), base.ServerName, now.AddDate(1, 0, 0)); err != nil {
		t.Fatal("old pending intent expired", err)
	}
}

func TestSwitchHostAdapterBindsRequestsBeforeMutation(t *testing.T) {
	state, now := switchFixture()
	calls := 0
	p := Publisher{ServerName: state.ServerName, Now: func() time.Time { return now }, Run: func(ctx context.Context, input []byte) ([]byte, error) {
		calls++
		if _, ok := ctx.Deadline(); !ok || !strings.Contains(string(input), "SET SESSION AUTHORIZATION nethub_issuer;") || !strings.Contains(string(input), "SET log_min_error_statement=panic;") {
			t.Fatal("host SQL boundary missing")
		}
		return json.Marshal(state)
	}}
	if _, err := p.BeginSwitch(context.Background(), state.SwitchRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ReadSwitch(context.Background(), state.ID); err != nil {
		t.Fatal(err)
	}
	altered := state.SwitchRequest
	altered.NextRoot = altered.NextLeaf
	before := calls
	if _, err := p.FinishSwitch(context.Background(), altered, "rolled_back", altered.PreviousLeaf); err == nil || calls != before+1 {
		t.Fatal("mismatched host identity reached mutation")
	}
	bad := state.SwitchRequest
	bad.ID = "'; SELECT 1;--"
	before = calls
	if _, err := p.BeginSwitch(context.Background(), bad); err == nil || calls != before {
		t.Fatal("invalid request reached SQL")
	}
	if _, err := p.FinishSwitch(context.Background(), state.SwitchRequest, "committed", state.PreviousLeaf); err == nil || calls != before {
		t.Fatal("wrong leaf reached SQL")
	}
	done := state
	done.Phase = "committed"
	done.FinishedAt = &now
	done.ObservedLeaf = &done.NextLeaf
	p.Run = func(ctx context.Context, input []byte) ([]byte, error) {
		if strings.Contains(string(input), "finish_relay_authority_switch(") {
			return json.Marshal(done)
		}
		return json.Marshal(state)
	}
	if _, err := p.FinishSwitch(context.Background(), state.SwitchRequest, "committed", state.NextLeaf); err != nil {
		t.Fatal(err)
	}
}
