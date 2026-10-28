package dbbackup

import (
	"strings"
	"testing"
	"time"
)

func successfulState() State {
	started := time.Date(2026, 10, 27, 1, 2, 3, 0, time.UTC)
	return State{Version: 1, DeploymentFingerprint: strings.Repeat("a", 64), AttemptStartedAt: started, AttemptDeadline: started.Add(time.Minute), Outcome: "succeeded", LatestSuccess: &Receipt{Archive: "nethub-20261027T010203Z-0123456789abcdef.dump", SHA256: strings.Repeat("b", 64), Bytes: 1024, StartedAt: started, CompletedAt: started.Add(time.Second), Role: "nethub_backup", DumpVersion: "16.10"}}
}

func TestStateCoherence(t *testing.T) {
	if !validState(successfulState()) {
		t.Fatal("valid completed attempt refused")
	}
	cases := []struct {
		name   string
		change func(*State)
	}{
		{"missing receipt", func(s *State) { s.LatestSuccess = nil }},
		{"version", func(s *State) { s.Version = 2 }},
		{"deployment", func(s *State) { s.DeploymentFingerprint = "invalid" }},
		{"outcome", func(s *State) { s.Outcome = "unknown" }},
		{"zero start", func(s *State) { s.AttemptStartedAt = time.Time{} }},
		{"deadline", func(s *State) { s.AttemptDeadline = s.AttemptStartedAt }},
		{"excessive budget", func(s *State) { s.AttemptDeadline = s.AttemptStartedAt.Add(31 * time.Minute) }},
		{"receipt from another attempt", func(s *State) { s.AttemptStartedAt = s.AttemptStartedAt.Add(time.Second) }},
		{"late completion", func(s *State) { s.LatestSuccess.CompletedAt = s.AttemptDeadline.Add(time.Second) }},
		{"previous success after running attempt", func(s *State) { s.Outcome = "running" }},
		{"previous success after failed attempt", func(s *State) { s.Outcome = "failed" }},
		{"traversal", func(s *State) { s.LatestSuccess.Archive = "../outside.dump" }},
		{"archive date mismatch", func(s *State) { s.LatestSuccess.Archive = "nethub-20261028T010203Z-0123456789abcdef.dump" }},
		{"bad digest", func(s *State) { s.LatestSuccess.SHA256 = "invalid" }},
		{"empty archive", func(s *State) { s.LatestSuccess.Bytes = 0 }},
		{"excessive archive", func(s *State) { s.LatestSuccess.Bytes = 1<<40 + 1 }},
		{"wrong role", func(s *State) { s.LatestSuccess.Role = "nethub_owner" }},
		{"wrong major", func(s *State) { s.LatestSuccess.DumpVersion = "17.0" }},
		{"noncanonical version", func(s *State) { s.LatestSuccess.DumpVersion = "16.01" }},
		{"completion before start", func(s *State) { s.LatestSuccess.CompletedAt = s.LatestSuccess.StartedAt.Add(-time.Second) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := successfulState()
			tc.change(&s)
			if validState(s) {
				t.Fatal("incoherent state accepted")
			}
		})
	}
	for _, outcome := range []string{"running", "failed"} {
		s := successfulState()
		s.Outcome = outcome
		s.AttemptStartedAt = s.AttemptStartedAt.Add(time.Hour)
		s.AttemptDeadline = s.AttemptStartedAt.Add(time.Minute)
		if !validState(s) {
			t.Fatalf("retained previous success refused for %s", outcome)
		}
		s.LatestSuccess = nil
		if !validState(s) {
			t.Fatalf("first %s attempt refused", outcome)
		}
	}
}
