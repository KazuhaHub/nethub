package http01

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanupObservationRejectsMissingStaleFutureFailedAndWrongNamespace(t *testing.T) {
	p, _, now := fixture(t)
	if p.CleanupReady(*now) == nil {
		t.Fatal("missing cleanup observation accepted")
	}
	result := SweepResult{CycleComplete: true}
	if err := p.RecordCleanup(result, true, *now); err != nil || p.CleanupReady(*now) != nil {
		t.Fatal("complete cleanup observation unavailable")
	}
	if p.CleanupReady(now.Add(2*time.Minute)) == nil || p.CleanupReady(now.Add(-6*time.Second)) == nil {
		t.Fatal("stale or future cleanup observation accepted")
	}
	if err := p.RecordCleanup(result, false, *now); err != nil || p.CleanupReady(*now) == nil {
		t.Fatal("failed cleanup retained success")
	}
	result.CycleComplete = false
	if err := p.RecordCleanup(result, true, *now); err != nil || p.CleanupReady(*now) == nil {
		t.Fatal("partial cleanup accepted")
	}
	result.CycleComplete = true
	if err := p.RecordCleanup(result, true, *now); err != nil {
		t.Fatal(err)
	}
	if _, err := p.SweepExpired(context.Background()); err != nil {
		t.Fatal("own health metadata broke next cleanup", err)
	}
	var health cleanupHealth
	path := filepath.Join(p.state, "cleanup.json")
	if readCanonical(path, &health) != nil {
		t.Fatal("fixture observation")
	}
	health.Namespace = "different"
	if writeCanonical(path, health) != nil || p.CleanupReady(*now) == nil {
		t.Fatal("foreign namespace observation accepted")
	}
}
