package relaystate

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"
)

func sampleAnomaly(kind AnomalyKind, route string) Anomaly {
	a := Anomaly{Kind: kind, ProxyKey: fmt.Sprintf("%x", sha256.Sum256([]byte(route)))}
	if kind != UnknownProxy {
		a.TenantID = "11111111-1111-4111-8111-111111111111"
		a.DeviceID = "22222222-2222-4222-8222-222222222222"
	}
	return a
}

func TestAnomalyConfirmationUsesThreeSeparateFifteenSecondSamples(t *testing.T) {
	start := time.Now()
	tracker, err := NewAnomalyTracker(start, 3)
	if err != nil {
		t.Fatal(err)
	}
	anomaly := sampleAnomaly(DomainMismatch, "one route")
	for seconds := 0; seconds <= 45; seconds += 5 {
		confirmed, err := tracker.Sample(start.Add(time.Duration(seconds)*time.Second), []Anomaly{anomaly})
		want := 0
		if seconds == 45 {
			want = 1
		}
		if err != nil || len(confirmed) != want {
			t.Fatalf("confirmation at %ds: %v %v", seconds, confirmed, err)
		}
	}
}

func TestAnomalyPendingReceiptRetriesAndRejectsStaleAcknowledgement(t *testing.T) {
	start := time.Now()
	tracker, _ := NewAnomalyTracker(start, 3)
	anomaly := sampleAnomaly(RevokedOnline, "route")
	var first AnomalyConfirmation
	for seconds := 15; seconds <= 45; seconds += 15 {
		batch, err := tracker.Sample(start.Add(time.Duration(seconds)*time.Second), []Anomaly{anomaly})
		if err != nil {
			t.Fatal(err)
		}
		if seconds == 45 {
			first = batch[0]
		}
	}
	batch, err := tracker.Sample(start.Add(60*time.Second), []Anomaly{anomaly})
	if err != nil || len(batch) != 1 || tracker.Persisted(first) {
		t.Fatal("failed persistence lost retry or stale receipt was accepted")
	}
	if !tracker.Persisted(batch[0]) || tracker.Persisted(batch[0]) {
		t.Fatal("receipt must be acknowledged exactly once")
	}
	batch, err = tracker.Sample(start.Add(75*time.Second), []Anomaly{anomaly})
	if err != nil || len(batch) != 0 {
		t.Fatal("persisted incident repeated")
	}
	tracker.Sample(start.Add(90*time.Second), nil)
	for seconds := 105; seconds <= 135; seconds += 15 {
		batch, _ = tracker.Sample(start.Add(time.Duration(seconds)*time.Second), []Anomaly{anomaly})
	}
	if len(batch) != 1 || tracker.Persisted(first) || !tracker.Persisted(batch[0]) {
		t.Fatal("new incident was lost or old receipt acknowledged it")
	}
}

func TestAnomalyFailuresGapsAndChangedRoutesBreakConfirmation(t *testing.T) {
	for _, interruption := range []string{"unavailable", "missing", "changed_route", "changed_kind", "gap"} {
		t.Run(interruption, func(t *testing.T) {
			start := time.Now()
			tracker, _ := NewAnomalyTracker(start, 3)
			anomaly := sampleAnomaly(DomainMismatch, "first")
			tracker.Sample(start.Add(15*time.Second), []Anomaly{anomaly})
			next := 45
			switch interruption {
			case "unavailable":
				tracker.Unavailable(start.Add(30 * time.Second))
			case "missing":
				tracker.Sample(start.Add(30*time.Second), nil)
			case "changed_route":
				tracker.Sample(start.Add(30*time.Second), []Anomaly{sampleAnomaly(DomainMismatch, "second")})
			case "changed_kind":
				tracker.Sample(start.Add(30*time.Second), []Anomaly{sampleAnomaly(RevokedOnline, "first")})
			case "gap":
				next = 60
			}
			for index := 0; index < 3; index++ {
				batch, err := tracker.Sample(start.Add(time.Duration(next+index*15)*time.Second), []Anomaly{anomaly})
				want := 0
				if index == 2 {
					want = 1
				}
				if err != nil || len(batch) != want {
					t.Fatalf("interruption combined separate incidents: %v %v", batch, err)
				}
			}
		})
	}
}

func TestAnomalyThresholdCountsAllConfirmedIncidentsAndNeverActsOnUnknown(t *testing.T) {
	start := time.Now()
	tracker, _ := NewAnomalyTracker(start, 1)
	known := sampleAnomaly(DomainMismatch, "known")
	unknown := sampleAnomaly(UnknownProxy, "unknown")
	var batch []AnomalyConfirmation
	for seconds := 15; seconds <= 45; seconds += 15 {
		batch, _ = tracker.Sample(start.Add(time.Duration(seconds)*time.Second), []Anomaly{known, unknown})
	}
	if len(batch) != 2 || !batch[0].AlarmOnly || !batch[1].AlarmOnly {
		t.Fatal("mass anomaly did not degrade the entire batch to alarms")
	}
	tracker, _ = NewAnomalyTracker(start, 2)
	for seconds := 15; seconds <= 45; seconds += 15 {
		batch, _ = tracker.Sample(start.Add(time.Duration(seconds)*time.Second), []Anomaly{known, unknown})
	}
	if len(batch) != 2 || batch[0].AlarmOnly || !batch[1].AlarmOnly {
		t.Fatal("threshold boundary or unknown route action policy changed")
	}
}

func TestAnomalyTrackerRejectsUnscopedMalformedAndOversizedSamples(t *testing.T) {
	start := time.Now()
	valid := sampleAnomaly(DomainMismatch, "valid")
	unscoped := valid
	unscoped.TenantID = ""
	raw := valid
	raw.ProxyKey = "sensitive-relay-name"
	unknown := sampleAnomaly(UnknownProxy, "unknown")
	unknown.TenantID = valid.TenantID
	for _, values := range [][]Anomaly{{valid, valid}, {unscoped}, {raw}, {unknown}, make([]Anomaly, MaxProxies+1)} {
		tracker, _ := NewAnomalyTracker(start, 1)
		if _, err := tracker.Sample(start.Add(15*time.Second), values); err != ErrAnomalySample {
			t.Fatal("unsafe sample was accepted")
		}
	}
	for _, maximum := range []int{0, MaxProxies + 1} {
		if _, err := NewAnomalyTracker(start, maximum); err != ErrAnomalySample {
			t.Fatal("invalid action budget accepted")
		}
	}
	if _, err := NewAnomalyTracker(time.Time{}, 1); err != ErrAnomalySample {
		t.Fatal("zero start time accepted")
	}
	tracker, _ := NewAnomalyTracker(start, 1)
	for _, at := range []time.Time{time.Time{}, start.Add(-time.Second)} {
		if _, err := tracker.Sample(at, []Anomaly{valid}); err != ErrAnomalySample {
			t.Fatal("invalid observation time accepted")
		}
	}
}
