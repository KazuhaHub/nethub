package relaystate

import (
	"errors"
	"regexp"
	"sync"
	"time"
)

const AnomalyInterval = 15 * time.Second
const AnomalyConfirmations = 3

var ErrAnomalySample = errors.New("invalid relay anomaly sample")
var proxyDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

type AnomalyKind string

const (
	UnknownProxy   AnomalyKind = "unknown_proxy"
	RevokedOnline  AnomalyKind = "revoked_online"
	DomainMismatch AnomalyKind = "domain_mismatch"
)

// Tenant and device IDs must come from the database. ProxyKey is a digest,
// never a relay-provided name or domain that could leak into logs or alerts.
type Anomaly struct {
	Kind                         AnomalyKind
	TenantID, DeviceID, ProxyKey string
}

func (a Anomaly) valid() bool {
	if !proxyDigest.MatchString(a.ProxyKey) {
		return false
	}
	if a.Kind == UnknownProxy {
		return a.TenantID == "" && a.DeviceID == ""
	}
	return (a.Kind == RevokedOnline || a.Kind == DomainMismatch) && uuid.MatchString(a.TenantID) && uuid.MatchString(a.DeviceID)
}

type AnomalyConfirmation struct {
	Anomaly
	Token     uint64
	AlarmOnly bool
}

type anomalyStreak struct {
	count     int
	token     uint64
	persisted bool
}

// AnomalyTracker confirms successful observations separately from the faster
// display poll. It does not authorize, revoke or persist anything itself.
type AnomalyTracker struct {
	mu         sync.Mutex
	last       time.Time
	maxActions int
	sequence   uint64
	streaks    map[Anomaly]anomalyStreak
}

func NewAnomalyTracker(started time.Time, maxActions int) (*AnomalyTracker, error) {
	if started.IsZero() || maxActions < 1 || maxActions > MaxProxies {
		return nil, ErrAnomalySample
	}
	return &AnomalyTracker{last: started, maxActions: maxActions, streaks: make(map[Anomaly]anomalyStreak)}, nil
}

// Unavailable breaks consecutive confirmation after a failed fetch or database
// check. Already persisted incidents can be rediscovered after recovery; storage
// must deduplicate their durable audit and action receipts.
func (t *AnomalyTracker) Unavailable(at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.streaks = make(map[Anomaly]anomalyStreak)
	if at.After(t.last) {
		t.last = at
	}
}

func (t *AnomalyTracker) Sample(at time.Time, anomalies []Anomaly) ([]AnomalyConfirmation, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if at.IsZero() || at.Before(t.last) || len(anomalies) > MaxProxies {
		t.streaks = make(map[Anomaly]anomalyStreak)
		return nil, ErrAnomalySample
	}
	invalid := false
	seen := make(map[Anomaly]bool, len(anomalies))
	for _, anomaly := range anomalies {
		invalid = invalid || !anomaly.valid() || seen[anomaly]
		seen[anomaly] = true
	}
	if invalid {
		t.streaks = make(map[Anomaly]anomalyStreak)
		return nil, ErrAnomalySample
	}
	elapsed := at.Sub(t.last)
	if elapsed < AnomalyInterval {
		return nil, nil
	}
	if elapsed >= 2*AnomalyInterval {
		// Never turn a long observation gap into several successful samples.
		t.streaks = make(map[Anomaly]anomalyStreak)
	}
	t.last = at
	t.sequence++
	if t.sequence == 0 {
		t.streaks = make(map[Anomaly]anomalyStreak)
		return nil, ErrAnomalySample
	}
	next := make(map[Anomaly]anomalyStreak, len(anomalies))
	confirmed := 0
	for _, anomaly := range anomalies {
		streak := t.streaks[anomaly]
		if streak.count < AnomalyConfirmations {
			streak.count++
		}
		if streak.count == AnomalyConfirmations {
			confirmed++
		}
		streak.token = t.sequence
		next[anomaly] = streak
	}
	t.streaks = next
	result := make([]AnomalyConfirmation, 0, confirmed)
	for _, anomaly := range anomalies {
		streak := next[anomaly]
		if streak.count == AnomalyConfirmations && !streak.persisted {
			result = append(result, AnomalyConfirmation{Anomaly: anomaly, Token: streak.token,
				AlarmOnly: confirmed > t.maxActions || anomaly.Kind == UnknownProxy})
		}
	}
	return result, nil
}

// Persisted is called only after the audit/action transaction commits. A failed
// transaction leaves the confirmation pending for the next successful sample.
func (t *AnomalyTracker) Persisted(confirmation AnomalyConfirmation) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	streak, present := t.streaks[confirmation.Anomaly]
	if !present || streak.count != AnomalyConfirmations || streak.token != confirmation.Token || streak.persisted {
		return false
	}
	streak.persisted = true
	t.streaks[confirmation.Anomaly] = streak
	return true
}
