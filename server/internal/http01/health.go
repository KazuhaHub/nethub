package http01

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"time"
)

type cleanupHealth struct {
	Version   int         `json:"version"`
	Namespace string      `json:"namespace_sha256"`
	At        time.Time   `json:"attempted_at"`
	Complete  bool        `json:"complete"`
	Result    SweepResult `json:"result"`
}

func (p *Publisher) namespaceFingerprint() (string, error) {
	data, err := readProtected(filepath.Join(p.state, "namespace.json"), 0600, 2048)
	if err != nil {
		return "", ErrState
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

// RecordCleanup writes an observation, never proof/assignment authority. A
// failed scan explicitly supersedes the prior successful observation.
func (p *Publisher) RecordCleanup(result SweepResult, success bool, at time.Time) error {
	if at.IsZero() {
		return ErrInput
	}
	binding, err := p.namespaceFingerprint()
	if err != nil {
		return err
	}
	return writeCanonical(filepath.Join(p.state, "cleanup.json"), cleanupHealth{Version: 1, Namespace: binding, At: at.UTC(), Complete: success && result.CycleComplete && result.Errors == 0, Result: result})
}

// CleanupReady requires a recent successful complete scan of this exact bound
// namespace. The host separately verifies that its independent timer is active.
func (p *Publisher) CleanupReady(now time.Time) error {
	binding, err := p.namespaceFingerprint()
	if err != nil {
		return err
	}
	var health cleanupHealth
	if now.IsZero() || readCanonical(filepath.Join(p.state, "cleanup.json"), &health) != nil || health.Version != 1 || health.Namespace != binding || !health.Complete || !health.Result.CycleComplete || health.Result.Errors != 0 || health.Result.Scanned < 0 || health.Result.Retired < 0 || health.Result.Busy < 0 || health.Result.Retired > health.Result.Scanned || health.Result.Busy > health.Result.Scanned-health.Result.Retired || health.At.IsZero() || health.At.After(now.Add(5*time.Second)) || !health.At.After(now.Add(-2*time.Minute)) {
		return ErrState
	}
	return nil
}
