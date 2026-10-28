package dbbackup

import "time"

// WorkerState describes the daemon's current phase independently of archive
// validity. A successful archive does not by itself establish a healthy cycle.
type WorkerState struct {
	Version               int       `json:"version"`
	Outcome               string    `json:"outcome"`
	AttemptStartedAt      time.Time `json:"attempt_started_at"`
	AttemptDeadline       time.Time `json:"attempt_deadline"`
	LastSuccessfulCycleAt time.Time `json:"last_successful_cycle_at"`
	DeploymentFingerprint string    `json:"deployment_fingerprint"`
}

func validWorkerState(state WorkerState) bool {
	if state.Version != 1 || state.AttemptStartedAt.IsZero() || !state.AttemptDeadline.After(state.AttemptStartedAt) || state.AttemptDeadline.Sub(state.AttemptStartedAt) > 30*time.Minute {
		return false
	}
	if state.Outcome != "starting" && state.Outcome != "running" && state.Outcome != "succeeded" && state.Outcome != "failed" {
		return false
	}
	if state.LastSuccessfulCycleAt.IsZero() {
		return state.DeploymentFingerprint == "" && state.Outcome != "succeeded"
	}
	if state.Outcome == "starting" || !digestPattern.MatchString(state.DeploymentFingerprint) {
		return false
	}
	if state.Outcome == "succeeded" {
		return !state.LastSuccessfulCycleAt.Before(state.AttemptStartedAt) && !state.LastSuccessfulCycleAt.After(state.AttemptDeadline)
	}
	return !state.LastSuccessfulCycleAt.After(state.AttemptStartedAt)
}
