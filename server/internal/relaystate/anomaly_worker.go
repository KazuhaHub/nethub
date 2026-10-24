package relaystate

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

var ErrAnomalyChanged = errors.New("relay anomaly classification changed")

type AnomalyRepository interface {
	Inspect(context.Context, []ObservedRoute) ([]Anomaly, error)
	// Commit must recheck the expected classification while locking current rows.
	// A changed snapshot returns ErrAnomalyChanged without any audit or action.
	Commit(context.Context, []ObservedRoute, []Anomaly, []AnomalyConfirmation) error
}

type anomalyWorker struct {
	reader     *Poller
	repository AnomalyRepository
	tracker    *AnomalyTracker
	logger     *slog.Logger
	interval   time.Duration
	now        func() time.Time
}

func (w *anomalyWorker) sample(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	value, err := w.reader.fetch(ctx)
	if err != nil {
		w.tracker.Unavailable(w.now())
		return err
	}
	inspection, stopInspection := context.WithTimeout(ctx, 2*time.Second)
	findings, err := w.repository.Inspect(inspection, value.routes)
	inspectionFailed := inspection.Err() != nil
	stopInspection()
	if err != nil || inspectionFailed {
		w.tracker.Unavailable(w.now())
		return ErrStorage
	}
	confirmations, err := w.tracker.Sample(w.now(), findings)
	if err != nil {
		return ErrAnomalySample
	}
	persistence, stopPersistence := context.WithTimeout(ctx, 2*time.Second)
	err = w.repository.Commit(persistence, value.routes, findings, confirmations)
	persistenceFailed := persistence.Err() != nil
	stopPersistence()
	if errors.Is(err, ErrAnomalyChanged) {
		w.tracker.Unavailable(w.now())
		return ErrAnomalyChanged
	}
	if err != nil || persistenceFailed {
		// Valid observations remain pending; only COMMIT permits acknowledgement.
		return ErrStorage
	}
	for _, confirmation := range confirmations {
		if !w.tracker.Persisted(confirmation) {
			return ErrAnomalySample
		}
	}
	return nil
}

func (w *anomalyWorker) run(ctx context.Context) {
	defer w.reader.client.CloseIdleConnections()
	// Wait after each completed operation instead of catching up missed ticks or
	// shortening the sample interval when HTTP/database latency varies.
	timer := time.NewTimer(w.interval)
	defer timer.Stop()
	failed := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			err := w.sample(ctx)
			if ctx.Err() != nil {
				return
			}
			if err != nil && !failed {
				w.logger.Warn("Relay anomaly check unavailable")
			} else if err == nil && failed {
				w.logger.Info("Relay anomaly check resumed")
			}
			failed = err != nil
			timer.Reset(w.interval)
		}
	}
}
