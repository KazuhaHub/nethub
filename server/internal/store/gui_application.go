package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/guicert"
)

// Acknowledge holds the live credential/assignment lock through immutable report
// and audit insertion. A lost commit reply retries the same generation.
func (s *GUIJobQueue) Acknowledge(ctx context.Context, credential device.Credential, report guicert.ApplicationReport) (time.Time, error) {
	if s == nil || s.Requests == nil {
		return time.Time{}, device.ErrUnavailable
	}
	tx, host, key, err := s.Requests.lock(ctx, credential, report.DeviceID)
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback()
	request, found, err := readGUIRequest(ctx, tx, credential.TenantID, report.DeviceID, host, key)
	if err != nil {
		return time.Time{}, err
	}
	if !found || request.ID != report.RequestID || request.Fingerprint != report.RequestFingerprint {
		return time.Time{}, device.ErrDenied
	}
	var accepted time.Time
	err = tx.QueryRowContext(ctx, `SELECT accepted_at FROM record_gui_certificate_application($1,$2,$3,$4,$5,$6,$7)`,
		report.DeviceID, report.RequestID, report.RequestFingerprint, host, report.GenerationID, report.Generation, report.Fingerprint).Scan(&accepted)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, device.ErrDenied
	}
	if err != nil || accepted.IsZero() {
		return time.Time{}, device.ErrUnavailable
	}
	if tx.Commit() != nil {
		return time.Time{}, device.ErrUnavailable
	}
	return accepted, nil
}
