package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/claim"
	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

var _ device.RotationRepository = (*EnrollmentStore)(nil)

// RotateDevice serializes publication, current-credential verification, claim
// advancement, the immutable operation and audit in one transaction. Recovery
// authenticates the committed candidate and cannot resurrect an older operation.
func (s *EnrollmentStore) RotateDevice(ctx context.Context, c device.Credential, r device.RotationRecord, issue func(device.Assignment) (string, error)) (device.Assignment, error) {
	if err := r.Validate(); err != nil {
		return device.Assignment{}, err
	}
	if s == nil || s.DB == nil || c.TenantID == "" || c.Hash == "" || issue == nil {
		return device.Assignment{}, device.ErrUnavailable
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return device.Assignment{}, device.ErrUnavailable
	}
	defer tx.Rollback()
	var result device.Assignment
	var head bool
	// Match enrollment's global trust-head-before-device lock ordering.
	if err := tx.QueryRowContext(ctx, `SELECT lock_relay_trust_head()`).Scan(&head); err != nil || !head {
		return device.Assignment{}, device.ErrUnavailable
	}
	var data []byte
	if err := tx.QueryRowContext(ctx, `SELECT coalesce(read_current_relay_trust($1),'null'::jsonb)`, r.RelayServerName).Scan(&data); err != nil {
		return device.Assignment{}, device.ErrUnavailable
	}
	if string(data) != "null" {
		generation, err := relaytrust.DecodeGeneration(data, r.RelayServerName, time.Now())
		if err != nil {
			return device.Assignment{}, device.ErrUnavailable
		}
		result.RelayCAPEM = generation.Bundle().PEM()
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, c.TenantID); err != nil {
		return device.Assignment{}, device.ErrUnavailable
	}
	var hash string
	var revoked bool
	err = tx.QueryRowContext(ctx, `SELECT id,tenant_id,owner_user_id,subdomain,domain_claim_issued_at,device_secret_hash,revoked
 FROM devices WHERE id=$1 AND tenant_id=$2 FOR UPDATE`, r.DeviceID, c.TenantID).Scan(
		&result.ID, &result.TenantID, &result.OwnerID, &result.Subdomain, &result.IssuedAt, &hash, &revoked)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (revoked || hash != c.Hash) {
		return device.Assignment{}, device.ErrDenied
	}
	if err != nil {
		return device.Assignment{}, device.ErrUnavailable
	}
	var digest []byte
	var recordedHash, recordedTrust string
	var recordedTime time.Time
	err = tx.QueryRowContext(ctx, `SELECT candidate_digest,credential_hash,issued_at,relay_ca_pem FROM device_rotations
 WHERE tenant_id=$1 AND device_id=$2 AND operation_id=$3`, c.TenantID, r.DeviceID, r.OperationID).Scan(&digest, &recordedHash, &recordedTime, &recordedTrust)
	switch {
	case err == nil:
		if !r.CandidateIsCurrent || !bytes.Equal(digest, r.CandidateDigest[:]) || recordedHash != hash || !recordedTime.Equal(result.IssuedAt) || protocol.RelayTrustDigest(recordedTrust) != r.ExpectedRelayCASHA256 {
			return device.Assignment{}, device.ErrDenied
		}
		// Recovery retains the committed public trust even if publication has
		// advanced. This is not permission to overwrite managed native trust.
		result.RelayCAPEM = recordedTrust
	case errors.Is(err, sql.ErrNoRows):
		// A credential equal to the current bearer can recover only its committed
		// operation; it cannot create an unrecorded no-op credential rotation.
		if r.CandidateIsCurrent || r.SecretHash == hash {
			return device.Assignment{}, device.ErrDenied
		}
		selectedTrust := result.RelayCAPEM
		if selectedTrust == "" {
			selectedTrust = r.BootstrapCAPEM
		}
		if protocol.RelayTrustDigest(selectedTrust) != r.ExpectedRelayCASHA256 {
			return device.Assignment{}, device.ErrRotationTrustChanged
		}
		var now time.Time
		if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return device.Assignment{}, device.ErrUnavailable
		}
		result.IssuedAt, err = claim.NextIssuedAt(now, result.IssuedAt)
		if err != nil {
			return device.Assignment{}, device.ErrUnavailable
		}
		if _, err := tx.ExecContext(ctx, `UPDATE devices SET device_secret_hash=$1,domain_claim_issued_at=$2 WHERE id=$3 AND tenant_id=$4`, r.SecretHash, result.IssuedAt, r.DeviceID, c.TenantID); err != nil {
			return device.Assignment{}, device.ErrUnavailable
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO device_rotations(tenant_id,device_id,operation_id,candidate_digest,credential_hash,issued_at,relay_ca_pem)
 VALUES($1,$2,$3,$4,$5,$6,$7)`, c.TenantID, r.DeviceID, r.OperationID, r.CandidateDigest[:], r.SecretHash, result.IssuedAt, selectedTrust); err != nil {
			return device.Assignment{}, device.ErrUnavailable
		}
		payload, err := json.Marshal(map[string]string{"source_ip": r.SourceIP.String(), "operation_id": r.OperationID})
		if err != nil {
			return device.Assignment{}, device.ErrUnavailable
		}
		if _, err := tx.ExecContext(ctx, `SELECT append_audit('device',$1,'device.rotated',$1,$2::jsonb)`, r.DeviceID, string(payload)); err != nil {
			return device.Assignment{}, device.ErrUnavailable
		}
	default:
		return device.Assignment{}, device.ErrUnavailable
	}
	result.Claim, err = issue(result)
	if err != nil || result.Claim == "" {
		return device.Assignment{}, device.ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return device.Assignment{}, device.ErrUnavailable
	}
	return result, nil
}
