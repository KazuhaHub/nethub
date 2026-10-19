package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/claim"
	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/jackc/pgx/v5/pgconn"
)

// EnrollmentStore derives tenant/owner from a one-use token, never device metadata.
type EnrollmentStore struct{ DB *sql.DB }

var _ device.Repository = (*EnrollmentStore)(nil)

func (s *EnrollmentStore) Register(ctx context.Context, record device.Registration, issue func(device.Assignment) (string, error)) (device.Assignment, error) {
	if err := record.Validate(); err != nil {
		return device.Assignment{}, err
	}
	if s == nil || s.DB == nil || issue == nil {
		return device.Assignment{}, device.ErrUnavailable
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return device.Assignment{}, device.ErrUnavailable
	}
	defer tx.Rollback()
	var result device.Assignment
	if err = tx.QueryRowContext(ctx, `SELECT tenant_id,created_by_user_id FROM consume_enroll_token($1)`, record.TokenHash[:]).Scan(&result.TenantID, &result.OwnerID); errors.Is(err, sql.ErrNoRows) {
		return device.Assignment{}, device.ErrDenied
	} else if err != nil {
		return device.Assignment{}, device.ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, result.TenantID); err != nil {
		return device.Assignment{}, device.ErrUnavailable
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return device.Assignment{}, device.ErrUnavailable
	}
	result.IssuedAt, err = claim.NextIssuedAt(now, time.Time{})
	if err != nil {
		return device.Assignment{}, device.ErrUnavailable
	}
	capabilities, err := json.Marshal(record.Capabilities)
	if err != nil {
		return device.Assignment{}, device.ErrUnavailable
	}
	for _, name := range record.Candidates {
		if _, err = tx.ExecContext(ctx, `SAVEPOINT device_candidate`); err != nil {
			return device.Assignment{}, device.ErrUnavailable
		}
		err = tx.QueryRowContext(ctx, `INSERT INTO devices
 (tenant_id,owner_user_id,hostname,platform,capabilities,device_secret_hash,subdomain,
  domain_claim_issued_at,cluster_hint,agent_protocol_version,platform_version,agent_version)
 VALUES($1,$2,$3,$4,ARRAY(SELECT jsonb_array_elements_text($5::jsonb)),$6,$7,$8,
        CASE WHEN $9::boolean THEN 'cluster member' ELSE NULL END,$10,$11,$12)
 RETURNING id,subdomain`, result.TenantID, result.OwnerID, record.Hostname,
			record.Platform, string(capabilities), record.SecretHash, name, result.IssuedAt,
			record.ClusterHint, record.ProtocolVersion, record.PlatformVersion, record.AgentVersion).Scan(&result.ID, &result.Subdomain)
		if err == nil {
			if _, err = tx.ExecContext(ctx, `RELEASE SAVEPOINT device_candidate`); err != nil {
				return device.Assignment{}, device.ErrUnavailable
			}
			break
		}
		var conflict *pgconn.PgError
		if !errors.As(err, &conflict) || conflict.Code != "23505" || conflict.ConstraintName != "devices_subdomain_key" {
			return device.Assignment{}, device.ErrUnavailable
		}
		if _, err = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT device_candidate`); err != nil {
			return device.Assignment{}, device.ErrUnavailable
		}
		if _, err = tx.ExecContext(ctx, `RELEASE SAVEPOINT device_candidate`); err != nil {
			return device.Assignment{}, device.ErrUnavailable
		}
	}
	if result.ID == "" {
		return device.Assignment{}, device.ErrUnavailable
	}
	result.Claim, err = issue(result)
	if err != nil || result.Claim == "" {
		return device.Assignment{}, device.ErrUnavailable
	}
	payload, err := json.Marshal(map[string]string{"source_ip": record.SourceIP.Unmap().String(),
		"platform": record.Platform, "agent_protocol_version": record.ProtocolVersion})
	if err != nil {
		return device.Assignment{}, device.ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, `SELECT append_audit('user',$1,'device.enrolled',$2,$3::jsonb)`, result.OwnerID, result.ID, string(payload)); err != nil {
		return device.Assignment{}, device.ErrUnavailable
	}
	if err = tx.Commit(); err != nil {
		return device.Assignment{}, device.ErrUnavailable
	}
	return result, nil
}
