package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

var _ device.LifecycleRepository = (*EnrollmentStore)(nil)

func (s *EnrollmentStore) DeviceCredential(ctx context.Context, id string) (device.Credential, error) {
	var c device.Credential
	if s == nil || s.DB == nil {
		return c, device.ErrUnavailable
	}
	err := s.DB.QueryRowContext(ctx, `SELECT tenant_id,secret_hash FROM lookup_device_credential($1)`, id).Scan(&c.TenantID, &c.Hash)
	if errors.Is(err, sql.ErrNoRows) {
		return c, device.ErrDenied
	}
	if err != nil {
		return device.Credential{}, device.ErrUnavailable
	}
	return c, nil
}

func (s *EnrollmentStore) lockDevice(ctx context.Context, c device.Credential, id string) (*sql.Tx, bool, error) {
	if s == nil || s.DB == nil || c.TenantID == "" || c.Hash == "" {
		return nil, false, device.ErrUnavailable
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, device.ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, c.TenantID); err != nil {
		tx.Rollback()
		return nil, false, device.ErrUnavailable
	}
	var hash string
	var revoked bool
	err = tx.QueryRowContext(ctx, `SELECT device_secret_hash,revoked FROM devices WHERE id=$1 AND tenant_id=$2 FOR UPDATE`, id, c.TenantID).Scan(&hash, &revoked)
	if errors.Is(err, sql.ErrNoRows) || err == nil && hash != c.Hash {
		tx.Rollback()
		return nil, false, device.ErrDenied
	}
	if err != nil {
		tx.Rollback()
		return nil, false, device.ErrUnavailable
	}
	return tx, revoked, nil
}

func (s *EnrollmentStore) ReportDevice(ctx context.Context, c device.Credential, r protocol.StatusRequest) (bool, error) {
	if err := r.Validate(); err != nil {
		return false, err
	}
	tx, revoked, err := s.lockDevice(ctx, c, r.DeviceID)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if !revoked {
		_, err = tx.ExecContext(ctx, `UPDATE devices SET platform_version=$1,agent_version=$2,service_state=$3,
 last_reconcile_success=$4,last_reconcile_at=$5,last_report_at=clock_timestamp()
 WHERE id=$6 AND tenant_id=$7 AND NOT revoked`, r.PlatformVersion, r.AgentVersion, r.ServiceState, r.LastReconcileSuccess, r.LastReconcileAt, r.DeviceID, c.TenantID)
		if err != nil {
			return false, device.ErrUnavailable
		}
	}
	if tx.Commit() != nil {
		return false, device.ErrUnavailable
	}
	return revoked, nil
}

func (s *EnrollmentStore) UnenrollDevice(ctx context.Context, c device.Credential, r protocol.Identity, ip netip.Addr) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if !ip.IsValid() || ip.Zone() != "" {
		return protocol.ErrInvalidRequest
	}
	tx, revoked, err := s.lockDevice(ctx, c, r.DeviceID)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if !revoked {
		if _, err = tx.ExecContext(ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp(),last_seen_at=NULL,service_state='disabled' WHERE id=$1 AND tenant_id=$2`, r.DeviceID, c.TenantID); err != nil {
			return device.ErrUnavailable
		}
		data, err := json.Marshal(map[string]string{"source_ip": ip.Unmap().String()})
		if err != nil {
			return device.ErrUnavailable
		}
		if _, err = tx.ExecContext(ctx, `SELECT append_audit('device',$1,'device.unenrolled',$1,$2::jsonb)`, r.DeviceID, string(data)); err != nil {
			return device.ErrUnavailable
		}
	}
	if tx.Commit() != nil {
		return device.ErrUnavailable
	}
	return nil
}
