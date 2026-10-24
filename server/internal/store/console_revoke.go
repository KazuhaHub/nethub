package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/web"
)

// RevokeDevice serializes ownership and enabled actor checks with one-way revocation.
func (s *ConsoleStore) RevokeDevice(ctx context.Context, actor, device string, ip netip.Addr) (web.DeviceRevocation, error) {
	if !ip.IsValid() || ip.Zone() != "" {
		return web.DeviceRevocation{}, errors.New("invalid revocation source")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return web.DeviceRevocation{}, err
	}
	defer tx.Rollback()
	var role string
	err = tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id=$1 AND disabled_at IS NULL FOR SHARE`, actor).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return web.DeviceRevocation{}, auth.ErrUnauthenticated
	}
	if err != nil {
		return web.DeviceRevocation{}, err
	}
	var result web.DeviceRevocation
	var stamp sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT revoked,revoked_at FROM devices WHERE id=$1 AND ($2='admin' OR owner_user_id=$3) FOR UPDATE`, device, role, actor).Scan(&result.Revoked, &stamp)
	if errors.Is(err, sql.ErrNoRows) {
		return web.DeviceRevocation{}, web.ErrDeviceUnavailable
	}
	if err != nil {
		return web.DeviceRevocation{}, err
	}
	if result.Revoked {
		if !stamp.Valid {
			return web.DeviceRevocation{}, errors.New("invalid retained revocation")
		}
		result.RevokedAt = stamp.Time
		return result, tx.Commit()
	}
	err = tx.QueryRowContext(ctx, `UPDATE devices SET revoked=true,revoked_at=clock_timestamp(),revoked_by_user_id=$2 WHERE id=$1 RETURNING revoked_at`, device, actor).Scan(&result.RevokedAt)
	if err != nil {
		return web.DeviceRevocation{}, err
	}
	payload, err := json.Marshal(map[string]string{"source_ip": ip.Unmap().String()})
	if err != nil {
		return web.DeviceRevocation{}, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT append_audit('user',$1,'device.revoked',$2,$3::jsonb)`, actor, device, string(payload)); err != nil {
		return web.DeviceRevocation{}, err
	}
	result.Revoked = true
	return result, tx.Commit()
}
