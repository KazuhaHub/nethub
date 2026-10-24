package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/web"
	"github.com/jackc/pgx/v5/pgconn"
)

// OpenDevice grants only the resolved source address. PostgreSQL locks the actor
// and assignment and chooses the fixed lifetime; browser traffic cannot renew it.
func (s *ConsoleStore) OpenDevice(ctx context.Context, actor, device string, ip netip.Addr) (web.DeviceAccess, error) {
	if !ip.IsValid() || ip.Zone() != "" {
		return web.DeviceAccess{}, errors.New("invalid access source address")
	}
	tx, err := s.begin(ctx, false)
	if err != nil {
		return web.DeviceAccess{}, err
	}
	defer tx.Rollback()
	var id string
	if err = tx.QueryRowContext(ctx, `SELECT id FROM users WHERE id=$1 AND disabled_at IS NULL FOR SHARE`, actor).Scan(&id); errors.Is(err, sql.ErrNoRows) {
		return web.DeviceAccess{}, auth.ErrUnauthenticated
	}
	if err != nil {
		return web.DeviceAccess{}, err
	}
	var revoked bool
	err = tx.QueryRowContext(ctx, `SELECT d.revoked FROM devices d JOIN users actor ON actor.tenant_id=d.tenant_id
 WHERE d.id=$1 AND actor.id=$2 AND actor.disabled_at IS NULL AND (actor.role='admin' OR d.owner_user_id=actor.id) FOR SHARE OF d`, device, actor).Scan(&revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return web.DeviceAccess{}, web.ErrDeviceUnavailable
	}
	if err != nil {
		return web.DeviceAccess{}, err
	}
	if revoked {
		return web.DeviceAccess{}, web.ErrDeviceRevoked
	}
	var result web.DeviceAccess
	err = tx.QueryRowContext(ctx, `SELECT open_device($1,$2,$3::inet)`, actor, device, ip.Unmap().String()).Scan(&result.ExpiresAt)
	var denied *pgconn.PgError
	if errors.Is(err, sql.ErrNoRows) || errors.As(err, &denied) && denied.Code == "42501" {
		return web.DeviceAccess{}, web.ErrDeviceUnavailable
	}
	if err != nil {
		return web.DeviceAccess{}, err
	}
	// Read the destination after the assignment lock; a projection from before a
	// lock wait could otherwise return a superseded subdomain.
	if err = tx.QueryRowContext(ctx, `SELECT subdomain FROM devices WHERE id=$1`, device).Scan(&result.Subdomain); err != nil {
		return web.DeviceAccess{}, err
	}
	payload, err := json.Marshal(map[string]any{"source_ip": ip.Unmap().String(), "expires_at": result.ExpiresAt})
	if err != nil {
		return web.DeviceAccess{}, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT append_audit('user',$1,'device.access_granted',$2,$3::jsonb)`, actor, device, string(payload)); err != nil {
		return web.DeviceAccess{}, err
	}
	return result, tx.Commit()
}
