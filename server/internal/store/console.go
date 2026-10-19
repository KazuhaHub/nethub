package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/web"
)

type ConsoleStore struct{ AuthStore }

var _ web.Repository = (*ConsoleStore)(nil)

// SoleTenant refuses ambiguous startup instead of allowing a browser-supplied
// tenant selector in the single-tenant v1 product.
func SoleTenant(ctx context.Context, db *sql.DB) (string, error) {
	rows, err := db.QueryContext(ctx, `SELECT id FROM tenants ORDER BY id LIMIT 2`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var tenant string
	count := 0
	for rows.Next() {
		if err := rows.Scan(&tenant); err != nil {
			return "", err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if count != 1 {
		return "", errors.New("v1 requires exactly one deployment tenant")
	}
	return tenant, nil
}

func (s *ConsoleStore) Health(ctx context.Context) error { return s.DB.PingContext(ctx) }

func (s *ConsoleStore) Devices(ctx context.Context, actor string, query web.DeviceQuery) (web.DevicePage, error) {
	if query.Limit < 1 || query.Limit > 200 {
		return web.DevicePage{}, errors.New("invalid device limit")
	}
	tx, err := s.begin(ctx, true)
	if err != nil {
		return web.DevicePage{}, err
	}
	defer tx.Rollback()
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM users WHERE id=$1 AND disabled_at IS NULL)`, actor).Scan(&active); err != nil {
		return web.DevicePage{}, err
	}
	if !active {
		return web.DevicePage{}, auth.ErrUnauthenticated
	}
	rows, err := tx.QueryContext(ctx, `SELECT d.id,d.label,d.hostname,d.subdomain,d.platform,d.platform_version,d.agent_version,
 to_json(d.capabilities),d.cluster_hint,
 coalesce(d.last_seen_at>statement_timestamp()-interval '45 seconds' AND d.last_seen_at<=statement_timestamp(),false),
 d.last_seen_at,d.enrolled_at,d.revoked,d.revoked_at,owner.id,owner.email,
 d.service_state,d.last_report_at,d.last_reconcile_success,d.last_reconcile_at
 FROM devices d JOIN users actor ON actor.tenant_id=d.tenant_id
 JOIN users owner ON owner.tenant_id=d.tenant_id AND owner.id=d.owner_user_id
 WHERE actor.id=$1 AND actor.disabled_at IS NULL AND (actor.role='admin' OR d.owner_user_id=actor.id)
 AND (nullif($2,'')::uuid IS NULL OR d.id>nullif($2,'')::uuid)
 AND ($3::boolean IS NULL OR d.revoked=$3)
 AND ($4::boolean IS NULL OR coalesce(d.last_seen_at>statement_timestamp()-interval '45 seconds' AND d.last_seen_at<=statement_timestamp(),false)=$4)
 ORDER BY d.id LIMIT $5`, actor, query.AfterID, query.Revoked, query.Online, query.Limit+1)
	if err != nil {
		return web.DevicePage{}, err
	}
	page := web.DevicePage{Items: []web.Device{}}
	for rows.Next() {
		var device web.Device
		var capabilities []byte
		if err = rows.Scan(&device.ID, &device.Label, &device.Hostname, &device.Subdomain, &device.Platform, &device.PlatformVersion, &device.AgentVersion,
			&capabilities, &device.ClusterHint, &device.Online, &device.LastSeenAt, &device.EnrolledAt, &device.Revoked, &device.RevokedAt, &device.Owner.ID, &device.Owner.Email,
			&device.ServiceState, &device.LastReportAt, &device.LastReconcileSuccess, &device.LastReconcileAt); err != nil {
			rows.Close()
			return web.DevicePage{}, err
		}
		if err = json.Unmarshal(capabilities, &device.Capabilities); err != nil {
			rows.Close()
			return web.DevicePage{}, err
		}
		page.Items = append(page.Items, device)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return web.DevicePage{}, err
	}
	if len(page.Items) > query.Limit {
		page.Items = page.Items[:query.Limit]
		cursor := base64.RawURLEncoding.EncodeToString([]byte(page.Items[len(page.Items)-1].ID))
		page.NextCursor = &cursor
	}
	return page, tx.Commit()
}

func appendConsoleAudit(ctx context.Context, tx *sql.Tx, kind, actor, action string, ip netip.Addr, tokenID string) error {
	if !ip.IsValid() || ip.Zone() != "" {
		return errors.New("invalid audit source address")
	}
	payload := map[string]string{"source_ip": ip.Unmap().String()}
	if tokenID != "" {
		payload["token_id"] = tokenID
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `SELECT append_audit($1,nullif($2,'')::uuid,$3,NULL,$4::jsonb)`, kind, actor, action, string(encoded))
	return err
}

func (s *ConsoleStore) LoginFailed(ctx context.Context, ip netip.Addr) error {
	tx, err := s.begin(ctx, false)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = appendConsoleAudit(ctx, tx, "system", "", "auth.login_failed", ip, ""); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *ConsoleStore) IssueEnrollToken(ctx context.Context, actor string, ip netip.Addr) (web.EnrollToken, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return web.EnrollToken{}, errors.New("enrollment randomness unavailable")
	}
	digest := sha256.Sum256(raw)
	tx, err := s.begin(ctx, false)
	if err != nil {
		return web.EnrollToken{}, err
	}
	defer tx.Rollback()
	var id string
	if err = tx.QueryRowContext(ctx, `SELECT id FROM users WHERE id=$1 AND disabled_at IS NULL FOR SHARE`, actor).Scan(&id); errors.Is(err, sql.ErrNoRows) {
		return web.EnrollToken{}, auth.ErrUnauthenticated
	}
	if err != nil {
		return web.EnrollToken{}, err
	}
	var result web.EnrollToken
	if err = tx.QueryRowContext(ctx, `INSERT INTO enroll_tokens(tenant_id,created_by_user_id,token_hash) VALUES($1,$2,$3) RETURNING id,expires_at`, s.Tenant, actor, digest[:]).Scan(&id, &result.ExpiresAt); err != nil {
		return web.EnrollToken{}, err
	}
	if err = appendConsoleAudit(ctx, tx, "user", actor, "enroll_token.created", ip, id); err != nil {
		return web.EnrollToken{}, err
	}
	result.Token = base64.RawURLEncoding.EncodeToString(raw)
	return result, tx.Commit()
}
