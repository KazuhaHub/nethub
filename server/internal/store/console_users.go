package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/web"
	"github.com/jackc/pgx/v5/pgconn"
)

const userProjection = `u.id,u.email,u.role,u.disabled_at IS NOT NULL,u.password_hash IS NOT NULL,u.created_at,
 coalesce((SELECT json_agg(json_build_object('provider_slug',p.slug,'linked_at',i.created_at) ORDER BY p.slug,i.id)
 FROM user_identities i JOIN identity_providers p ON p.tenant_id=i.tenant_id AND p.id=i.provider_id
 WHERE i.tenant_id=u.tenant_id AND i.user_id=u.id),'[]'::json)`

func scanManagedUser(row interface{ Scan(...any) error }) (web.ManagedUser, error) {
	var user web.ManagedUser
	var identities []byte
	err := row.Scan(&user.ID, &user.Email, &user.Role, &user.Disabled, &user.HasPassword, &user.CreatedAt, &identities)
	if err == nil {
		err = json.Unmarshal(identities, &user.Identities)
	}
	return user, err
}

func requireAdmin(ctx context.Context, tx *sql.Tx, actor string) error {
	var role string
	err := tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id=$1 AND disabled_at IS NULL FOR SHARE`, actor).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.ErrUnauthenticated
	}
	if err != nil {
		return err
	}
	if role != "admin" {
		return web.ErrForbidden
	}
	return nil
}

func (s *ConsoleStore) Users(ctx context.Context, actor string, query web.UserQuery) (web.UserPage, error) {
	if query.Limit < 1 || query.Limit > 200 {
		return web.UserPage{}, errors.New("invalid user limit")
	}
	tx, err := s.begin(ctx, false)
	if err != nil {
		return web.UserPage{}, err
	}
	defer tx.Rollback()
	if err = requireAdmin(ctx, tx, actor); err != nil {
		return web.UserPage{}, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+userProjection+` FROM users u WHERE (nullif($1,'')::uuid IS NULL OR u.id>nullif($1,'')::uuid) ORDER BY u.id LIMIT $2`, query.AfterID, query.Limit+1)
	if err != nil {
		return web.UserPage{}, err
	}
	page := web.UserPage{Items: []web.ManagedUser{}}
	for rows.Next() {
		user, e := scanManagedUser(rows)
		if e != nil {
			rows.Close()
			return web.UserPage{}, e
		}
		page.Items = append(page.Items, user)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return web.UserPage{}, err
	}
	if len(page.Items) > query.Limit {
		page.Items = page.Items[:query.Limit]
		cursor := base64.RawURLEncoding.EncodeToString([]byte(page.Items[len(page.Items)-1].ID))
		page.NextCursor = &cursor
	}
	return page, tx.Commit()
}

// UpdateUser serializes account administration before locking actor and target.
// Disable, session deletion and audit append commit or roll back together.
func (s *ConsoleStore) UpdateUser(ctx context.Context, actor, target string, patch web.UserPatch, ip netip.Addr) (web.ManagedUser, error) {
	if !ip.IsValid() || ip.Zone() != "" || (patch.Role == nil && patch.Disabled == nil) || (patch.Role != nil && *patch.Role != "admin" && *patch.Role != "member") {
		return web.ManagedUser{}, errors.New("invalid user update")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return web.ManagedUser{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1 || ':account-admin',0))`, s.Tenant); err != nil {
		return web.ManagedUser{}, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,role,disabled_at IS NOT NULL,password_hash IS NOT NULL FROM users WHERE id IN ($1,$2) ORDER BY id FOR UPDATE`, actor, target)
	if err != nil {
		return web.ManagedUser{}, err
	}
	type lockedUser struct {
		role               string
		disabled, password bool
	}
	locked := map[string]lockedUser{}
	for rows.Next() {
		var id string
		var u lockedUser
		if err = rows.Scan(&id, &u.role, &u.disabled, &u.password); err != nil {
			rows.Close()
			return web.ManagedUser{}, err
		}
		locked[id] = u
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return web.ManagedUser{}, err
	}
	a, ok := locked[actor]
	if !ok || a.disabled {
		return web.ManagedUser{}, auth.ErrUnauthenticated
	}
	if a.role != "admin" {
		return web.ManagedUser{}, web.ErrForbidden
	}
	old, ok := locked[target]
	if !ok {
		return web.ManagedUser{}, web.ErrUserUnavailable
	}
	role, disabled := old.role, old.disabled
	if patch.Role != nil {
		role = *patch.Role
	}
	if patch.Disabled != nil {
		disabled = *patch.Disabled
	}
	if old.role == "admin" && !old.disabled && (role != "admin" || disabled) {
		var admin, local bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM users WHERE id<>$1 AND role='admin' AND disabled_at IS NULL),EXISTS(SELECT FROM users WHERE id<>$1 AND role='admin' AND disabled_at IS NULL AND password_hash IS NOT NULL)`, target).Scan(&admin, &local); err != nil {
			return web.ManagedUser{}, err
		}
		if !admin {
			return web.ManagedUser{}, web.ErrLastAdmin
		}
		if old.password && !local {
			return web.ManagedUser{}, web.ErrLastLocalAdmin
		}
	}
	if old.role != role || old.disabled != disabled {
		_, err = tx.ExecContext(ctx, `UPDATE users SET role=$2,disabled_at=CASE WHEN $3 THEN coalesce(disabled_at,clock_timestamp()) ELSE NULL END WHERE id=$1`, target, role, disabled)
		if err != nil {
			var pg *pgconn.PgError
			if errors.As(err, &pg) && pg.Code == "23514" {
				return web.ManagedUser{}, web.ErrLastLocalAdmin
			}
			return web.ManagedUser{}, err
		}
		var removed int64
		if disabled {
			result, e := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=$1`, target)
			if e != nil {
				return web.ManagedUser{}, e
			}
			removed, err = result.RowsAffected()
			if err != nil {
				return web.ManagedUser{}, err
			}
		}
		payload, e := json.Marshal(map[string]any{"target_user_id": target, "previous_role": old.role, "role": role, "previous_disabled": old.disabled, "disabled": disabled, "source_ip": ip.Unmap().String(), "sessions_revoked": removed})
		if e != nil {
			return web.ManagedUser{}, e
		}
		if _, err = tx.ExecContext(ctx, `SELECT append_audit('user',$1,'user.updated',NULL,$2::jsonb)`, actor, string(payload)); err != nil {
			return web.ManagedUser{}, err
		}
		if removed > 0 {
			if _, err = tx.ExecContext(ctx, `SELECT append_audit('user',$1,'auth.sessions_revoked',NULL,$2::jsonb)`, actor, string(payload)); err != nil {
				return web.ManagedUser{}, err
			}
		}
	}
	user, err := scanManagedUser(tx.QueryRowContext(ctx, `SELECT `+userProjection+` FROM users u WHERE id=$1`, target))
	if err != nil {
		return web.ManagedUser{}, err
	}
	return user, tx.Commit()
}
