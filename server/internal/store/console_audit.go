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

func (s *ConsoleStore) Audit(ctx context.Context, actor string, query web.AuditQuery) (web.AuditPage, error) {
	before, err := web.AuditBefore(s.Tenant+":"+actor, query)
	if err != nil {
		return web.AuditPage{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return web.AuditPage{}, err
	}
	defer tx.Rollback()
	var role string
	err = tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id=$1 AND disabled_at IS NULL FOR SHARE`, actor).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return web.AuditPage{}, auth.ErrUnauthenticated
	}
	if err != nil {
		return web.AuditPage{}, err
	}
	if query.UserID != "" && role != "admin" {
		return web.AuditPage{}, web.ErrForbidden
	}
	rows, err := tx.QueryContext(ctx, `SELECT a.sequence,a.id,a.created_at,a.actor_type,a.actor_id,a.action,a.target_device_id,
 CASE WHEN ($2='admin' OR (a.actor_type='user' AND a.actor_id=$1)) AND length(a.payload->>'source_ip')<=45 THEN a.payload->>'source_ip' END,
 CASE WHEN a.action IN ('user.updated','auth.sessions_revoked') THEN jsonb_build_object(
   'target_user_id',CASE WHEN length(a.payload->>'target_user_id')=36 THEN a.payload->'target_user_id' END,
   'role',CASE WHEN a.payload->>'role' IN ('admin','member') THEN a.payload->'role' END,
   'disabled',CASE WHEN jsonb_typeof(a.payload->'disabled')='boolean' THEN a.payload->'disabled' END,
   'sessions_revoked',CASE WHEN a.payload->>'sessions_revoked' ~ '^[0-9]{1,9}$' THEN a.payload->'sessions_revoked' END)
 WHEN a.action='device.access_granted' THEN jsonb_build_object(
   'expires_at',CASE WHEN length(a.payload->>'expires_at')<=64 THEN a.payload->'expires_at' END)
 WHEN a.action='device.disconnect_requested' THEN jsonb_build_object(
   'request_id',CASE WHEN length(a.payload->>'request_id')=36 THEN a.payload->'request_id' END)
 ELSE '{}'::jsonb END
 FROM audit_log a
 WHERE a.tenant_id=$3 AND ($4::bigint=0 OR a.sequence<$4)
 AND ($5='' OR a.action=$5) AND (nullif($6,'')::uuid IS NULL OR a.target_device_id=nullif($6,'')::uuid
   OR (a.actor_type='device' AND a.actor_id=nullif($6,'')::uuid))
 AND (nullif($7,'')::uuid IS NULL OR (a.actor_type='user' AND a.actor_id=nullif($7,'')::uuid))
 AND ($8::timestamptz IS NULL OR a.created_at >= $8) AND ($9::timestamptz IS NULL OR a.created_at < $9)
 AND ($2='admin' OR (a.actor_type='user' AND a.actor_id=$1)
   OR (a.action IN ('user.updated','auth.sessions_revoked') AND a.payload->>'target_user_id'=$1::text)
   OR EXISTS(SELECT FROM devices d WHERE d.tenant_id=a.tenant_id AND d.owner_user_id=$1
       AND (d.id=a.target_device_id OR (a.actor_type='device' AND d.id=a.actor_id)))
   OR (NOT EXISTS(SELECT FROM devices d WHERE d.tenant_id=a.tenant_id
         AND (d.id=a.target_device_id OR (a.actor_type='device' AND d.id=a.actor_id)))
       AND EXISTS(SELECT FROM audit_log enrolled WHERE enrolled.tenant_id=a.tenant_id
         AND enrolled.action='device.enrolled' AND enrolled.actor_type='user' AND enrolled.actor_id=$1
         AND (enrolled.target_device_id=a.target_device_id OR (a.actor_type='device' AND enrolled.target_device_id=a.actor_id))
         AND NOT EXISTS(SELECT FROM audit_log conflicting WHERE conflicting.tenant_id=enrolled.tenant_id
           AND conflicting.action='device.enrolled' AND conflicting.target_device_id=enrolled.target_device_id
           AND (conflicting.actor_type<>'user' OR conflicting.actor_id IS DISTINCT FROM enrolled.actor_id)))))
 ORDER BY a.sequence DESC LIMIT $10`, actor, role, s.Tenant, before, query.Action, query.DeviceID, query.UserID, query.Since, query.Until, query.Limit+1)
	if err != nil {
		return web.AuditPage{}, err
	}
	page := web.AuditPage{Items: []web.AuditEntry{}}
	var last int64
	for rows.Next() {
		var entry web.AuditEntry
		var sequence int64
		var ip sql.NullString
		var details []byte
		if err = rows.Scan(&sequence, &entry.ID, &entry.CreatedAt, &entry.ActorType, &entry.Actor, &entry.Action, &entry.TargetDeviceID, &ip, &details); err != nil {
			rows.Close()
			return web.AuditPage{}, err
		}
		if len(page.Items) == query.Limit {
			cursor := web.AuditCursor(s.Tenant+":"+actor, query, last)
			page.NextCursor = &cursor
			break
		}
		entry.CreatedAt = entry.CreatedAt.UTC()
		if ip.Valid {
			if address, parseErr := netip.ParseAddr(ip.String); parseErr == nil && address.Zone() == "" {
				value := address.Unmap().String()
				entry.ClientIP = &value
			}
		}
		entry.Details = auditDetails(details)
		page.Items = append(page.Items, entry)
		last = sequence
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return web.AuditPage{}, err
	}
	return page, tx.Commit()
}

func auditDetails(raw []byte) web.AuditDetails {
	var fields map[string]json.RawMessage
	var result web.AuditDetails
	if len(raw) > 1024 || json.Unmarshal(raw, &fields) != nil {
		return result
	}
	var target, role string
	if json.Unmarshal(fields["target_user_id"], &target) == nil && (web.AuditQuery{UserID: target, Limit: 1}).Valid() && target != "" {
		result.TargetUserID = &target
	}
	if json.Unmarshal(fields["role"], &role) == nil && (role == "admin" || role == "member") {
		result.Role = &role
	}
	var disabled bool
	if string(fields["disabled"]) != "null" && json.Unmarshal(fields["disabled"], &disabled) == nil {
		result.Disabled = &disabled
	}
	var sessions int64
	if string(fields["sessions_revoked"]) != "null" && json.Unmarshal(fields["sessions_revoked"], &sessions) == nil && sessions >= 0 && sessions < 1_000_000_000 {
		result.SessionsRevoked = &sessions
	}
	var expiry, request string
	if json.Unmarshal(fields["expires_at"], &expiry) == nil {
		if stamp, err := time.Parse(time.RFC3339Nano, expiry); err == nil && !stamp.IsZero() && stamp.Year() >= 1 && stamp.Year() <= 9999 {
			stamp = stamp.UTC()
			result.ExpiresAt = &stamp
		}
	}
	if json.Unmarshal(fields["request_id"], &request) == nil && request != "" && (web.AuditQuery{DeviceID: request, Limit: 1}).Valid() {
		result.RequestID = &request
	}
	return result
}
