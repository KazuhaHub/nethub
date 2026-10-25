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
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/web"
	"github.com/jackc/pgx/v5/pgconn"
)

var _ auth.InvitationRepository = (*AuthStore)(nil)
var _ web.InvitationRepository = (*ConsoleStore)(nil)

func appendInvitationAudit(ctx context.Context, tx *sql.Tx, actor, action string, ip netip.Addr, id string) error {
	if !ip.IsValid() || ip.Zone() != "" {
		return errors.New("invalid invitation audit source")
	}
	payload, err := json.Marshal(map[string]string{"source_ip": ip.Unmap().String(), "invitation_id": id})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `SELECT append_audit('user',$1,$2,NULL,$3::jsonb)`, actor, action, string(payload))
	return err
}

func lockInvitationEmail(ctx context.Context, tx *sql.Tx, tenant, email string) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text || ':invite-email:' || $2::text,0))`, tenant, email)
	return err
}

func (s *ConsoleStore) IssueInvitation(ctx context.Context, actor string, input web.InvitationInput, ip netip.Addr) (web.IssuedInvitation, error) {
	email, err := auth.NormalizeEmail(input.Email)
	if err != nil || (input.Role != "admin" && input.Role != "member") || !ip.IsValid() || ip.Zone() != "" {
		return web.IssuedInvitation{}, errors.New("invalid invitation input")
	}
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return web.IssuedInvitation{}, errors.New("invitation randomness unavailable")
	}
	digest := sha256.Sum256(raw)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return web.IssuedInvitation{}, err
	}
	defer tx.Rollback()
	if err = requireAdmin(ctx, tx, actor); err != nil {
		return web.IssuedInvitation{}, err
	}
	if input.ProviderID != nil {
		var provider string
		err = tx.QueryRowContext(ctx, `SELECT id FROM identity_providers WHERE id=$1 AND enabled FOR SHARE`, *input.ProviderID).Scan(&provider)
		if errors.Is(err, sql.ErrNoRows) {
			return web.IssuedInvitation{}, web.ErrInviteProviderUnavailable
		}
		if err != nil {
			return web.IssuedInvitation{}, err
		}
	}
	if err = lockInvitationEmail(ctx, tx, s.Tenant, email); err != nil {
		return web.IssuedInvitation{}, err
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM users WHERE lower(email)=$1)`, email).Scan(&exists); err != nil {
		return web.IssuedInvitation{}, err
	}
	if exists {
		return web.IssuedInvitation{}, web.ErrUserExists
	}
	var result web.IssuedInvitation
	err = tx.QueryRowContext(ctx, `WITH stamp AS MATERIALIZED (SELECT clock_timestamp() AS t)
 INSERT INTO invites(tenant_id,email,role,token_hash,created_by_user_id,provider_id,created_at,expires_at)
 SELECT $1,$2,$3,$4,$5,$6::uuid,t,t+interval '72 hours' FROM stamp RETURNING id,expires_at`, s.Tenant, email, input.Role, digest[:], actor, input.ProviderID).Scan(&result.ID, &result.ExpiresAt)
	if err != nil {
		return web.IssuedInvitation{}, err
	}
	if err = appendInvitationAudit(ctx, tx, actor, "invite.created", ip, result.ID); err != nil {
		return web.IssuedInvitation{}, err
	}
	if err = tx.Commit(); err != nil {
		return web.IssuedInvitation{}, err
	}
	result.Token = base64.RawURLEncoding.EncodeToString(raw)
	return result, nil
}

func (s *ConsoleStore) Invitations(ctx context.Context, actor string, query web.UserQuery) (web.InvitationPage, error) {
	if query.Limit < 1 || query.Limit > 200 {
		return web.InvitationPage{}, errors.New("invalid invitation limit")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return web.InvitationPage{}, err
	}
	defer tx.Rollback()
	if err = requireAdmin(ctx, tx, actor); err != nil {
		return web.InvitationPage{}, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT i.id,i.email,i.role,i.provider_id,i.created_at,i.expires_at,u.id,u.email FROM invites i JOIN users u ON u.tenant_id=i.tenant_id AND u.id=i.created_by_user_id
 WHERE i.used_at IS NULL AND i.cancelled_at IS NULL AND i.created_at<=clock_timestamp() AND i.expires_at>clock_timestamp()
 AND (nullif($1,'')::uuid IS NULL OR i.id>nullif($1,'')::uuid) ORDER BY i.id LIMIT $2`, query.AfterID, query.Limit+1)
	if err != nil {
		return web.InvitationPage{}, err
	}
	page := web.InvitationPage{Items: []web.Invitation{}}
	for rows.Next() {
		var invite web.Invitation
		if err = rows.Scan(&invite.ID, &invite.Email, &invite.Role, &invite.ProviderID, &invite.CreatedAt, &invite.ExpiresAt, &invite.CreatedBy.ID, &invite.CreatedBy.Email); err != nil {
			rows.Close()
			return web.InvitationPage{}, err
		}
		page.Items = append(page.Items, invite)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return web.InvitationPage{}, err
	}
	if len(page.Items) > query.Limit {
		page.Items = page.Items[:query.Limit]
		cursor := base64.RawURLEncoding.EncodeToString([]byte(page.Items[len(page.Items)-1].ID))
		page.NextCursor = &cursor
	}
	return page, tx.Commit()
}

func (s *ConsoleStore) WithdrawInvitation(ctx context.Context, actor, id string, ip netip.Addr) error {
	if !ip.IsValid() || ip.Zone() != "" {
		return errors.New("invalid invitation source")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = requireAdmin(ctx, tx, actor); err != nil {
		return err
	}
	var used, cancelled sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT used_at,cancelled_at FROM invites WHERE id=$1 FOR UPDATE`, id).Scan(&used, &cancelled)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.ErrInviteInvalid
	}
	if err != nil {
		return err
	}
	if cancelled.Valid {
		return tx.Commit()
	}
	if used.Valid {
		return auth.ErrInviteInvalid
	}
	result, err := tx.ExecContext(ctx, `UPDATE invites SET cancelled_at=clock_timestamp() WHERE id=$1 AND expires_at>clock_timestamp() AND created_at<=clock_timestamp()`, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return auth.ErrInviteInvalid
	}
	if err = appendInvitationAudit(ctx, tx, actor, "invite.withdrawn", ip, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *ConsoleStore) InspectInvitation(ctx context.Context, digest []byte) (auth.InvitationInfo, error) {
	if len(digest) != 32 {
		return auth.InvitationInfo{}, auth.ErrInviteInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, true)
	if err != nil {
		return auth.InvitationInfo{}, err
	}
	defer tx.Rollback()
	var info auth.InvitationInfo
	var provider *string
	err = tx.QueryRowContext(ctx, `SELECT email,role,expires_at,provider_id FROM invites WHERE token_hash=$1 AND used_at IS NULL AND cancelled_at IS NULL AND created_at<=clock_timestamp() AND expires_at>clock_timestamp()`, digest).Scan(&info.Email, &info.Role, &info.ExpiresAt, &provider)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.InvitationInfo{}, auth.ErrInviteInvalid
	}
	if err != nil {
		return auth.InvitationInfo{}, err
	}
	info.PasswordAllowed = provider == nil
	info.Providers = []auth.InvitationProvider{}
	rows, err := tx.QueryContext(ctx, `SELECT slug,display_name,kind FROM identity_providers WHERE enabled AND ($1::uuid IS NULL OR id=$1::uuid) ORDER BY slug`, provider)
	if err != nil {
		return auth.InvitationInfo{}, err
	}
	for rows.Next() {
		var choice auth.InvitationProvider
		if err = rows.Scan(&choice.Slug, &choice.DisplayName, &choice.Kind); err != nil {
			rows.Close()
			return auth.InvitationInfo{}, err
		}
		info.Providers = append(info.Providers, choice)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return auth.InvitationInfo{}, err
	}
	if provider != nil && len(info.Providers) != 1 {
		return auth.InvitationInfo{}, auth.ErrInviteInvalid
	}
	return info, tx.Commit()
}

func (s *ConsoleStore) InvitationFailed(ctx context.Context, ip netip.Addr) error {
	if !ip.IsValid() || ip.Zone() != "" {
		return errors.New("invalid invitation source")
	}
	tx, err := s.begin(ctx, false)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = appendConsoleAudit(ctx, tx, "system", "", "auth.invite_failed", ip, ""); err != nil {
		return err
	}
	return tx.Commit()
}

// AcceptInvitation admits the bearer only after all row/email lock waits. The
// consume, account, session and both audit entries share one transaction.
func (s *AuthStore) AcceptInvitation(ctx context.Context, digest []byte, passwordHash string, record auth.SessionRecord) (auth.SessionRecord, error) {
	if len(digest) != 32 || passwordHash == "" || len(passwordHash) > 256 || !validSessionRecord(record) {
		return auth.SessionRecord{}, errors.New("invalid invitation activation")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return auth.SessionRecord{}, err
	}
	defer tx.Rollback()
	var id, email, role string
	var provider *string
	err = tx.QueryRowContext(ctx, `SELECT id,email,role,provider_id FROM invites WHERE token_hash=$1 FOR UPDATE`, digest).Scan(&id, &email, &role, &provider)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.SessionRecord{}, auth.ErrInviteInvalid
	}
	if err != nil {
		return auth.SessionRecord{}, err
	}
	if provider != nil {
		return auth.SessionRecord{}, auth.ErrInviteInvalid
	}
	email, err = auth.NormalizeEmail(email)
	if err != nil {
		return auth.SessionRecord{}, auth.ErrInviteInvalid
	}
	if err = lockInvitationEmail(ctx, tx, s.Tenant, email); err != nil {
		return auth.SessionRecord{}, err
	}
	var used time.Time
	err = tx.QueryRowContext(ctx, `UPDATE invites SET used_at=clock_timestamp() WHERE id=$1 AND used_at IS NULL AND cancelled_at IS NULL AND created_at<=clock_timestamp() AND expires_at>clock_timestamp() RETURNING used_at`, id).Scan(&used)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.SessionRecord{}, auth.ErrInviteInvalid
	}
	if err != nil {
		return auth.SessionRecord{}, err
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM users WHERE lower(email)=$1)`, email).Scan(&exists); err != nil {
		return auth.SessionRecord{}, err
	}
	if exists {
		return auth.SessionRecord{}, auth.ErrInviteInvalid
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO users(tenant_id,email,role,password_hash) VALUES($1,$2,$3,$4) RETURNING id,email,role`, s.Tenant, email, role, passwordHash).Scan(&record.ID, &record.Email, &record.Role)
	if err != nil {
		var failure *pgconn.PgError
		if errors.As(err, &failure) && failure.Code == "23505" {
			return auth.SessionRecord{}, auth.ErrInviteInvalid
		}
		return auth.SessionRecord{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO sessions(tenant_id,user_id,token_hash,csrf_hash,created_at,expires_at,last_seen_at,ip,user_agent) VALUES($1,$2,$3,$4,$5,$6,$5,$7,$8)`, s.Tenant, record.ID, record.TokenHash, record.CSRFHash, record.CreatedAt, record.ExpiresAt, record.IP.Unmap().String(), record.UserAgent)
	if err != nil {
		return auth.SessionRecord{}, err
	}
	if err = appendInvitationAudit(ctx, tx, record.ID, "invite.accepted", record.IP, id); err != nil {
		return auth.SessionRecord{}, err
	}
	if err = appendConsoleAudit(ctx, tx, "user", record.ID, "auth.login", record.IP, ""); err != nil {
		return auth.SessionRecord{}, err
	}
	return record, tx.Commit()
}
