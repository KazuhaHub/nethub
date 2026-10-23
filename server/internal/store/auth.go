package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
)

// AuthStore binds all console authentication operations to one deployment tenant.
// The tenant is selected at startup, never from a request parameter or cookie.
type AuthStore struct {
	DB     *sql.DB
	Tenant string
}

var _ auth.Repository = (*AuthStore)(nil)

func (s *AuthStore) begin(ctx context.Context, readOnly bool) (*sql.Tx, error) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: readOnly})
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true)`, s.Tenant); err != nil {
		tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func (s *AuthStore) PasswordCandidate(ctx context.Context, email string) (auth.Candidate, error) {
	tx, err := s.begin(ctx, true)
	if err != nil {
		return auth.Candidate{}, err
	}
	defer tx.Rollback()
	var candidate auth.Candidate
	err = tx.QueryRowContext(ctx, `SELECT id,email,role,coalesce(password_hash,''),disabled_at IS NOT NULL FROM users WHERE lower(email)=$1`, email).Scan(&candidate.ID, &candidate.Email, &candidate.Role, &candidate.PasswordHash, &candidate.Disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.Candidate{}, auth.ErrInvalidCredentials
	}
	if err != nil {
		return auth.Candidate{}, err
	}
	return candidate, tx.Commit()
}

func (s *AuthStore) CreateSession(ctx context.Context, candidate auth.Candidate, record auth.SessionRecord) (auth.SessionRecord, error) {
	if len(record.TokenHash) != 32 || len(record.CSRFHash) != 32 || !record.IP.IsValid() || record.IP.Zone() != "" || len(record.UserAgent) > 1024 || !record.ExpiresAt.After(record.CreatedAt) {
		return auth.SessionRecord{}, errors.New("invalid session record")
	}
	tx, err := s.begin(ctx, false)
	if err != nil {
		return auth.SessionRecord{}, err
	}
	defer tx.Rollback()
	// Hold the user lock through insertion: a password change or disable that
	// committed while Argon2 ran must prevent this new session.
	err = tx.QueryRowContext(ctx, `SELECT id,email,role FROM users WHERE id=$1 AND disabled_at IS NULL AND password_hash=$2 FOR SHARE`, candidate.ID, candidate.PasswordHash).Scan(&record.ID, &record.Email, &record.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.SessionRecord{}, auth.ErrInvalidCredentials
	}
	if err != nil {
		return auth.SessionRecord{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO sessions(tenant_id,user_id,token_hash,csrf_hash,created_at,expires_at,last_seen_at,ip,user_agent) VALUES($1,$2,$3,$4,$5,$6,$5,$7,$8)`, s.Tenant, record.ID, record.TokenHash, record.CSRFHash, record.CreatedAt, record.ExpiresAt, record.IP.Unmap().String(), record.UserAgent)
	if err != nil {
		return auth.SessionRecord{}, err
	}
	if err = appendConsoleAudit(ctx, tx, "user", record.ID, "auth.login", record.IP, ""); err != nil {
		return auth.SessionRecord{}, err
	}
	return record, tx.Commit()
}

func (s *AuthStore) LookupSession(ctx context.Context, digest []byte, idle time.Duration) (auth.SessionRecord, error) {
	return s.lookupSession(ctx, digest, idle, true)
}

func (s *AuthStore) LookupSessionPassive(ctx context.Context, digest []byte, idle time.Duration) (auth.SessionRecord, error) {
	return s.lookupSession(ctx, digest, idle, false)
}

func (s *AuthStore) lookupSession(ctx context.Context, digest []byte, idle time.Duration, touch bool) (auth.SessionRecord, error) {
	if len(digest) != 32 || idle < time.Second {
		return auth.SessionRecord{}, auth.ErrUnauthenticated
	}
	tx, err := s.begin(ctx, false)
	if err != nil {
		return auth.SessionRecord{}, err
	}
	defer tx.Rollback()
	var record auth.SessionRecord
	// Acquire user then session locks in separate statements. PostgreSQL may
	// evaluate UPDATE predicates before waiting for row locks, even when they
	// use clock_timestamp(). Expiry is checked only after both locks are held.
	err = tx.QueryRowContext(ctx, `SELECT u.id,u.email,u.role FROM users u
 JOIN sessions s ON s.user_id=u.id AND s.tenant_id=u.tenant_id
 WHERE s.token_hash=$1 AND u.disabled_at IS NULL FOR SHARE OF u`, digest).Scan(&record.ID, &record.Email, &record.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.SessionRecord{}, auth.ErrUnauthenticated
	}
	if err != nil {
		return auth.SessionRecord{}, err
	}
	var sessionID string
	lock := "FOR SHARE"
	if touch {
		lock = "FOR UPDATE"
	}
	err = tx.QueryRowContext(ctx, `SELECT id FROM sessions WHERE token_hash=$1 AND user_id=$2 `+lock, digest, record.ID).Scan(&sessionID)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.SessionRecord{}, auth.ErrUnauthenticated
	}
	if err != nil {
		return auth.SessionRecord{}, err
	}
	query := `UPDATE sessions SET last_seen_at=greatest(last_seen_at,clock_timestamp())
 WHERE id=$1 AND created_at<=clock_timestamp() AND expires_at>clock_timestamp()
 AND last_seen_at>clock_timestamp()-($2 * interval '1 millisecond')
 RETURNING csrf_hash,created_at,expires_at`
	if !touch {
		query = `SELECT csrf_hash,created_at,expires_at FROM sessions
 WHERE id=$1 AND created_at<=clock_timestamp() AND expires_at>clock_timestamp()
 AND last_seen_at>clock_timestamp()-($2 * interval '1 millisecond')`
	}
	err = tx.QueryRowContext(ctx, query, sessionID, idle.Milliseconds()).Scan(&record.CSRFHash, &record.CreatedAt, &record.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.SessionRecord{}, auth.ErrUnauthenticated
	}
	if err != nil {
		return auth.SessionRecord{}, err
	}
	return record, tx.Commit()
}

func (s *AuthStore) DeleteSession(ctx context.Context, digest []byte, ip netip.Addr) error {
	tx, err := s.begin(ctx, false)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var actor string
	err = tx.QueryRowContext(ctx, `SELECT u.id FROM users u JOIN sessions s ON s.user_id=u.id AND s.tenant_id=u.tenant_id WHERE s.token_hash=$1 FOR SHARE OF u`, digest).Scan(&actor)
	if errors.Is(err, sql.ErrNoRows) {
		return tx.Commit()
	}
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=$1`, digest); err != nil {
		return err
	}
	if err = appendConsoleAudit(ctx, tx, "user", actor, "auth.logout", ip, ""); err != nil {
		return err
	}
	return tx.Commit()
}
