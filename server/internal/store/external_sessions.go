package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
)

var _ auth.ExternalRepository = (*AuthStore)(nil)

// The caller has already verified the protocol assertion. Recheck its consumed
// flow, provider and account in SQL; request JSON cannot supply this identity.
func (s *AuthStore) CreateExternalSession(ctx context.Context, identity auth.ExternalIdentity, record auth.SessionRecord) (auth.SessionRecord, error) {
	if !validSessionRecord(record) || identity.Subject == "" || identity.ProviderRevision < 1 {
		return auth.SessionRecord{}, auth.ErrInvalidCredentials
	}
	protocol := identity.Protocol
	if protocol == "" {
		protocol = "oidc"
	}
	flowTable := "oidc_flows"
	providerQuery := `SELECT p.revision,o.issuer_url FROM identity_providers p JOIN oidc_providers o ON o.tenant_id=p.tenant_id AND o.id=p.id WHERE p.id=$1 AND p.enabled AND p.deleted_at IS NULL FOR SHARE OF p`
	switch protocol {
	case "oidc":
	case "saml":
		flowTable = "saml_flows"
		providerQuery = `SELECT p.revision,s.entity_id FROM identity_providers p JOIN saml_providers s ON s.tenant_id=p.tenant_id AND s.id=p.id WHERE p.id=$1 AND p.enabled AND p.deleted_at IS NULL FOR SHARE OF p`
	default:
		return auth.SessionRecord{}, auth.ErrInvalidCredentials
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, false)
	if err != nil {
		return auth.SessionRecord{}, err
	}
	defer tx.Rollback()
	var revision int64
	var issuer string
	err = tx.QueryRowContext(ctx, providerQuery, identity.ProviderID).Scan(&revision, &issuer)
	if err != nil || revision != identity.ProviderRevision || issuer != identity.Issuer {
		return auth.SessionRecord{}, auth.ErrInvalidCredentials
	}
	var invitation []byte
	// The table name is selected only by the closed protocol switch above.
	err = tx.QueryRowContext(ctx, `SELECT invitation_hash FROM `+flowTable+` WHERE id=$1 AND provider_id=$2 AND provider_revision=$3 AND consumed_at IS NOT NULL AND admitted_at IS NULL FOR UPDATE`, identity.FlowID, identity.ProviderID, revision).Scan(&invitation)
	if err != nil {
		return auth.SessionRecord{}, auth.ErrInvalidCredentials
	}
	key, _ := json.Marshal([]string{identity.Issuer, identity.Subject})
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, s.Tenant+":"+protocol+"-identity:"+string(key)); err != nil {
		return auth.SessionRecord{}, err
	}
	var userID string
	err = tx.QueryRowContext(ctx, `SELECT user_id FROM user_identities WHERE protocol=$1 AND issuer=$2 AND subject=$3 AND ($1='oidc' OR provider_id=$4)`, protocol, identity.Issuer, identity.Subject, identity.ProviderID).Scan(&userID)
	if err == nil {
		// OIDC uses issuer/subject across aliases. SAML additionally retains its
		// provider/SP scope. Email claims never relink an account.
		err = tx.QueryRowContext(ctx, `SELECT id,email,role FROM users WHERE id=$1 AND disabled_at IS NULL FOR SHARE`, userID).Scan(&record.ID, &record.Email, &record.Role)
		if err != nil {
			return auth.SessionRecord{}, auth.ErrInvalidCredentials
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		trustedEmail := protocol == "oidc" && identity.EmailVerified || protocol == "saml" && identity.SignedEmail
		if !trustedEmail || len(invitation) != 32 {
			return auth.SessionRecord{}, auth.ErrInvalidCredentials
		}
		email, e := auth.NormalizeEmail(identity.Email)
		if e != nil {
			return auth.SessionRecord{}, auth.ErrInvalidCredentials
		}
		var inviteID, invitedEmail, role string
		var restriction *string
		err = tx.QueryRowContext(ctx, `SELECT id,email,role,provider_id FROM invites WHERE token_hash=$1 FOR UPDATE`, invitation).Scan(&inviteID, &invitedEmail, &role, &restriction)
		if err != nil || email != invitedEmail || restriction != nil && *restriction != identity.ProviderID {
			return auth.SessionRecord{}, auth.ErrInvalidCredentials
		}
		if err = lockInvitationEmail(ctx, tx, s.Tenant, email); err != nil {
			return auth.SessionRecord{}, err
		}
		var used string
		err = tx.QueryRowContext(ctx, `UPDATE invites SET used_at=clock_timestamp() WHERE id=$1 AND used_at IS NULL AND cancelled_at IS NULL AND created_at<=clock_timestamp() AND expires_at>clock_timestamp() RETURNING id`, inviteID).Scan(&used)
		if err != nil {
			return auth.SessionRecord{}, auth.ErrInvalidCredentials
		}
		var exists bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM users WHERE lower(email)=$1)`, email).Scan(&exists); err != nil {
			return auth.SessionRecord{}, err
		}
		if exists {
			return auth.SessionRecord{}, auth.ErrInvalidCredentials
		}
		err = tx.QueryRowContext(ctx, `INSERT INTO users(tenant_id,email,role,password_hash) VALUES($1,$2,$3,NULL) RETURNING id,email,role`, s.Tenant, email, role).Scan(&record.ID, &record.Email, &record.Role)
		if err != nil {
			return auth.SessionRecord{}, auth.ErrInvalidCredentials
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO user_identities(tenant_id,user_id,provider_id,protocol,issuer,subject,email_at_link) VALUES($1,$2,$3,$4,$5,$6,$7)`, s.Tenant, record.ID, identity.ProviderID, protocol, identity.Issuer, identity.Subject, email)
		if err != nil {
			return auth.SessionRecord{}, auth.ErrInvalidCredentials
		}
		if err = appendInvitationAudit(ctx, tx, record.ID, "invite.accepted", record.IP, inviteID); err != nil {
			return auth.SessionRecord{}, err
		}
		if err = providerAudit(ctx, tx, record.ID, "identity.linked", identity.ProviderID, record.IP); err != nil {
			return auth.SessionRecord{}, err
		}
	} else {
		return auth.SessionRecord{}, err
	}
	// Check flow expiry after all provider, identity, invitation and account waits.
	var admitted string
	err = tx.QueryRowContext(ctx, `UPDATE `+flowTable+` SET admitted_at=clock_timestamp() WHERE id=$1 AND admitted_at IS NULL AND created_at<=clock_timestamp() AND expires_at>clock_timestamp() RETURNING id`, identity.FlowID).Scan(&admitted)
	if err != nil {
		return auth.SessionRecord{}, auth.ErrInvalidCredentials
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
