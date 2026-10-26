package store

import (
	"context"
	"crypto/sha256"
	"time"
	"unicode/utf8"

	authsaml "github.com/KazuhaHub/authcore/saml"
	"github.com/KazuhaHub/nethub/server/internal/sso"
)

type samlReplayCache struct {
	store      *ConsoleStore
	providerID string
}

var _ authsaml.ReplayCache = (*samlReplayCache)(nil)

// SAMLReplayCache supplies authcore with provider-scoped durable replay state.
// Metadata revisions do not reset it. Application admission remains separate.
func (s *ConsoleStore) SAMLReplayCache(providerID string) authsaml.ReplayCache {
	return &samlReplayCache{store: s, providerID: providerID}
}

func (c *samlReplayCache) SeenOrAdd(ctx context.Context, id string, expiresAt, now time.Time) (bool, error) {
	if ctx == nil || c == nil || c.store == nil || c.store.DB == nil || c.providerID == "" || len(id) == 0 || len(id) > 4096 || !utf8.ValidString(id) || now.IsZero() || !expiresAt.After(now) {
		return false, sso.ErrFlow
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tx, err := c.store.begin(ctx, false)
	if err != nil {
		return false, sso.ErrFlow
	}
	defer tx.Rollback()
	var enabled bool
	if err = tx.QueryRowContext(ctx, `SELECT enabled AND deleted_at IS NULL FROM identity_providers WHERE id=$1 AND kind='saml' FOR SHARE`, c.providerID).Scan(&enabled); err != nil || !enabled {
		return false, sso.ErrFlow
	}
	// Serialize bounded cleanup/count/insert across Web instances. Existing
	// records never lose protection to make room for a new assertion.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, c.store.Tenant+":saml-replays"); err != nil {
		return false, sso.ErrFlow
	}
	var stamp time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&stamp); err != nil || !expiresAt.After(stamp) {
		return false, sso.ErrFlow
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM saml_replays WHERE expires_at<=$1`, stamp); err != nil {
		return false, sso.ErrFlow
	}
	digest := sha256.Sum256([]byte(id))
	var seen bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM saml_replays WHERE provider_id=$1 AND assertion_hash=$2)`, c.providerID, digest[:]).Scan(&seen); err != nil {
		return false, sso.ErrFlow
	}
	if !seen {
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM saml_replays`).Scan(&count); err != nil {
			return false, sso.ErrFlow
		}
		if count >= 10000 {
			return false, authsaml.ErrReplayCacheFull
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO saml_replays(tenant_id,provider_id,assertion_hash,created_at,expires_at) VALUES($1,$2,$3,$4,$5)`, c.store.Tenant, c.providerID, digest[:], stamp, expiresAt); err != nil {
			return false, sso.ErrFlow
		}
	}
	if err = tx.Commit(); err != nil {
		return false, sso.ErrFlow
	}
	return seen, nil
}
