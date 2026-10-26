package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"math"
)

var (
	ErrAuditChainInvalid     = errors.New("audit chain cannot be verified")
	ErrAuditChainUnavailable = errors.New("audit verification unavailable")
)

// AuditChainResult describes one coherent tenant snapshot, not an external seal.
type AuditChainResult struct {
	Entries       int64
	LegacyEntries int64
}

type auditChainState struct {
	AuditChainResult
	head []byte
}

func (s *auditChainState) accept(sequence int64, previous, digest, content []byte, version int) error {
	if s.Entries == math.MaxInt64 || sequence != s.Entries+1 ||
		!bytes.Equal(previous, s.head) || len(digest) != sha256.Size ||
		len(content) == 0 || len(content) > 1<<20 || (version != 1 && version != 2) {
		return ErrAuditChainInvalid
	}
	actual := sha256.Sum256(content)
	if !bytes.Equal(actual[:], digest) {
		return ErrAuditChainInvalid
	}
	s.Entries++
	if version == 1 {
		s.LegacyEntries++
	}
	s.head = append(s.head[:0], digest...)
	return nil
}

// VerifyAuditChain never repairs history. Legacy entries require their original
// writer timezone; version 2 always serializes the timestamp explicitly in UTC.
// A valid prefix cannot establish absence of tail truncation or hostile rewriting.
func VerifyAuditChain(ctx context.Context, db *sql.DB, tenant, legacyZone string) (AuditChainResult, error) {
	if db == nil || tenant == "" {
		return AuditChainResult{}, ErrAuditChainUnavailable
	}
	if legacyZone == "" {
		legacyZone = "UTC"
	}
	if len(legacyZone) > 64 {
		return AuditChainResult{}, ErrAuditChainUnavailable
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return AuditChainResult{}, ErrAuditChainUnavailable
	}
	defer tx.Rollback()
	var valid bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_timezone_names WHERE name=$1)
        AND EXISTS(SELECT 1 FROM public.tenants WHERE id=$2)`, legacyZone, tenant).Scan(&valid); err != nil || !valid {
		return AuditChainResult{}, ErrAuditChainUnavailable
	}
	if _, err = tx.ExecContext(ctx, `SELECT set_config('app.tenant_id',$1,true),set_config('TimeZone',$2,true)`, tenant, legacyZone); err != nil {
		return AuditChainResult{}, ErrAuditChainUnavailable
	}
	rows, err := tx.QueryContext(ctx, `WITH documents AS (
        SELECT sequence,prev_hash,entry_hash,hash_version,
        CASE hash_version WHEN 1 THEN jsonb_build_object(
            'id',id,'tenant_id',tenant_id,'sequence',sequence,'actor_type',actor_type,
            'actor_id',actor_id,'action',action,'target_device_id',target_device_id,
            'payload',payload,'created_at',created_at,'prev_hash',encode(prev_hash,'hex'))::text
        WHEN 2 THEN jsonb_build_object(
            'id',id,'tenant_id',tenant_id,'sequence',sequence,'actor_type',actor_type,
            'actor_id',actor_id,'action',action,'target_device_id',target_device_id,
            'payload',payload,'created_at',to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            'prev_hash',encode(prev_hash,'hex'),'hash_version',2)::text END AS body
        FROM public.audit_log WHERE tenant_id=$1)
        SELECT sequence,prev_hash,entry_hash,hash_version,
            CASE WHEN octet_length(body)<=1048576 THEN convert_to(body,'UTF8') END
        FROM documents ORDER BY sequence`, tenant)
	if err != nil {
		return AuditChainResult{}, ErrAuditChainUnavailable
	}
	defer rows.Close()
	var state auditChainState
	for rows.Next() {
		var sequence int64
		var previous, digest, content []byte
		var version int
		if err = rows.Scan(&sequence, &previous, &digest, &version, &content); err != nil {
			return AuditChainResult{}, ErrAuditChainUnavailable
		}
		if err = state.accept(sequence, previous, digest, content, version); err != nil {
			return AuditChainResult{}, err
		}
	}
	if err = rows.Err(); err != nil {
		return AuditChainResult{}, ErrAuditChainUnavailable
	}
	if err = rows.Close(); err != nil {
		return AuditChainResult{}, ErrAuditChainUnavailable
	}
	if err = tx.Commit(); err != nil {
		return AuditChainResult{}, ErrAuditChainUnavailable
	}
	return state.AuditChainResult, nil
}
