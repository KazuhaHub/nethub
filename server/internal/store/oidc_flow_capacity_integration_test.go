package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	authoidc "github.com/KazuhaHub/authcore/oidc"
	"github.com/KazuhaHub/nethub/server/internal/providersecret"
	"github.com/KazuhaHub/nethub/server/internal/sso"
)

func testOIDCFlowCapacity(t *testing.T, ctx context.Context, owner, db *sql.DB, cipher *providersecret.Cipher) {
	var tenant, provider string
	if err := owner.QueryRowContext(ctx, `INSERT INTO tenants(name) VALUES('flow capacity fixture') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRowContext(ctx, `INSERT INTO identity_providers(tenant_id,kind,slug,display_name,enabled) VALUES($1,'oidc','capacity','Capacity',true) RETURNING id`, tenant).Scan(&provider); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ExecContext(ctx, `INSERT INTO oidc_providers(tenant_id,id,issuer_url,client_id) VALUES($1,$2,'https://capacity.example','console')`, tenant, provider); err != nil {
		t.Fatal(err)
	}
	// These inert rows occupy storage slots, not valid protocol authorizations.
	if _, err := owner.ExecContext(ctx, `WITH stamp AS (SELECT clock_timestamp() AS now) INSERT INTO oidc_flows(tenant_id,provider_id,provider_revision,state_hash,browser_hash,protocol_state_enc,created_at,expires_at) SELECT $1,$2,1,sha256(('capacity-fixture-'||i::text)::bytea),decode(repeat('00',32),'hex'),decode('00','hex'),stamp.now,stamp.now+interval '5 minutes' FROM generate_series(1,9999) AS i CROSS JOIN stamp`, tenant, provider); err != nil {
		t.Fatal(err)
	}
	opaque := func() string {
		t.Helper()
		value := make([]byte, 32)
		if _, err := rand.Read(value); err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(value)
	}
	input := func() sso.FlowInput {
		t.Helper()
		browser, _ := sso.Digest(opaque())
		return sso.FlowInput{Provider: sso.LoginProvider{ID: provider, Slug: "capacity", Revision: 1}, State: authoidc.State{Value: opaque(), Nonce: opaque(), Verifier: opaque(), Configuration: opaque()}, BrowserDigest: browser}
	}
	inputs := []sso.FlowInput{input(), input()}
	var winners atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, value := range inputs {
		wg.Add(1)
		go func(value sso.FlowInput) {
			defer wg.Done()
			<-start
			repository := &ConsoleStore{AuthStore: AuthStore{DB: db, Tenant: tenant}, ProviderSecrets: cipher}
			_, err := repository.SaveOIDCFlow(ctx, value)
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, sso.ErrFlow) {
				t.Error(err)
			}
		}(value)
	}
	close(start)
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("cross-repository capacity race admitted wrong count", winners.Load())
	}
	var count int
	if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM oidc_flows WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 10000 {
		t.Fatal("tenant flow capacity exceeded", count, err)
	}
	if _, err := owner.ExecContext(ctx, `UPDATE oidc_flows SET expires_at=created_at+interval '1 microsecond' WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	repository := &ConsoleStore{AuthStore: AuthStore{DB: db, Tenant: tenant}, ProviderSecrets: cipher}
	if _, err := repository.SaveOIDCFlow(ctx, input()); err != nil {
		t.Fatal("expired flow slots not reclaimed", err)
	}
	if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM oidc_flows WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 1 {
		t.Fatal("expired flow cleanup incomplete", count, err)
	}
	t.Log("Two genuine repositories admitted exactly one final flow slot; 10,000 expired rows were reclaimed before a new start")
}
