package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/guicert"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/jackc/pgx/v5/pgconn"
)

func testGUIKeyBinding(t *testing.T, f *enrollmentFixture, web *sql.DB, tenantA, tenantB string) {
	t.Run("readiness_requires_immutable_binding_guard", func(t *testing.T) {
		if _, err := f.owner.ExecContext(f.ctx, `ALTER TABLE devices DISABLE TRIGGER devices_gui_key_binding`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.owner.ExecContext(f.ctx, `ALTER TABLE devices ENABLE TRIGGER devices_gui_key_binding`); err != nil {
				t.Fatal(err)
			}
		}()
		if f.repository.Health(f.ctx) == nil {
			t.Fatal("authorization ready without immutable binding guard")
		}
	})
	makeKey := func() (string, string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		value := base64.RawURLEncoding.EncodeToString(der)
		bound, err := guicert.ValidatePublicKey(value)
		if err != nil {
			t.Fatal(err)
		}
		return value, bound.Fingerprint
	}
	key, fingerprint := makeKey()
	other, _ := makeKey()
	_, token, _ := f.fresh(t, tenantA)
	request := f.input
	request.EnrollToken, request.GUIPublicKey = token, key
	status, body := f.post(t, request)
	var response protocol.EnrollResponse
	if status != http.StatusCreated || json.Unmarshal(body, &response) != nil || response.GUIKeyFingerprint != fingerprint {
		t.Fatal("initial public-key enrollment failed")
	}
	f.validateResponse(t, body)
	var stored string
	if err := f.owner.QueryRowContext(f.ctx, `SELECT gui_public_key FROM devices WHERE id=$1`, response.DeviceID).Scan(&stored); err != nil || stored != key {
		t.Fatal("binding was not committed with enrollment")
	}
	request.GUIPublicKey = other
	if status, _ := f.post(t, request); status != http.StatusUnauthorized {
		t.Fatal("one-use token rebound key")
	}
	checkMutation := func(role *sql.DB, tenant string, value any, want string) {
		t.Helper()
		tx, err := role.BeginTx(f.ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(f.ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		_, err = tx.ExecContext(f.ctx, `UPDATE devices SET gui_public_key=$1 WHERE id=$2`, value, response.DeviceID)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != want {
			t.Fatalf("binding update SQLSTATE: %v", err)
		}
	}
	for _, value := range []any{other, nil} {
		checkMutation(f.repository.DB, tenantA, value, "P0001")
		checkMutation(f.owner, tenantA, value, "P0001")
		checkMutation(web, tenantA, value, "42501")
	}
	tx, err := f.repository.DB.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenantB); err != nil {
		t.Fatal(err)
	}
	result, err := tx.ExecContext(f.ctx, `UPDATE devices SET gui_public_key=$1 WHERE id=$2`, other, response.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := result.RowsAffected(); err != nil || n != 0 {
		t.Fatal("cross-tenant binding update reached row")
	}
	_ = tx.Rollback()
	tx, err = web.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenantA); err != nil {
		t.Fatal(err)
	}
	var hidden string
	err = tx.QueryRowContext(f.ctx, `SELECT gui_public_key FROM devices WHERE id=$1`, response.DeviceID).Scan(&hidden)
	var denied *pgconn.PgError
	if !errors.As(err, &denied) || denied.Code != "42501" {
		t.Fatal("web role can read issuance key binding")
	}
	_ = tx.Rollback()
	legacy, _, _ := f.fresh(t, tenantA)
	assigned, err := f.repository.Register(f.ctx, legacy, f.issue)
	if err != nil {
		t.Fatal(err)
	}
	if err := rejectLegacyBinding(f.ctx, f.owner, assigned.ID, other); err != nil {
		t.Fatal(err)
	}
	// An invalid point has the correct wire shape but is rejected before token use.
	invalid, rawToken, _ := f.fresh(t, tenantA)
	request.EnrollToken, request.GUIPublicKey = rawToken, base64.RawURLEncoding.EncodeToString(make([]byte, 91))
	if status, _ := f.post(t, request); status != http.StatusBadRequest {
		t.Fatal("invalid public point accepted")
	}
	f.unused(t, invalid)
	t.Log("Initial key binding, one-use replay rejection, immutable updates, legacy no-backfill, role scope and pre-consumption point validation passed")
}

func rejectLegacyBinding(ctx context.Context, owner *sql.DB, id, key string) error {
	_, err := owner.ExecContext(ctx, `UPDATE devices SET gui_public_key=$1 WHERE id=$2`, key, id)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "P0001" {
		return errors.New("legacy device accepted bearer-era key backfill")
	}
	return nil
}
