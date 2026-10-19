package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/netip"
	"regexp"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/guicert"
)

var ErrGUIRequestConflict = guicert.ErrConflict

var certificateDomain = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
var certificateLabel = regexp.MustCompile(`^[a-z0-9]{8}$`)

// GUIRequest is public signed material, excluded from ordinary status JSON.
// A request identifies the CSR, not a certificate generation or an issuance grant.
type GUIRequest = guicert.StoredRequest

// GUIRequestStore must receive DeviceDomain from trusted deployment settings.
// No API caller may supply the assigned host, tenant or enrollment public key.
type GUIRequestStore struct {
	Enrollment   *EnrollmentStore
	DeviceDomain string
}

func (s *GUIRequestStore) configured() bool {
	if s == nil || s.Enrollment == nil || len(s.DeviceDomain) > 244 || !certificateDomain.MatchString(s.DeviceDomain) {
		return false
	}
	_, err := netip.ParseAddr(s.DeviceDomain)
	return err != nil
}

// Health is required before exposing certificate admission.
func (s *GUIRequestStore) Health(ctx context.Context) error {
	if !s.configured() || s.Enrollment.Health(ctx) != nil {
		return device.ErrUnavailable
	}
	var ready bool
	err := s.Enrollment.DB.QueryRowContext(ctx, `SELECT
 has_table_privilege(current_user,'public.gui_certificate_requests','SELECT')
 AND has_table_privilege(current_user,'public.gui_certificate_requests','INSERT')
 AND NOT has_table_privilege(current_user,'public.gui_certificate_requests','UPDATE,DELETE,TRUNCATE')
 AND EXISTS (SELECT 1 FROM pg_class WHERE oid='public.gui_certificate_requests'::regclass AND relrowsecurity AND relforcerowsecurity)
 AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='public.gui_certificate_requests'::regclass
  AND tgname='gui_certificate_request_binding' AND NOT tgisinternal AND tgenabled IN ('O','A')
  AND tgfoid='public.guard_gui_certificate_request()'::regprocedure)`).Scan(&ready)
	if err != nil || !ready {
		return device.ErrUnavailable
	}
	return nil
}

func (s *GUIRequestStore) lock(ctx context.Context, credential device.Credential, id string) (*sql.Tx, string, string, error) {
	if !s.configured() {
		return nil, "", "", device.ErrUnavailable
	}
	tx, revoked, err := s.Enrollment.lockDevice(ctx, credential, id)
	if err != nil {
		return nil, "", "", err
	}
	if revoked {
		tx.Rollback()
		return nil, "", "", device.ErrDenied
	}
	var key sql.NullString
	var label string
	if err := tx.QueryRowContext(ctx, `SELECT gui_public_key,subdomain FROM devices WHERE id=$1 AND tenant_id=$2`, id, credential.TenantID).Scan(&key, &label); err != nil {
		tx.Rollback()
		return nil, "", "", device.ErrUnavailable
	}
	if !key.Valid || !certificateLabel.MatchString(label) {
		tx.Rollback()
		return nil, "", "", device.ErrDenied
	}
	if _, err := guicert.ValidatePublicKey(key.String); err != nil {
		tx.Rollback()
		return nil, "", "", device.ErrUnavailable
	}
	return tx, label + "." + s.DeviceDomain, key.String, nil
}

func readGUIRequest(ctx context.Context, tx *sql.Tx, tenant, id, host, key string) (GUIRequest, bool, error) {
	var result GUIRequest
	err := tx.QueryRowContext(ctx, `SELECT id,device_id,assigned_host,gui_public_key,csr_der,csr_fingerprint,created_at
 FROM gui_certificate_requests WHERE tenant_id=$1 AND device_id=$2`, tenant, id).Scan(&result.ID, &result.DeviceID, &result.AssignedHost, &result.PublicKey, &result.DER, &result.Fingerprint, &result.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return GUIRequest{}, false, nil
	}
	if err != nil {
		return GUIRequest{}, false, device.ErrUnavailable
	}
	if result.AssignedHost != host || result.PublicKey != key {
		return GUIRequest{}, false, device.ErrDenied
	}
	request, err := guicert.ValidateBoundCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: result.DER}), host, key)
	if err != nil || len(result.DER) > 4096 || hex.EncodeToString(request.Fingerprint[:]) != result.Fingerprint {
		return GUIRequest{}, false, device.ErrUnavailable
	}
	return result, true, nil
}

// Read reauthorizes the live credential and assignment before returning the exact
// original CSR for cache recovery. Revocation does not delete retained evidence.
func (s *GUIRequestStore) Read(ctx context.Context, credential device.Credential, id string) (GUIRequest, bool, error) {
	_, record, err := s.Settings(ctx, credential, id)
	if err != nil || record == nil {
		return GUIRequest{}, false, err
	}
	return *record, true, nil
}

// Settings returns the current assignment and, when present, its original CSR.
func (s *GUIRequestStore) Settings(ctx context.Context, credential device.Credential, id string) (guicert.Assignment, *GUIRequest, error) {
	tx, host, key, err := s.lock(ctx, credential, id)
	if err != nil {
		return guicert.Assignment{}, nil, err
	}
	defer tx.Rollback()
	result, found, err := readGUIRequest(ctx, tx, credential.TenantID, id, host, key)
	if err != nil {
		return guicert.Assignment{}, nil, err
	}
	if tx.Commit() != nil {
		return guicert.Assignment{}, nil, device.ErrUnavailable
	}
	bound, err := guicert.ValidatePublicKey(key)
	if err != nil {
		return guicert.Assignment{}, nil, device.ErrUnavailable
	}
	assignment := guicert.Assignment{Host: host, KeyFingerprint: bound.Fingerprint}
	if !found {
		return assignment, nil, nil
	}
	return assignment, &result, nil
}

// Admit atomically validates and persists the signed request with the current
// immutable key binding. Identical retries return the same row; changed signed
// bytes conflict, even if they request the same name with the same public key.
// No database transaction remains open across CA or other network operations.
func (s *GUIRequestStore) Admit(ctx context.Context, credential device.Credential, id string, encoded []byte) (GUIRequest, error) {
	tx, host, key, err := s.lock(ctx, credential, id)
	if err != nil {
		return GUIRequest{}, err
	}
	defer tx.Rollback()
	request, err := guicert.ValidateBoundCSR(encoded, host, key)
	if err != nil || len(request.DER) > 4096 {
		return GUIRequest{}, guicert.ErrRequest
	}
	result, found, err := readGUIRequest(ctx, tx, credential.TenantID, id, host, key)
	if err != nil {
		return GUIRequest{}, err
	}
	if found && !bytes.Equal(request.DER, result.DER) {
		return GUIRequest{}, ErrGUIRequestConflict
	}
	if !found {
		if _, err := tx.ExecContext(ctx, `INSERT INTO gui_certificate_requests(tenant_id,device_id,assigned_host,gui_public_key,csr_der) VALUES($1,$2,$3,$4,$5)`, credential.TenantID, id, host, key, request.DER); err != nil {
			return GUIRequest{}, device.ErrUnavailable
		}
		result, found, err = readGUIRequest(ctx, tx, credential.TenantID, id, host, key)
		if err != nil || !found {
			return GUIRequest{}, device.ErrUnavailable
		}
		data, err := json.Marshal(map[string]string{"request_id": result.ID, "csr_fingerprint": result.Fingerprint})
		if err != nil {
			return GUIRequest{}, device.ErrUnavailable
		}
		if _, err := tx.ExecContext(ctx, `SELECT append_audit('device',$1,'device.certificate_requested',$1,$2::jsonb)`, id, string(data)); err != nil {
			return GUIRequest{}, device.ErrUnavailable
		}
	}
	if tx.Commit() != nil {
		return GUIRequest{}, device.ErrUnavailable
	}
	return result, nil
}
