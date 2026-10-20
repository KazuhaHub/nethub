package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/guicert"
)

// Issued holds the current credential/assignment lock through request validation,
// narrow public generation lookup and commit. Reading does not acknowledge apply.
func (s *GUIJobQueue) Issued(ctx context.Context, credential device.Credential, id, requestID, fingerprint string) (GUIRequest, *guicert.IssuedCertificate, error) {
	if s == nil || s.Requests == nil {
		return GUIRequest{}, nil, device.ErrUnavailable
	}
	tx, host, key, err := s.Requests.lock(ctx, credential, id)
	if err != nil {
		return GUIRequest{}, nil, err
	}
	defer tx.Rollback()
	request, found, err := readGUIRequest(ctx, tx, credential.TenantID, id, host, key)
	if err != nil {
		return GUIRequest{}, nil, err
	}
	if !found || request.ID != requestID || request.Fingerprint != fingerprint {
		return GUIRequest{}, nil, device.ErrDenied
	}
	var value guicert.IssuedCertificate
	err = tx.QueryRowContext(ctx, `SELECT id,generation,chain_pem,leaf_fingerprint,not_before,not_after,valid_until,renew_after
 FROM read_issued_gui_certificate($1,$2,$3,$4)`, id, requestID, fingerprint, host).Scan(&value.ID, &value.Generation, &value.PEM, &value.Fingerprint, &value.NotBefore, &value.NotAfter, &value.ValidUntil, &value.RenewAfter)
	var issued *guicert.IssuedCertificate
	if err == nil {
		// The immutable worker record already passed independent issuer trust.
		// Recheck public integrity here; the recipient still verifies its own roots.
		now := time.Now()
		chain, inspectErr := guicert.InspectChain(value.PEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request.DER}), host, now)
		if inspectErr != nil || value.Generation < 1 || value.Generation > 2147483647 || hex.EncodeToString(chain.Fingerprint[:]) != value.Fingerprint || !chain.NotBefore.Equal(value.NotBefore) || !chain.NotAfter.Equal(value.NotAfter) || value.ValidUntil.After(chain.ValidUntil) || !value.ValidUntil.After(now) || !value.RenewAfter.Before(value.ValidUntil) || !value.RenewAfter.After(value.NotBefore) {
			return GUIRequest{}, nil, device.ErrUnavailable
		}
		issued = &value
	} else if !errors.Is(err, sql.ErrNoRows) {
		return GUIRequest{}, nil, device.ErrUnavailable
	}
	if tx.Commit() != nil {
		return GUIRequest{}, nil, device.ErrUnavailable
	}
	return request, issued, nil
}
