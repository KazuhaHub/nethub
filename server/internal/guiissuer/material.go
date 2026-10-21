package guiissuer

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guicert"
)

var ErrMaterial = errors.New("issued certificate material unavailable or mismatched")

// Material is independently verified public installation data, not an applied
// generation. Persistence/delivery still require a fresh live assignment lease.
type Material struct {
	PEM                                         []byte    `json:"-"`
	Fingerprint                                 string    `json:"-"`
	NotBefore, NotAfter, ValidUntil, RenewAfter time.Time `json:"-"`
}

// PrepareMaterial checks configured root trust and the original bound request.
// Renewals use actual lifetime and a stable device bucket, with a minimum interval
// after issuance so a short-lived certificate cannot trigger a tight renew loop.
func PrepareMaterial(work Snapshot, progress Progress, encoded []byte, roots *x509.CertPool, allows func(string) bool, now time.Time) (Material, error) {
	if now.IsZero() || roots == nil || progress.Phase != "finalizing" || progress.Order == nil || progress.Order.Status != "valid" || progress.validate(work, allows) != nil {
		return Material{}, ErrMaterial
	}
	request, err := guicert.ValidateBoundCSR(work.CSR, work.Host, work.PublicKey)
	if err != nil || hex.EncodeToString(request.Fingerprint[:]) != work.CSRFingerprint {
		return Material{}, ErrMaterial
	}
	chain, err := guicert.ValidateChain(encoded, work.CSR, work.Host, roots.Clone(), now)
	if err != nil {
		return Material{}, ErrMaterial
	}
	renew, err := RenewalTime(work.Lease.DeviceID, chain.NotBefore, chain.ValidUntil, now)
	if err != nil {
		return Material{}, ErrMaterial
	}
	return Material{PEM: chain.PEM, Fingerprint: hex.EncodeToString(chain.Fingerprint[:]), NotBefore: chain.NotBefore, NotAfter: chain.NotAfter, ValidUntil: chain.ValidUntil, RenewAfter: renew}, nil
}

func RenewalTime(device string, notBefore, validUntil, issuedAt time.Time) (time.Time, error) {
	if !uuidPattern.MatchString(device) || issuedAt.Before(notBefore) || !validUntil.After(issuedAt) {
		return time.Time{}, ErrMaterial
	}
	lifetime := validUntil.Sub(notBefore)
	if lifetime <= 0 {
		return time.Time{}, ErrMaterial
	}
	lead := min(30*24*time.Hour, lifetime/3)
	spread := min(24*time.Hour, lead/4)
	digest := sha256.Sum256([]byte(device))
	jitter := time.Duration(binary.BigEndian.Uint64(digest[:8]) % uint64(spread+1))
	renew := validUntil.Add(-lead - jitter)
	earliest := issuedAt.Add(lifetime / 10)
	if renew.Before(earliest) {
		renew = earliest
	}
	if !renew.After(issuedAt) || !renew.Before(validUntil) {
		return time.Time{}, ErrMaterial
	}
	return renew, nil
}
