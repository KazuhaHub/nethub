package guicert

import (
	"errors"
	"time"
)

var ErrConflict = errors.New("device certificate request already bound")

// StoredRequest identifies retained public signed material, not an issuance grant.
type StoredRequest struct {
	ID, DeviceID, AssignedHost, PublicKey, Fingerprint string    `json:"-"`
	DER                                                []byte    `json:"-"`
	CreatedAt                                          time.Time `json:"-"`
}

type Assignment struct {
	Host, KeyFingerprint string `json:"-"`
}

// IssuedCertificate carries immutable public material, never issuer checkpoints
// or a successful native application acknowledgement.
type IssuedCertificate struct {
	ID, Fingerprint                             string    `json:"-"`
	Generation                                  int       `json:"-"`
	PEM                                         []byte    `json:"-"`
	NotBefore, NotAfter, ValidUntil, RenewAfter time.Time `json:"-"`
}
