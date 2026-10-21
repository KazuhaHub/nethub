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
