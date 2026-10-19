// Package claim signs device identities; callers must also check database state.
package claim

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

const timestampLayout = "2006-01-02T15:04:05.000000Z"
const maxTokenBytes = 3116

var ErrInvalid = errors.New("invalid domain claim")
var ErrKeyring = errors.New("invalid claim signing configuration")

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var subdomainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var keyIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

type Keyring struct {
	active string
	keys   map[string][]byte
}

// New snapshots the key material so later caller mutation cannot alter signatures.
func New(active string, keys map[string][]byte) (*Keyring, error) {
	if !keyIDPattern.MatchString(active) || len(keys) < 1 || len(keys) > 8 {
		return nil, ErrKeyring
	}
	copyKeys := make(map[string][]byte, len(keys))
	for id, key := range keys {
		if !keyIDPattern.MatchString(id) || len(key) != 32 {
			return nil, ErrKeyring
		}
		copyKeys[id] = bytes.Clone(key)
	}
	if _, exists := copyKeys[active]; !exists {
		return nil, ErrKeyring
	}
	return &Keyring{active: active, keys: copyKeys}, nil
}

func validTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 1 && value.Year() <= 9999 && value.Nanosecond()%1000 == 0
}

// NextIssuedAt must be called while holding the device row lock, before saving.
func NextIssuedAt(now, previous time.Time) (time.Time, error) {
	now = now.UTC().Truncate(time.Microsecond)
	previous = previous.UTC()
	if !validTime(now) || (!previous.IsZero() && !validTime(previous)) {
		return time.Time{}, ErrInvalid
	}
	if !previous.IsZero() && !now.After(previous) {
		now = previous.Add(time.Microsecond)
	}
	if !validTime(now) {
		return time.Time{}, ErrInvalid
	}
	return now, nil
}

func validate(payload protocol.ClaimPayload) error {
	if !uuidPattern.MatchString(payload.DeviceID) || !uuidPattern.MatchString(payload.TenantID) ||
		!subdomainPattern.MatchString(payload.Subdomain) || !keyIDPattern.MatchString(payload.KeyID) {
		return ErrInvalid
	}
	issued, err := time.Parse(timestampLayout, payload.IssuedAt)
	if err != nil || !validTime(issued) || issued.Format(timestampLayout) != payload.IssuedAt {
		return ErrInvalid
	}
	return nil
}

func signature(key []byte, encodedPayload string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(encodedPayload))
	return mac.Sum(nil)
}

func (k *Keyring) Issue(deviceID, subdomain, tenantID string, issuedAt time.Time) (string, error) {
	issuedAt = issuedAt.UTC()
	if k == nil || !validTime(issuedAt) {
		return "", ErrInvalid
	}
	payload := protocol.ClaimPayload{DeviceID: deviceID, Subdomain: subdomain,
		TenantID: tenantID, IssuedAt: issuedAt.Format(timestampLayout), KeyID: k.active}
	if err := validate(payload); err != nil {
		return "", err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", ErrInvalid
	}
	encoded := base64.RawURLEncoding.EncodeToString(data)
	return encoded + "." + base64.RawURLEncoding.EncodeToString(signature(k.keys[k.active], encoded)), nil
}

func decodeCanonical(value string) ([]byte, error) {
	data, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(data) != value {
		return nil, ErrInvalid
	}
	return data, nil
}

// Verify proves the signature and canonical shape, not ownership or nonrevocation.
func (k *Keyring) Verify(token string) (protocol.ClaimPayload, error) {
	var payload protocol.ClaimPayload
	if k == nil || len(token) > maxTokenBytes {
		return payload, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 || len(parts[0]) < 1 || len(parts[0]) > 3072 || len(parts[1]) != 43 {
		return payload, ErrInvalid
	}
	data, err := decodeCanonical(parts[0])
	if err != nil {
		return payload, ErrInvalid
	}
	supplied, err := decodeCanonical(parts[1])
	if err != nil || len(supplied) != sha256.Size {
		return payload, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil {
		return protocol.ClaimPayload{}, ErrInvalid
	}
	key, exists := k.keys[payload.KeyID]
	if !exists || !hmac.Equal(signature(key, parts[0]), supplied) || validate(payload) != nil {
		return protocol.ClaimPayload{}, ErrInvalid
	}
	canonical, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(data, canonical) {
		return protocol.ClaimPayload{}, ErrInvalid
	}
	return payload, nil
}
