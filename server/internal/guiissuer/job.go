// Package guiissuer defines fenced, independently validated private issuer work.
package guiissuer

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/netip"
	"regexp"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/boundedjson"
	"github.com/KazuhaHub/nethub/server/internal/guicert"
)

var ErrSnapshot = errors.New("certificate issuer work unavailable or mismatched")
var uuidPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var labelPattern = regexp.MustCompile(`^[a-z0-9]{8}$`)
var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// Lease and Snapshot are deliberately excluded from ordinary JSON/status logs.
// Neither a valid snapshot nor CSR is an authorization to use a stale lease.
type Lease struct {
	ID, TenantID, DeviceID, RequestID, Token string    `json:"-"`
	Version                                  int64     `json:"-"`
	Generation, Failures, Recoveries, Polls  int       `json:"-"`
	Expires, Deadline                        time.Time `json:"-"`
}
type Snapshot struct {
	Lease                           Lease  `json:"-"`
	Host, PublicKey, CSRFingerprint string `json:"-"`
	CSR                             []byte `json:"-"`
}

type databaseJob struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id"`
	DeviceID     string     `json:"device_id"`
	RequestID    string     `json:"request_id"`
	Generation   int        `json:"generation"`
	State        string     `json:"state"`
	Failures     int        `json:"failures"`
	Recoveries   int        `json:"recoveries"`
	Polls        int        `json:"polls"`
	Version      int64      `json:"version"`
	LeaseToken   *string    `json:"lease_token"`
	LeaseExpires *time.Time `json:"lease_expires_at"`
	NextAttempt  time.Time  `json:"next_attempt_at"`
	FailureCode  string     `json:"failure_code"`
	Created      time.Time  `json:"created_at"`
	Updated      time.Time  `json:"updated_at"`
	Deadline     time.Time  `json:"deadline"`
}
type databaseSnapshot struct {
	Job            databaseJob `json:"job"`
	Host           string      `json:"assigned_host"`
	Subdomain      string      `json:"subdomain"`
	PublicKey      string      `json:"public_key"`
	CSRHex         string      `json:"csr_der_hex"`
	CSRFingerprint string      `json:"csr_fingerprint"`
}

// DecodeSnapshot binds database work to the host's independently configured DNS
// suffix and exclusions. Call a fresh fenced database function before each CA
// mutation or delivery; decoding cannot extend a lease or prevent revocation.
func DecodeSnapshot(data []byte, domain string, excluded []string, now time.Time) (Snapshot, error) {
	if len(domain) > 244 || !domainPattern.MatchString(domain) || now.IsZero() || len(excluded) > 32 {
		return Snapshot{}, ErrSnapshot
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return Snapshot{}, ErrSnapshot
	}
	object, err := boundedjson.Object(bytes.NewReader(data))
	if err != nil || len(object) != 6 {
		return Snapshot{}, ErrSnapshot
	}
	for _, field := range []string{"job", "assigned_host", "subdomain", "public_key", "csr_der_hex", "csr_fingerprint"} {
		if _, ok := object[field]; !ok {
			return Snapshot{}, ErrSnapshot
		}
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(object["job"], &fields) != nil || len(fields) != 17 {
		return Snapshot{}, ErrSnapshot
	}
	for _, field := range []string{"id", "tenant_id", "device_id", "request_id", "generation", "state", "failures", "recoveries", "polls", "version", "lease_token", "lease_expires_at", "next_attempt_at", "failure_code", "created_at", "updated_at", "deadline"} {
		if _, ok := fields[field]; !ok {
			return Snapshot{}, ErrSnapshot
		}
	}
	var raw databaseSnapshot
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&raw) != nil {
		return Snapshot{}, ErrSnapshot
	}
	j := raw.Job
	for _, value := range []string{j.ID, j.TenantID, j.DeviceID, j.RequestID} {
		if !uuidPattern.MatchString(value) {
			return Snapshot{}, ErrSnapshot
		}
	}
	if j.State != "leased" || j.FailureCode != "none" || j.Generation < 1 || j.Version < 2 || j.Failures < 0 || j.Failures >= 5 || j.Recoveries < 0 || j.Recoveries > 3 || j.Polls < 0 || j.Polls >= 60 ||
		j.LeaseToken == nil || !uuidPattern.MatchString(*j.LeaseToken) || *j.LeaseToken == "00000000-0000-0000-0000-000000000000" ||
		j.LeaseExpires == nil || !j.LeaseExpires.After(now) || j.LeaseExpires.After(j.Deadline) ||
		j.LeaseExpires.After(now.Add(125*time.Second)) || !j.Deadline.After(now) ||
		j.Created.IsZero() || j.Created.After(now.Add(5*time.Second)) || j.Updated.Before(j.Created) || j.Updated.After(now.Add(5*time.Second)) ||
		j.NextAttempt.IsZero() || j.NextAttempt.After(now.Add(5*time.Second)) || !j.Deadline.After(j.Created) || j.Deadline.Sub(j.Created) > 2*time.Hour ||
		!labelPattern.MatchString(raw.Subdomain) || raw.Host != raw.Subdomain+"."+domain || len(raw.CSRHex) == 0 || len(raw.CSRHex) > 8192 {
		return Snapshot{}, ErrSnapshot
	}
	for _, host := range excluded {
		if len(host) > 253 || !domainPattern.MatchString(host) || raw.Host == host {
			return Snapshot{}, ErrSnapshot
		}
	}
	der, err := hex.DecodeString(raw.CSRHex)
	if err != nil || hex.EncodeToString(der) != raw.CSRHex {
		return Snapshot{}, ErrSnapshot
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	request, err := guicert.ValidateBoundCSR(csr, raw.Host, raw.PublicKey)
	if err != nil || hex.EncodeToString(request.Fingerprint[:]) != raw.CSRFingerprint {
		return Snapshot{}, ErrSnapshot
	}
	return Snapshot{Lease: Lease{ID: j.ID, TenantID: j.TenantID, DeviceID: j.DeviceID, RequestID: j.RequestID, Token: *j.LeaseToken, Version: j.Version, Generation: j.Generation,
		Failures: j.Failures, Recoveries: j.Recoveries, Polls: j.Polls, Expires: *j.LeaseExpires, Deadline: j.Deadline}, Host: raw.Host, PublicKey: raw.PublicKey, CSRFingerprint: raw.CSRFingerprint, CSR: csr}, nil
}
