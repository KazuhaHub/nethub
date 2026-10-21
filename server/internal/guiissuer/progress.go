package guiissuer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/boundedjson"
	"github.com/KazuhaHub/nethub/server/internal/guiacme"
)

var ErrProgress = errors.New("certificate issuance checkpoint unavailable or mismatched")
var profilePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var proofTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)
var keyAuthorizationPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var publicationPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// Progress is private recovery data. Explicit encoding is required for storage;
// ordinary JSON and status encoding deliberately omit every field.
type Progress struct {
	Phase      string          `json:"-"`
	Order      *guiacme.Order  `json:"-"`
	Proof      *guiacme.HTTP01 `json:"-"`
	Generation string          `json:"-"`
	Retired    bool            `json:"-"`
}

type savedOrder struct {
	URI              string    `json:"uri"`
	Host             string    `json:"host"`
	Fingerprint      string    `json:"request_fingerprint"`
	Status           string    `json:"status"`
	Profile          string    `json:"profile"`
	AuthorizationURL string    `json:"authorization_url"`
	FinalizeURL      string    `json:"finalize_url"`
	CertificateURL   string    `json:"certificate_url"`
	Expires          time.Time `json:"expires"`
}
type savedProof struct {
	URI              string    `json:"uri"`
	Token            string    `json:"token"`
	KeyAuthorization string    `json:"key_authorization"`
	Status           string    `json:"status"`
	Expires          time.Time `json:"expires"`
	Generation       string    `json:"generation"`
	Retired          bool      `json:"retired"`
}
type savedCheckpoint struct {
	Version     int         `json:"version"`
	Host        string      `json:"host"`
	Fingerprint string      `json:"request_fingerprint"`
	Order       *savedOrder `json:"order"`
	Proof       *savedProof `json:"proof"`
}

func sameOrderIdentity(a, b guiacme.Order) bool {
	return a.URI == b.URI && a.Host == b.Host && a.RequestFingerprint == b.RequestFingerprint && a.Profile == b.Profile && a.AuthorizationURL == b.AuthorizationURL && a.FinalizeURL == b.FinalizeURL
}

func (p Progress) validate(work Snapshot, allows func(string) bool) error {
	if allows == nil || work.Host == "" || work.CSRFingerprint == "" {
		return ErrProgress
	}
	switch p.Phase {
	case "order_intent", "order_saved", "proof_saved", "proof_live", "validating", "finalizing":
	default:
		return ErrProgress
	}
	if p.Phase == "order_intent" {
		if p.Order != nil || p.Proof != nil || p.Generation != "" || p.Retired {
			return ErrProgress
		}
		return nil
	}
	if p.Order == nil {
		return ErrProgress
	}
	order := *p.Order
	if order.Host != work.Host || order.RequestFingerprint != work.CSRFingerprint || !allows(order.URI) || !allows(order.AuthorizationURL) || !allows(order.FinalizeURL) ||
		(order.Profile != "" && !profilePattern.MatchString(order.Profile)) {
		return ErrProgress
	}
	switch order.Status {
	case "pending", "ready", "processing":
		if order.Expires.IsZero() || order.CertificateURL != "" {
			return ErrProgress
		}
	case "valid":
		if !allows(order.CertificateURL) {
			return ErrProgress
		}
	default:
		return ErrProgress
	}
	if p.Phase == "finalizing" && order.Status == "pending" {
		return ErrProgress
	}
	if (p.Phase == "proof_saved" || p.Phase == "proof_live" || p.Phase == "validating") && order.Status != "pending" && order.Status != "ready" {
		return ErrProgress
	}
	if p.Proof == nil {
		if p.Generation != "" || p.Retired || p.Phase == "proof_saved" || p.Phase == "proof_live" || p.Phase == "validating" {
			return ErrProgress
		}
		return nil
	}
	proof := *p.Proof
	if proof.Complete || !sameOrderIdentity(proof.Order, order) || !allows(proof.URI) || !proofTokenPattern.MatchString(proof.Token) || proof.ExpiresAt.IsZero() ||
		!publicationPattern.MatchString(p.Generation) || proof.ExpiresAt.After(work.Lease.Deadline) {
		return ErrProgress
	}
	parts := strings.Split(proof.KeyAuthorization, ".")
	if len(parts) != 2 || parts[0] != proof.Token || !keyAuthorizationPattern.MatchString(parts[1]) {
		return ErrProgress
	}
	thumb, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(thumb) != 32 || base64.RawURLEncoding.EncodeToString(thumb) != parts[1] {
		return ErrProgress
	}
	if proof.Status != "pending" && proof.Status != "processing" && proof.Status != "valid" {
		return ErrProgress
	}
	if p.Phase == "order_saved" || p.Phase == "finalizing" && !p.Retired || p.Retired && p.Phase != "finalizing" {
		return ErrProgress
	}
	return nil
}

// EncodeProgress requires the same URL allowlist used by the protected account
// transport. Encoding proves neither current lease authority nor publication.
func EncodeProgress(p Progress, work Snapshot, allows func(string) bool) ([]byte, error) {
	if p.validate(work, allows) != nil {
		return nil, ErrProgress
	}
	value := savedCheckpoint{Version: 1, Host: work.Host, Fingerprint: work.CSRFingerprint}
	if p.Order != nil {
		o := p.Order
		value.Order = &savedOrder{URI: o.URI, Host: o.Host, Fingerprint: o.RequestFingerprint, Status: o.Status, Profile: o.Profile, AuthorizationURL: o.AuthorizationURL, FinalizeURL: o.FinalizeURL, CertificateURL: o.CertificateURL, Expires: o.Expires}
	}
	if p.Proof != nil {
		o := p.Proof
		value.Proof = &savedProof{URI: o.URI, Token: o.Token, KeyAuthorization: o.KeyAuthorization, Status: o.Status, Expires: o.ExpiresAt, Generation: p.Generation, Retired: p.Retired}
	}
	data, err := json.Marshal(value)
	if err != nil || len(data) > 32768 {
		return nil, ErrProgress
	}
	return data, nil
}

func exactProgressObject(data []byte, fields []string) (map[string]json.RawMessage, error) {
	object, err := boundedjson.Object(bytes.NewReader(data))
	if err != nil || len(object) != len(fields) {
		return nil, ErrProgress
	}
	for _, field := range fields {
		if _, ok := object[field]; !ok {
			return nil, ErrProgress
		}
	}
	for name, value := range object {
		if name != "order" && name != "proof" && name != "checkpoint" && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, ErrProgress
		}
	}
	return object, nil
}

// DecodeProgress retains expired proof metadata for exact cleanup/recovery.
// The caller must not accept/publish it without preparing a fresh live proof.
func DecodeProgress(data []byte, work Snapshot, allows func(string) bool) (Progress, error) {
	if len(data) > 32768 {
		return Progress{}, ErrProgress
	}
	frame, err := exactProgressObject(data, []string{"phase", "checkpoint"})
	if err != nil {
		return Progress{}, ErrProgress
	}
	var phase string
	if json.Unmarshal(frame["phase"], &phase) != nil {
		return Progress{}, ErrProgress
	}
	if phase == "new" && bytes.Equal(frame["checkpoint"], []byte("null")) {
		return Progress{Phase: "new"}, nil
	}
	object, err := exactProgressObject(frame["checkpoint"], []string{"version", "host", "request_fingerprint", "order", "proof"})
	if err != nil {
		return Progress{}, ErrProgress
	}
	if !bytes.Equal(object["order"], []byte("null")) {
		if _, err := exactProgressObject(object["order"], []string{"uri", "host", "request_fingerprint", "status", "profile", "authorization_url", "finalize_url", "certificate_url", "expires"}); err != nil {
			return Progress{}, ErrProgress
		}
	}
	if !bytes.Equal(object["proof"], []byte("null")) {
		if _, err := exactProgressObject(object["proof"], []string{"uri", "token", "key_authorization", "status", "expires", "generation", "retired"}); err != nil {
			return Progress{}, ErrProgress
		}
	}
	var saved savedCheckpoint
	decoder := json.NewDecoder(bytes.NewReader(frame["checkpoint"]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&saved) != nil || saved.Version != 1 || saved.Host != work.Host || saved.Fingerprint != work.CSRFingerprint {
		return Progress{}, ErrProgress
	}
	p := Progress{Phase: phase}
	if saved.Order != nil {
		o := saved.Order
		p.Order = &guiacme.Order{URI: o.URI, Host: o.Host, RequestFingerprint: o.Fingerprint, Status: o.Status, Profile: o.Profile, AuthorizationURL: o.AuthorizationURL, FinalizeURL: o.FinalizeURL, CertificateURL: o.CertificateURL, Expires: o.Expires}
	}
	if saved.Proof != nil {
		if p.Order == nil {
			return Progress{}, ErrProgress
		}
		o := saved.Proof
		p.Proof = &guiacme.HTTP01{Order: *p.Order, URI: o.URI, Token: o.Token, KeyAuthorization: o.KeyAuthorization, Status: o.Status, ExpiresAt: o.Expires}
		p.Generation = o.Generation
		p.Retired = o.Retired
	}
	if p.validate(work, allows) != nil {
		return Progress{}, ErrProgress
	}
	return p, nil
}
