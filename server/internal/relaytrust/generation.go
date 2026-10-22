package relaytrust

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/boundedjson"
)

var ErrGeneration = errors.New("relay trust generation unavailable or mismatched")
var generationID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var serverNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)

type Generation struct {
	ID          string    `json:"-"`
	Number      int       `json:"-"`
	ServerName  string    `json:"-"`
	PublishedAt time.Time `json:"-"`
	bundle      *Bundle
}

func (g *Generation) Bundle() *Bundle { return g.bundle }

// Valid checks a retained typed generation against independent relay identity
// and current time. Cached material cannot establish current database authority.
func (g *Generation) Valid(serverName string, now time.Time) bool {
	if g == nil || !validID(g.ID) || g.Number < 1 || g.Number > 2147483647 || !validServerName(strings.ToLower(serverName)) || g.ServerName != strings.ToLower(serverName) || now.IsZero() || g.PublishedAt.IsZero() || g.PublishedAt.After(now.Add(5*time.Second)) || g.bundle == nil || !g.bundle.ValidAt(now) {
		return false
	}
	start, end := g.bundle.Window()
	return !g.PublishedAt.Before(start) && g.PublishedAt.Before(end)
}

type generationRecord struct {
	ID          string    `json:"id"`
	Number      int       `json:"generation"`
	ServerName  string    `json:"server_name"`
	CAPEM       string    `json:"ca_pem"`
	Fingerprint string    `json:"bundle_fingerprint"`
	Roots       []string  `json:"root_fingerprints"`
	NotBefore   time.Time `json:"not_before"`
	ValidUntil  time.Time `json:"valid_until"`
	PublishedAt time.Time `json:"published_at"`
}

func validID(value string) bool {
	return generationID.MatchString(value) && value != "00000000-0000-0000-0000-000000000000"
}
func validServerName(value string) bool {
	return len(value) <= 253 && serverNamePattern.MatchString(value)
}

// DecodeGeneration rechecks database public material against independent host
// identity and current time. It is not evidence of device application or a relay
// process serving a certificate under this trust.
func DecodeGeneration(data []byte, serverName string, now time.Time) (*Generation, error) {
	fields, err := boundedjson.Object(bytes.NewReader(data))
	if err != nil || len(fields) != 9 || !validServerName(strings.ToLower(serverName)) || now.IsZero() {
		return nil, ErrGeneration
	}
	for _, name := range []string{"id", "generation", "server_name", "ca_pem", "bundle_fingerprint", "root_fingerprints", "not_before", "valid_until", "published_at"} {
		if _, ok := fields[name]; !ok {
			return nil, ErrGeneration
		}
	}
	var raw generationRecord
	if json.Unmarshal(data, &raw) != nil || !validID(raw.ID) || raw.Number < 1 || raw.Number > 2147483647 || raw.ServerName != strings.ToLower(serverName) || raw.PublishedAt.IsZero() || raw.PublishedAt.After(now.Add(5*time.Second)) {
		return nil, ErrGeneration
	}
	bundle, err := Parse(raw.CAPEM, now)
	if err != nil || bundle.PEM() != raw.CAPEM || bundle.Fingerprint() != raw.Fingerprint || !slices.Equal(bundle.RootFingerprints(), raw.Roots) {
		return nil, ErrGeneration
	}
	start, end := bundle.Window()
	if !start.Equal(raw.NotBefore) || !end.Equal(raw.ValidUntil) || raw.PublishedAt.Before(start) || !raw.PublishedAt.Before(end) {
		return nil, ErrGeneration
	}
	return &Generation{ID: raw.ID, Number: raw.Number, ServerName: raw.ServerName, PublishedAt: raw.PublishedAt, bundle: bundle}, nil
}
