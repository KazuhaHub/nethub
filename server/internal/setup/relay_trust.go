package setup

import (
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

var ErrRelayTrust = errors.New("protected relay trust operation unavailable")
var relayTrustGenerationID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

type RelayTrustOptions struct {
	Directory, Project, ComposeFile, Action, BundleFile, ExpectedGeneration string
	Initialize                                                              bool
}

type RelayTrustResult struct {
	State       string   `json:"state"`
	ServerName  string   `json:"server_name"`
	ID          string   `json:"generation_id,omitempty"`
	Number      int      `json:"generation,omitempty"`
	Fingerprint string   `json:"bundle_fingerprint,omitempty"`
	Roots       []string `json:"root_fingerprints,omitempty"`
	PublishedAt string   `json:"published_at,omitempty"`
}

func validRelayTrustOperation(o RelayTrustOptions) bool {
	if o.Action == "current" {
		return o.BundleFile == "" && o.ExpectedGeneration == "" && !o.Initialize
	}
	if o.Action != "publish" || o.BundleFile == "" || o.Initialize == (o.ExpectedGeneration != "") {
		return false
	}
	return o.Initialize || relayTrustGenerationID.MatchString(o.ExpectedGeneration) && o.ExpectedGeneration != "00000000-0000-0000-0000-000000000000"
}

// A public publication cannot retire the configured, independently backed-up
// issuer. Switching authority requires a separate protected migration first.
func relayTrustCandidate(public, authority []byte, now time.Time) (*relaytrust.Bundle, error) {
	bundle, err := relaytrust.Parse(string(public), now)
	if err != nil {
		return nil, ErrRelayTrust
	}
	active, err := relaytrust.Parse(string(authority), now)
	if err != nil || len(active.RootFingerprints()) != 1 {
		return nil, ErrRelayTrust
	}
	for _, root := range active.RootFingerprints() {
		if !slices.Contains(bundle.RootFingerprints(), root) {
			return nil, ErrRelayTrust
		}
	}
	return bundle, nil
}

func relayTrustSummary(g *relaytrust.Generation, name string) RelayTrustResult {
	if g == nil {
		return RelayTrustResult{State: "pending", ServerName: name}
	}
	return RelayTrustResult{State: "current", ServerName: g.ServerName, ID: g.ID, Number: g.Number,
		Fingerprint: g.Bundle().Fingerprint(), Roots: g.Bundle().RootFingerprints(), PublishedAt: g.PublishedAt.UTC().Format(time.RFC3339Nano)}
}
