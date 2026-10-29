package setup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"slices"
	"strings"

	"github.com/KazuhaHub/nethub/server/internal/relaytoken"
)

// relayTokenManifest plans only the two token digests and successor backup.
// It performs no filesystem writes and does not prove custody or durability.
// The protected host adapter must independently verify all original files,
// retain the candidate, and verify a complete independent successor copy before
// publishing this manifest. A syntactically valid candidate is not entropy proof.
func relayTokenManifest(directory, successor string, before Manifest, previous, candidate []byte) (Manifest, error) {
	var empty Manifest
	validPath := func(path string) bool {
		return filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.Dir(path) != path
	}
	if before.Version != 3 || before.ConfirmedAt == nil || before.ConfirmedAt.IsZero() ||
		!validPath(directory) || !validPath(before.BackupDirectory) || !validPath(successor) ||
		!tokenPathsDisjoint(directory, before.BackupDirectory) || !tokenPathsDisjoint(directory, successor) ||
		!tokenPathsDisjoint(before.BackupDirectory, successor) || validateIdentity(before.Config) != nil {
		return empty, relaytoken.ErrTransition
	}
	validToken := func(raw []byte) bool {
		return len(raw) == 65 && raw[64] == '\n' && relayTrustDigest.Match(raw[:64])
	}
	if !validToken(previous) || !validToken(candidate) || bytes.Equal(previous, candidate) {
		return empty, relaytoken.ErrTransition
	}
	hash := func(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
	oldDigest, newDigest := hash(previous), hash(candidate)
	expected := expectedOwners()
	if len(before.Files) != len(expected) {
		return empty, relaytoken.ErrTransition
	}
	after := before
	after.Files = slices.Clone(before.Files)
	after.Config.OIDCPrivateHosts = slices.Clone(before.Config.OIDCPrivateHosts)
	confirmed := *before.ConfirmedAt
	after.ConfirmedAt = &confirmed
	after.BackupDirectory = successor
	changed := 0
	for i, file := range before.Files {
		owner, ok := expected[file.Path]
		if !ok || file.UID != owner || !validSecretSize(file.Path, file.Size) || !relayTrustDigest.MatchString(file.SHA256) {
			return empty, relaytoken.ErrTransition
		}
		delete(expected, file.Path)
		if file.Path == "secrets/authz/frp_token" || file.Path == "secrets/frps/frp_token" {
			if file.UID != 65532 || file.Size != 65 || file.SHA256 != oldDigest {
				return empty, relaytoken.ErrTransition
			}
			after.Files[i].SHA256 = newDigest
			changed++
		}
	}
	if len(expected) != 0 || changed != 2 {
		return empty, relaytoken.ErrTransition
	}
	return after, nil
}

// Lexical separation is necessary but not sufficient: the concrete root adapter
// must also reject symlink, hardlink and mount aliases during protected reads.
func tokenPathsDisjoint(a, b string) bool {
	contains := func(parent, child string) bool {
		rel, err := filepath.Rel(parent, child)
		return err == nil && !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	return !contains(a, b) && !contains(b, a)
}
