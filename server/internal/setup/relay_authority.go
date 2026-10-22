package setup

import (
	"errors"
	"github.com/KazuhaHub/nethub/server/internal/relayauthority"
	"regexp"
)

var ErrRelayAuthority = errors.New("protected offline relay authority operation unavailable")
var relayTrustDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type RelayAuthorityOptions struct {
	Action, Directory, CandidateDirectory, BackupDirectory, ExpectedRoot string
}

type RelayAuthorityResult struct {
	State          string                  `json:"state"`
	Candidate      relayauthority.Metadata `json:"candidate"`
	BackupVerified bool                    `json:"backup_verified"`
}

func validRelayAuthorityOptions(o RelayAuthorityOptions) bool {
	if o.CandidateDirectory == "" {
		return false
	}
	switch o.Action {
	case "prepare":
		return o.BackupDirectory == "" && len(o.ExpectedRoot) == 64 && relayTrustDigest.MatchString(o.ExpectedRoot)
	case "inspect":
		return o.BackupDirectory == "" && o.ExpectedRoot == ""
	case "backup", "verify-backup":
		return o.BackupDirectory != "" && o.ExpectedRoot == ""
	}
	return false
}
