package setup

import (
	"errors"
	"regexp"

	"github.com/KazuhaHub/nethub/server/internal/relayauthority"
)

var ErrRelayAuthority = errors.New("protected offline relay authority operation unavailable")
var relayTrustDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type RelayAuthorityOptions struct {
	Action, Directory, CandidateDirectory, BackupDirectory, ExpectedRoot, CustodyFile, Acknowledgement string
}

type RelayAuthorityResult struct {
	State                 string                  `json:"state"`
	Candidate             relayauthority.Metadata `json:"candidate"`
	BackupVerified        bool                    `json:"backup_verified"`
	CustodyAcknowledgedAt string                  `json:"custody_acknowledged_at,omitempty"`
}

func validRelayAuthorityOptions(o RelayAuthorityOptions) bool {
	if o.CandidateDirectory == "" {
		return false
	}
	if o.Action != "acknowledge-backup" && o.Action != "verify-custody" && (o.CustodyFile != "" || o.Acknowledgement != "") {
		return false
	}
	switch o.Action {
	case "prepare":
		return o.BackupDirectory == "" && len(o.ExpectedRoot) == 64 && relayTrustDigest.MatchString(o.ExpectedRoot)
	case "inspect":
		return o.BackupDirectory == "" && o.ExpectedRoot == ""
	case "backup", "verify-backup":
		return o.BackupDirectory != "" && o.ExpectedRoot == ""
	case "acknowledge-backup":
		return o.BackupDirectory != "" && o.ExpectedRoot == "" && o.CustodyFile != "" && o.Acknowledgement == relayauthority.CustodyPhrase
	case "verify-custody":
		return o.BackupDirectory != "" && o.ExpectedRoot == "" && o.CustodyFile != "" && o.Acknowledgement == ""
	}
	return false
}
