package setup

import (
	"github.com/KazuhaHub/nethub/server/internal/relayauthority"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

type RelayAuthoritySnapshotOptions struct {
	Directory          string                   `json:"deployment"`
	CandidateDirectory string                   `json:"candidate"`
	CandidateBackup    string                   `json:"candidate_backup"`
	CustodyFile        string                   `json:"custody_file"`
	SuccessorBackup    string                   `json:"successor_backup"`
	Request            relaytrust.SwitchRequest `json:"request"`
	ServiceFingerprint string                   `json:"service_fingerprint,omitempty"`
}

// RelayAuthorityCommandOptions requires explicit original input for activation.
// Later commands use only the retained operation, never mutable live discovery.
type RelayAuthorityCommandOptions struct {
	Action, Directory, Project, ComposeFile, OptionsFile, OperationID string
}

type RelayAuthorityCommandResult struct {
	ServiceFingerprint string                          `json:"service_fingerprint,omitempty"`
	Transition         *relayauthority.TransitionState `json:"transition,omitempty"`
}
