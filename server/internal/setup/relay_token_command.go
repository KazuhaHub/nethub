package setup

import (
	"errors"

	"github.com/KazuhaHub/nethub/server/internal/relaytoken"
)

var ErrRelayTokenCommand = errors.New("shared relay token operation requires protected host recovery")

type RelayTokenCommandOptions struct {
	Action, Directory, Project, ComposeFile, SuccessorBackup, OperationID string
}

type RelayTokenOperationSummary struct {
	OperationID string `json:"operation_id"`
	Phase       string `json:"phase"`
}

type RelayTokenCommandResult struct {
	OperationID            string                       `json:"operation_id,omitempty"`
	Phase                  string                       `json:"phase,omitempty"`
	Verified               bool                         `json:"verified"`
	DeviceRotationRequired bool                         `json:"device_rotation_required,omitempty"`
	State                  *relaytoken.State            `json:"state,omitempty"`
	Operations             []RelayTokenOperationSummary `json:"operations,omitempty"`
}
