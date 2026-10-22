package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/boundedjson"
	"github.com/KazuhaHub/nethub/server/internal/relayauthority"
	"golang.org/x/sys/unix"
)

type authorityCommandRecord struct {
	Version     int                           `json:"version"`
	Options     RelayAuthoritySnapshotOptions `json:"options"`
	Project     string                        `json:"project"`
	ComposeFile string                        `json:"compose_file"`
}

func authorityCommandPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.Dir(path) != path
}

func decodeAuthorityCommandOptions(raw []byte) (RelayAuthoritySnapshotOptions, error) {
	var o RelayAuthoritySnapshotOptions
	if _, err := boundedjson.Object(bytes.NewReader(raw)); err != nil {
		return o, ErrRelayAuthority
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&o) != nil || !o.Request.Valid() || !relayTrustDigest.MatchString(o.ServiceFingerprint) {
		return o, ErrRelayAuthority
	}
	for _, path := range []string{o.Directory, o.CandidateDirectory, o.CandidateBackup, o.CustodyFile, o.SuccessorBackup} {
		if !authorityCommandPath(path) {
			return o, ErrRelayAuthority
		}
	}
	return o, nil
}

func readAuthorityCommand(directory, operationID string) (authorityCommandRecord, error) {
	var record authorityCommandRecord
	if !authorityCommandPath(directory) || !authorityOperationID.MatchString(operationID) {
		return record, ErrRelayAuthority
	}
	path := filepath.Join(directory, "authority-commands", operationID+".json")
	raw, err := authorityRead(path, 0, 32768)
	if err != nil || json.Unmarshal(raw, &record) != nil || !bytes.Equal(raw, authorityJSON(record)) || record.Version != 1 ||
		record.Options.Directory != directory || record.Options.Request.ID != operationID || !projectName.MatchString(record.Project) {
		return record, ErrRelayAuthority
	}
	if _, err := decodeAuthorityCommandOptions(authorityJSON(record.Options)); err != nil ||
		record.ComposeFile != "" && !authorityCommandPath(record.ComposeFile) {
		return record, ErrRelayAuthority
	}
	return record, nil
}

// Retain the complete original input before any snapshot or database admission.
// Atomic no-replace publication preserves the first operation across races and
// partial initialization; a caller cannot replace it with a new live baseline.
func retainAuthorityCommand(record authorityCommandRecord) error {
	directory := filepath.Join(record.Options.Directory, "authority-commands")
	if authorityPrivateDirectory(directory) != nil {
		return ErrRelayAuthority
	}
	path := filepath.Join(directory, record.Options.Request.ID+".json")
	raw := authorityJSON(record)
	temporary, err := os.CreateTemp(directory, ".command-*")
	if err != nil {
		return ErrRelayAuthority
	}
	defer os.Remove(temporary.Name())
	if err = temporary.Chmod(0600); err == nil {
		_, err = temporary.Write(raw)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err != nil || closeErr != nil {
		return ErrRelayAuthority
	}
	err = unix.Renameat2(unix.AT_FDCWD, temporary.Name(), unix.AT_FDCWD, path, unix.RENAME_NOREPLACE)
	if err != nil && !errors.Is(err, unix.EEXIST) || authoritySyncDirectory(directory) != nil {
		return ErrRelayAuthority
	}
	saved, err := readAuthorityCommand(record.Options.Directory, record.Options.Request.ID)
	if err != nil || !bytes.Equal(authorityJSON(saved), raw) {
		return ErrRelayAuthority
	}
	return nil
}

func RunRelayAuthorityCommand(ctx context.Context, o RelayAuthorityCommandOptions) (RelayAuthorityCommandResult, error) {
	var result RelayAuthorityCommandResult
	if os.Geteuid() != 0 || ctx.Err() != nil || !authorityCommandPath(o.Directory) || !projectName.MatchString(o.Project) ||
		o.ComposeFile != "" && !authorityCommandPath(o.ComposeFile) {
		return result, ErrRelayAuthority
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if o.Action == "binding" {
		if o.OptionsFile != "" || o.OperationID != "" {
			return result, ErrRelayAuthority
		}
		service, err := BindRelayAuthorityService(ctx, o.Directory, o.Project, o.ComposeFile, "")
		if err != nil {
			return result, ErrRelayAuthority
		}
		result.ServiceFingerprint = service.Fingerprint()
		return result, nil
	}
	var record authorityCommandRecord
	if o.Action == "activate" {
		if o.OptionsFile == "" || o.OperationID != "" || !authorityCommandPath(o.OptionsFile) {
			return result, ErrRelayAuthority
		}
		raw, err := authorityRead(o.OptionsFile, 0, 32768)
		if err != nil {
			return result, ErrRelayAuthority
		}
		options, err := decodeAuthorityCommandOptions(raw)
		if err != nil || options.Directory != o.Directory {
			return result, ErrRelayAuthority
		}
		record = authorityCommandRecord{Version: 1, Options: options, Project: o.Project, ComposeFile: o.ComposeFile}
		if retainAuthorityCommand(record) != nil {
			return result, ErrRelayAuthority
		}
	} else {
		if o.Action != "resume" && o.Action != "abort" && o.Action != "cancel-preparation" || o.OptionsFile != "" {
			return result, ErrRelayAuthority
		}
		var err error
		record, err = readAuthorityCommand(o.Directory, o.OperationID)
		if err != nil || record.Project != o.Project || record.ComposeFile != o.ComposeFile {
			return result, ErrRelayAuthority
		}
	}
	var state relayauthority.TransitionState
	var err error
	switch o.Action {
	case "activate", "resume":
		state, err = RunBoundRelayAuthorityTransition(ctx, record.Options, record.Project, record.ComposeFile)
	case "abort":
		state, err = AbortBoundRelayAuthorityTransition(ctx, o.Directory, o.OperationID, record.Project, record.ComposeFile)
	case "cancel-preparation":
		state, err = CancelBoundRelayAuthorityPreparation(ctx, record.Options, record.Project, record.ComposeFile)
	}
	if err != nil {
		return result, ErrRelayAuthority
	}
	result.Transition = &state
	return result, nil
}
