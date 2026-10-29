package setup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/hostlease"
	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/relayauthority"
	"github.com/KazuhaHub/nethub/server/internal/relayprobe"
	"github.com/KazuhaHub/nethub/server/internal/relaytoken"
)

func tokenCommandDirectory(directory string) bool {
	actual, err := filepath.EvalSymlinks(directory)
	info, statErr := os.Lstat(directory)
	return os.Geteuid() == 0 && filepath.IsAbs(directory) && filepath.Clean(directory) == directory &&
		err == nil && actual == directory && statErr == nil && info.IsDir() && info.Mode().Perm() == 0700 && ownerUID(directory) == 0
}

func readRelayTokenCommand(directory, id string) (relaytoken.Command, error) {
	var command relaytoken.Command
	if !tokenCommandDirectory(directory) || !protocol.ValidRotationOperationID(id) {
		return command, ErrRelayTokenCommand
	}
	path := filepath.Join(directory, "token-commands", id+".json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return command, relaytoken.ErrMissing
	} else if err != nil {
		return command, ErrRelayTokenCommand
	}
	raw, err := authorityRead(path, 0, 16384)
	if err != nil || json.Unmarshal(raw, &command) != nil || !bytes.Equal(raw, authorityJSON(command)) ||
		!command.Valid() || command.Directory != directory || command.Request.OperationID != id {
		return relaytoken.Command{}, ErrRelayTokenCommand
	}
	return command, nil
}

func retainRelayTokenCommand(ctx context.Context, command relaytoken.Command) error {
	if !command.Valid() || !tokenCommandDirectory(command.Directory) || ctx.Err() != nil {
		return ErrRelayTokenCommand
	}
	directory := filepath.Join(command.Directory, "token-commands")
	if authorityPrivateDirectory(directory) != nil ||
		tokenMaterialCopy(ctx, directory, command.Request.OperationID+".json", authorityJSON(command)) != nil {
		return ErrRelayTokenCommand
	}
	observed, err := readRelayTokenCommand(command.Directory, command.Request.OperationID)
	if err != nil || observed != command {
		return ErrRelayTokenCommand
	}
	return nil
}

func tokenCommandOptions(command relaytoken.Command) relayTokenMaterialOptions {
	return relayTokenMaterialOptions{Directory: command.Directory, SuccessorBackup: command.SuccessorBackup, Request: command.Request}
}

func inspectRelayTokenCommand(ctx context.Context, command relaytoken.Command) (RelayTokenCommandResult, error) {
	result := RelayTokenCommandResult{OperationID: command.Request.OperationID, Phase: "preparing"}
	directory := filepath.Join(command.Directory, "token-transitions", command.Request.OperationID)
	if _, err := os.Lstat(directory); os.IsNotExist(err) {
		return result, nil
	}
	journal := relayTokenJournal{directory: directory, request: command.Request}
	state, err := journal.ReadState(ctx)
	if errors.Is(err, relaytoken.ErrMissing) {
		return result, nil
	}
	if err != nil {
		result.Phase = "local_review"
		return result, ErrRelayTokenCommand
	}
	result.Phase, result.State = state.Phase, &state
	return result, nil
}

func inspectRelayTokenCommands(ctx context.Context, directory, id string) (RelayTokenCommandResult, error) {
	if id != "" {
		command, err := readRelayTokenCommand(directory, id)
		if err != nil {
			return RelayTokenCommandResult{}, ErrRelayTokenCommand
		}
		return inspectRelayTokenCommand(ctx, command)
	}
	result := RelayTokenCommandResult{Operations: []RelayTokenOperationSummary{}}
	root := filepath.Join(directory, "token-commands")
	if _, err := os.Lstat(root); os.IsNotExist(err) {
		return result, nil
	}
	if !tokenCommandDirectory(root) {
		return result, ErrRelayTokenCommand
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) > 4096 {
		return result, ErrRelayTokenCommand
	}
	for _, entry := range entries {
		id := entry.Name()
		if len(id) != 41 || filepath.Ext(id) != ".json" {
			return result, ErrRelayTokenCommand
		}
		command, err := readRelayTokenCommand(directory, id[:36])
		if err != nil {
			return result, ErrRelayTokenCommand
		}
		state, err := inspectRelayTokenCommand(ctx, command)
		result.Operations = append(result.Operations, RelayTokenOperationSummary{OperationID: id[:36], Phase: state.Phase})
		if err != nil {
			return result, ErrRelayTokenCommand
		}
	}
	return result, nil
}

func newRelayTokenOperationID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", ErrRelayTokenCommand
	}
	raw[6], raw[8] = (raw[6]&15)|64, (raw[8]&63)|128
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[:4], raw[4:6], raw[6:8], raw[8:10], raw[10:]), nil
}

func newRelayTokenCommand(ctx context.Context, options RelayTokenCommandOptions) (relaytoken.Command, error) {
	empty := relaytoken.Command{}
	if !projectName.MatchString(options.Project) || !authorityCommandPath(options.SuccessorBackup) ||
		options.ComposeFile != "" && !authorityCommandPath(options.ComposeFile) ||
		CheckFiles(options.Directory) != nil || relayauthority.CheckNoPendingTransition(options.Directory) != nil {
		return empty, ErrRelayTokenCommand
	}
	manifest, err := Load(options.Directory)
	if err != nil || !tokenPathsDisjoint(options.Directory, options.SuccessorBackup) ||
		!tokenPathsDisjoint(manifest.BackupDirectory, options.SuccessorBackup) {
		return empty, ErrRelayTokenCommand
	}
	service, err := BindRelayAuthorityService(ctx, options.Directory, options.Project, options.ComposeFile, "")
	if err != nil {
		return empty, ErrRelayTokenCommand
	}
	baseline, err := currentRelayTokenBaseline(ctx, options.Directory)
	if err != nil {
		return empty, ErrRelayTokenCommand
	}
	command := relaytoken.Command{Version: 1, Directory: options.Directory, Project: options.Project,
		ComposeFile: options.ComposeFile, SuccessorBackup: options.SuccessorBackup,
		Request:          relaytoken.Request{OperationID: options.OperationID, Binding: service.Fingerprint()},
		OriginalBaseline: baseline, CreatedAt: time.Now().UTC()}
	if !command.Valid() {
		return empty, ErrRelayTokenCommand
	}
	host := &relayTokenRuntimeHost{options: tokenCommandOptions(command), service: service, baseline: baseline}
	credential, err := host.probeCredential(ctx)
	ca, caErr := authorityRead(filepath.Join(command.Directory, "runtime/trust/relay-ca.pem"), 65532, 32768)
	leaf, leafErr := authorityRead(filepath.Join(command.Directory, "runtime/relay/relay-cert.pem"), 65532, 32768)
	token, tokenErr := authorityRead(filepath.Join(command.Directory, "secrets/authz/frp_token"), 65532, 65)
	if err != nil || caErr != nil || leafErr != nil || tokenErr != nil || len(token) != 65 || token[64] != '\n' {
		return empty, ErrRelayTokenCommand
	}
	observed, err := service.Observe(ctx, ca)
	if err != nil || observed != authorityLeaf(leaf) {
		return empty, ErrRelayTokenCommand
	}
	credential.Token = string(token[:64])
	accepted, err := relayprobe.LoginToken(ctx, "127.0.0.1:7000", service.binding.Config.ConsoleHost, ca, credential)
	if err != nil || !accepted || retainRelayTokenCommand(ctx, command) != nil {
		return empty, ErrRelayTokenCommand
	}
	return command, nil
}

// RunRelayTokenCommand retains original input and holds one shared host lease
// through durable preparation, publication, bound reload and actual verification.
// Resume never discovers a new baseline from mixed live files.
func RunRelayTokenCommand(ctx context.Context, options RelayTokenCommandOptions) (RelayTokenCommandResult, error) {
	result := RelayTokenCommandResult{}
	if !tokenCommandDirectory(options.Directory) || ctx.Err() != nil ||
		options.OperationID != "" && !protocol.ValidRotationOperationID(options.OperationID) {
		return result, ErrRelayTokenCommand
	}
	if options.Action == "inspect" && options.Project == "" && options.ComposeFile == "" && options.SuccessorBackup == "" {
		return inspectRelayTokenCommands(ctx, options.Directory, options.OperationID)
	}
	if options.Action != "rotate" && options.Action != "resume" ||
		options.Action == "resume" && (options.OperationID == "" || options.Project != "" || options.ComposeFile != "" || options.SuccessorBackup != "") {
		return result, ErrRelayTokenCommand
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	lease, err := hostlease.Acquire(filepath.Join(options.Directory, "relay-operation.lock"))
	if err != nil {
		if errors.Is(err, hostlease.ErrBusy) {
			return result, hostlease.ErrBusy
		}
		return result, ErrRelayTokenCommand
	}
	defer lease.Close()
	if options.OperationID == "" {
		options.OperationID, err = newRelayTokenOperationID()
		if err != nil {
			return result, ErrRelayTokenCommand
		}
	}
	result.OperationID, result.Phase = options.OperationID, "preparing"
	command, err := readRelayTokenCommand(options.Directory, options.OperationID)
	if errors.Is(err, relaytoken.ErrMissing) && options.Action == "rotate" {
		command, err = newRelayTokenCommand(bounded, options)
	} else if err == nil && options.Action == "rotate" &&
		(command.Project != options.Project || command.ComposeFile != options.ComposeFile || command.SuccessorBackup != options.SuccessorBackup) {
		return result, ErrRelayTokenCommand
	}
	if err != nil || relayauthority.CheckNoPendingAuthorityTransition(options.Directory) != nil ||
		relayauthority.CheckTokenRecoveryAdmission(options.Directory, command.Request) != nil {
		return result, ErrRelayTokenCommand
	}
	root := filepath.Join(options.Directory, "token-transitions")
	if authorityPrivateDirectory(root) != nil || authorityPrivateDirectory(filepath.Join(root, command.Request.OperationID)) != nil {
		return result, ErrRelayTokenCommand
	}
	service, err := BindRelayAuthorityService(bounded, command.Directory, command.Project, command.ComposeFile, command.Request.Binding)
	if err != nil {
		return result, ErrRelayTokenCommand
	}
	host := &relayTokenRuntimeHost{options: tokenCommandOptions(command), service: service, baseline: command.OriginalBaseline}
	journal := relayTokenJournal{directory: filepath.Join(root, command.Request.OperationID), request: command.Request}
	state, err := (relaytoken.Transition{Request: command.Request, Journal: journal, Host: host}).Run(bounded)
	if state.Version != 0 {
		result.State, result.Phase = &state, state.Phase
	}
	if err != nil || state.Phase != "complete" {
		return result, ErrRelayTokenCommand
	}
	result.Verified, result.DeviceRotationRequired = true, true
	return result, nil
}
