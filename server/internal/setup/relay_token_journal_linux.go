package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/KazuhaHub/nethub/server/internal/relaytoken"
	"golang.org/x/sys/unix"
)

// The host command must create and bind this operation directory under the
// shared lease. Reading never creates a missing directory or discovers a new
// request from live files. This journal contains only operation metadata.
type relayTokenJournal struct {
	directory string
	request   relaytoken.Request
}

func (j relayTokenJournal) valid() bool {
	if os.Geteuid() != 0 || !j.request.Valid() || !filepath.IsAbs(j.directory) || filepath.Clean(j.directory) != j.directory {
		return false
	}
	actual, err := filepath.EvalSymlinks(j.directory)
	info, statErr := os.Lstat(j.directory)
	return err == nil && actual == j.directory && statErr == nil && info.IsDir() &&
		info.Mode().Perm() == 0700 && ownerUID(j.directory) == 0
}

func (j relayTokenJournal) read(ctx context.Context, name string, value any) error {
	if ctx.Err() != nil || !j.valid() || name != "intent.json" && name != "state.json" {
		return relaytoken.ErrTransition
	}
	path := filepath.Join(j.directory, name)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return relaytoken.ErrMissing
	} else if err != nil {
		return relaytoken.ErrTransition
	}
	raw, err := authorityRead(path, 0, 32768)
	if err != nil || json.Unmarshal(raw, value) != nil || !bytes.Equal(raw, authorityJSON(value)) {
		return relaytoken.ErrTransition
	}
	return nil
}

func (j relayTokenJournal) ReadIntent(ctx context.Context) (relaytoken.Intent, error) {
	var intent relaytoken.Intent
	if err := j.read(ctx, "intent.json", &intent); err != nil {
		return intent, err
	}
	if !intent.Valid() || intent.Request != j.request {
		return relaytoken.Intent{}, relaytoken.ErrTransition
	}
	return intent, nil
}

func (j relayTokenJournal) ReadState(ctx context.Context) (relaytoken.State, error) {
	var state relaytoken.State
	if err := j.read(ctx, "state.json", &state); err != nil {
		return state, err
	}
	intent, err := j.ReadIntent(ctx)
	if err != nil || !state.Valid(intent) {
		return relaytoken.State{}, relaytoken.ErrTransition
	}
	return state, nil
}

func (j relayTokenJournal) create(ctx context.Context, name string, raw []byte) error {
	if ctx.Err() != nil || !j.valid() || name != "intent.json" && name != "state.json" || len(raw) > 32768 {
		return relaytoken.ErrTransition
	}
	file, err := os.CreateTemp(j.directory, ".relay-token-*")
	if err != nil {
		return relaytoken.ErrTransition
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil || ctx.Err() != nil || !j.valid() {
		return relaytoken.ErrTransition
	}
	path := filepath.Join(j.directory, name)
	err = unix.Renameat2(unix.AT_FDCWD, file.Name(), unix.AT_FDCWD, path, unix.RENAME_NOREPLACE)
	if err != nil && !errors.Is(err, unix.EEXIST) || authoritySyncDirectory(j.directory) != nil {
		return relaytoken.ErrTransition
	}
	saved, readErr := authorityRead(path, 0, 32768)
	if readErr != nil || !bytes.Equal(saved, raw) || authoritySyncMaterial(path, 0) != nil {
		return relaytoken.ErrTransition
	}
	return nil
}

func (j relayTokenJournal) WriteIntent(ctx context.Context, intent relaytoken.Intent) error {
	if ctx.Err() != nil || !j.valid() || !intent.Valid() || intent.Request != j.request {
		return relaytoken.ErrTransition
	}
	current, err := j.ReadIntent(ctx)
	if err == nil {
		if current != intent || authoritySyncMaterial(filepath.Join(j.directory, "intent.json"), 0) != nil {
			return relaytoken.ErrTransition
		}
		return nil
	}
	if !errors.Is(err, relaytoken.ErrMissing) {
		return relaytoken.ErrTransition
	}
	if _, stateErr := j.ReadState(ctx); !errors.Is(stateErr, relaytoken.ErrMissing) {
		return relaytoken.ErrTransition
	}
	return j.create(ctx, "intent.json", authorityJSON(intent))
}

func relayTokenPhase(phase string) int {
	for index, name := range []string{"prepared", "publishing", "published", "reloading", "verifying", "complete"} {
		if phase == name {
			return index
		}
	}
	return -1
}

func (j relayTokenJournal) WriteState(ctx context.Context, state relaytoken.State) error {
	if ctx.Err() != nil || !j.valid() {
		return relaytoken.ErrTransition
	}
	intent, err := j.ReadIntent(ctx)
	if err != nil || !state.Valid(intent) {
		return relaytoken.ErrTransition
	}
	current, err := j.ReadState(ctx)
	if errors.Is(err, relaytoken.ErrMissing) {
		if state.Phase != "prepared" {
			return relaytoken.ErrTransition
		}
		return j.create(ctx, "state.json", authorityJSON(state))
	}
	if err != nil {
		return relaytoken.ErrTransition
	}
	before, after := relayTokenPhase(current.Phase), relayTokenPhase(state.Phase)
	if after < before || after > before+1 || ctx.Err() != nil {
		return relaytoken.ErrTransition
	}
	if authorityReplace(filepath.Join(j.directory, "state.json"), 0, authorityJSON(state)) != nil {
		return relaytoken.ErrTransition
	}
	return nil
}
