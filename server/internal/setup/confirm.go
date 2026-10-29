package setup

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relayauthority"
)

// Confirm requires a verified local backup and correct Linux container ownership.
// The backup copy remains operator-owned; runtime files get service-specific UIDs.
func Confirm(directory, backup, phrase string) error {
	if phrase != BackupPhrase {
		return errors.New("type the exact backup acknowledgement before continuing")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("finalize on the Linux Docker host as root to assign service-specific file owners")
	}
	manifest, err := Load(directory)
	if err != nil {
		return err
	}
	if manifest.ConfirmedAt != nil {
		return errors.New("deployment is already confirmed; initialization does not rotate credentials")
	}
	if err = verifyFiles(directory, manifest.Files); err != nil {
		return err
	}
	if err = VerifyBackup(directory, backup); err != nil {
		return errors.New("backup is incomplete or differs from the generated secrets")
	}
	if err = checkRelayFiles(directory, manifest.Config, false); err != nil {
		return err
	}
	for _, file := range manifest.Files {
		path := filepath.Join(directory, filepath.FromSlash(file.Path))
		if err = os.Chown(filepath.Dir(path), file.UID, file.UID); err != nil {
			return errors.New("cannot assign secret directory owner")
		}
		if err = os.Chown(path, file.UID, file.UID); err != nil {
			return errors.New("cannot assign secret file owner")
		}
	}
	for _, name := range relayRuntimeFiles {
		path := filepath.Join(directory, filepath.FromSlash(name))
		if os.Chown(filepath.Dir(path), 65532, 65532) != nil || os.Chown(path, 65532, 65532) != nil {
			return errors.New("cannot assign relay runtime owner")
		}
	}
	manifest.BackupDirectory, err = filepath.Abs(backup)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	manifest.ConfirmedAt = &now
	return saveManifest(directory, manifest)
}

// CheckAuthority verifies protected issuance state and its independent backup.
// It deliberately does not require an unexpired or complete runtime leaf pair,
// so maintenance can recover expiry or an interrupted pair replacement.
func CheckAuthority(directory string) error {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return errors.New("deployment directory is unavailable")
	}
	directory = absolute
	if err := relayauthority.CheckNoPendingTokenTransition(directory); err != nil {
		return errors.New("shared relay token operation requires recovery")
	}
	manifest, err := Load(directory)
	if err != nil {
		return err
	}
	if manifest.ConfirmedAt == nil || manifest.BackupDirectory == "" {
		return errors.New("secret backup has not been verified and acknowledged")
	}
	for path, mode := range map[string]os.FileMode{directory: 0700, filepath.Join(directory, "setup.json"): 0600, filepath.Join(directory, "secrets"): 0700} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode || ownerUID(path) != 0 {
			return errors.New("deployment authority requires protected root-owned paths")
		}
	}
	if err = verifyFiles(directory, manifest.Files); err != nil {
		return err
	}
	if err = VerifyBackup(directory, manifest.BackupDirectory); err != nil {
		return errors.New("secret backup is missing or incomplete")
	}
	for _, file := range manifest.Files {
		path := filepath.Join(directory, filepath.FromSlash(file.Path))
		if ownerUID(path) != file.UID || ownerUID(filepath.Dir(path)) != file.UID {
			return errors.New("service-specific secret ownership is incorrect")
		}
	}
	return nil
}

func CheckFiles(directory string) error {
	if err := CheckAuthority(directory); err != nil {
		return err
	}
	manifest, err := Load(directory)
	if err != nil {
		return err
	}
	return checkRelayFiles(directory, manifest.Config, true)
}
