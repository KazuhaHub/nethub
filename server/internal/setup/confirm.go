package setup

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"
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

func CheckFiles(directory string) error {
	manifest, err := Load(directory)
	if err != nil {
		return err
	}
	if manifest.ConfirmedAt == nil || manifest.BackupDirectory == "" {
		return errors.New("secret backup has not been verified and acknowledged")
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
	return checkRelayFiles(directory, manifest.Config, true)
}
