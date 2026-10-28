package dbbackup

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStoragePreflightRefusesPublicAndAliasedInputs(t *testing.T) {
	config := syntheticConfig(t)
	if err := CheckStorage(config.Directory, config.RuntimeDirectory, config.PasswordFile); err != nil {
		t.Fatal(err)
	}
	if err := CheckStorage(config.Directory, config.Directory, config.PasswordFile); !errors.Is(err, ErrUnavailable) {
		t.Fatal("shared data and passfile directory accepted")
	}
	if err := os.Chmod(config.PasswordFile, 0644); err != nil {
		t.Fatal(err)
	}
	if err := CheckStorage(config.Directory, config.RuntimeDirectory, config.PasswordFile); !errors.Is(err, ErrUnavailable) {
		t.Fatal("public password file accepted")
	}
	if err := os.Chmod(config.PasswordFile, 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "archive-alias")
	if err := os.Symlink(config.Directory, alias); err != nil {
		t.Fatal(err)
	}
	if err := CheckStorage(alias, config.RuntimeDirectory, config.PasswordFile); !errors.Is(err, ErrUnavailable) {
		t.Fatal("symlink archive path accepted")
	}
	if err := os.Chmod(config.RuntimeDirectory, 0755); err != nil {
		t.Fatal(err)
	}
	if err := CheckStorage(config.Directory, config.RuntimeDirectory, config.PasswordFile); !errors.Is(err, ErrUnavailable) {
		t.Fatal("public runtime directory accepted")
	}
}
