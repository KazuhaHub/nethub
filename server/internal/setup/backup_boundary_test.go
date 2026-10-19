package setup

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBackupCannotAliasSourceFiles(t *testing.T) {
	parent := t.TempDir()
	bundle, err := Generate(filepath.Join(parent, "deployment"), fixtureConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	backup, err := Backup(bundle, filepath.Join(parent, "backup"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := Load(bundle)
	if err != nil {
		t.Fatal(err)
	}
	file := manifest.Files[0].Path
	target := filepath.Join(backup, filepath.FromSlash(file))
	if os.Remove(target) != nil {
		t.Fatal("fixture removal")
	}
	if err := os.Link(filepath.Join(bundle, filepath.FromSlash(file)), target); err != nil {
		t.Skip("hardlink fixture unavailable")
	}
	if VerifyBackup(bundle, backup) == nil {
		t.Fatal("hardlinked backup accepted as an independent copy")
	}
	if runtime.GOOS == "windows" {
		return
	}
	inside := filepath.Join(bundle, "inside")
	if os.Mkdir(inside, 0700) != nil {
		t.Fatal("fixture directory")
	}
	for _, file := range manifest.Files {
		data, err := os.ReadFile(filepath.Join(bundle, filepath.FromSlash(file.Path)))
		if err != nil {
			t.Fatal(err)
		}
		if writePrivate(filepath.Join(inside, filepath.FromSlash(file.Path)), data) != nil {
			t.Fatal("fixture copy")
		}
	}
	alias := filepath.Join(parent, "alias")
	if os.Symlink(bundle, alias) != nil {
		t.Fatal("fixture symlink")
	}
	if VerifyBackup(bundle, filepath.Join(alias, "inside")) == nil {
		t.Fatal("backup inside deployment hidden through a parent alias")
	}
}

func TestMaintenanceIdentityDoesNotRequireBuildSource(t *testing.T) {
	config := fixtureConfig(t)
	config.SourceDirectory = filepath.Join(t.TempDir(), "removed-build-source")
	if validateIdentity(config) != nil || Validate(config) == nil {
		t.Fatal("runtime identity validation depends on build source or initialization accepts missing sources")
	}
}

func TestBackupCannotAliasAnotherSharedCredentialSource(t *testing.T) {
	parent := t.TempDir()
	bundle, err := Generate(filepath.Join(parent, "deployment"), fixtureConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	backup, err := Backup(bundle, filepath.Join(parent, "backup"))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(backup, "secrets/authz/frp_token")
	if os.Remove(target) != nil {
		t.Fatal("fixture replacement")
	}
	if err := os.Link(filepath.Join(bundle, "secrets/frps/frp_token"), target); err != nil {
		t.Skip("hardlink fixture unavailable")
	}
	if VerifyBackup(bundle, backup) == nil {
		t.Fatal("backup aliases a different source path with the same credential value")
	}
}
