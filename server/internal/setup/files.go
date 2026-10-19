package setup

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

//go:embed templates/*
var templates embed.FS

type SecretFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	UID    int    `json:"uid"`
}
type Manifest struct {
	Version         int          `json:"version"`
	Config          Config       `json:"config"`
	Files           []SecretFile `json:"files"`
	BackupDirectory string       `json:"backup_directory,omitempty"`
	ConfirmedAt     *time.Time   `json:"confirmed_at,omitempty"`
}

func writePrivate(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

// Generate creates an unconfirmed bundle. It never overwrites an existing path.
// A partially written bundle remains private for explicit operator inspection.
func Generate(directory string, config Config) (string, error) {
	if err := Validate(config); err != nil {
		return "", err
	}
	target, err := resolvedNewDirectory(directory)
	if err != nil {
		return "", err
	}
	if err = os.Mkdir(target, 0700); err != nil {
		return "", err
	}
	if err = writePrivate(filepath.Join(target, ".gitignore"), []byte("*\n")); err != nil {
		return target, err
	}
	manifest := Manifest{Version: 1, Config: config, Files: []SecretFile{}}
	type binding struct {
		path string
		uid  int
	}
	groups := [][]binding{}
	for _, role := range []string{"bootstrap", "nethub_owner", "nethub_web", "nethub_authz", "nethub_backup"} {
		files := []binding{{"secrets/postgres/pg_" + role, 999}}
		switch role {
		case "nethub_owner":
			files = append(files, binding{"secrets/migrate/pg_nethub_owner", 65532})
		case "nethub_web":
			files = append(files, binding{"secrets/web/pg_nethub_web", 65532})
		case "nethub_authz":
			files = append(files, binding{"secrets/authz/pg_nethub_authz", 65532})
		case "nethub_backup":
			files = append(files, binding{"secrets/backup/pg_nethub_backup", 65532})
		}
		groups = append(groups, files)
	}
	groups = append(groups, []binding{{"secrets/authz/claim_key", 65532}}, []binding{{"secrets/web/secrets_key", 65532}},
		[]binding{{"secrets/authz/frp_token", 65532}, {"secrets/frps/frp_token", 65532}},
		[]binding{{"secrets/authz/frps_admin_user", 65532}, {"secrets/frps/frps_admin_user", 65532}},
		[]binding{{"secrets/authz/frps_admin_password", 65532}, {"secrets/frps/frps_admin_password", 65532}})
	for _, group := range groups {
		raw := make([]byte, 32)
		if _, err = rand.Read(raw); err != nil {
			return target, errors.New("secret randomness unavailable")
		}
		data := []byte(hex.EncodeToString(raw) + "\n")
		digest := sha256.Sum256(data)
		for _, file := range group {
			if err = writePrivate(filepath.Join(target, filepath.FromSlash(file.path)), data); err != nil {
				return target, errors.New("secret file creation failed; existing partial bundle was preserved")
			}
			manifest.Files = append(manifest.Files, SecretFile{file.path, hex.EncodeToString(digest[:]), file.uid})
		}
	}
	for _, name := range []string{"docker-compose.yml", "Caddyfile", "00-nethub-roles.sh"} {
		data, err := templates.ReadFile("templates/" + name)
		if err != nil {
			return target, err
		}
		data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
		if err = writePrivate(filepath.Join(target, name), data); err != nil {
			return target, err
		}
		if err = os.Chmod(filepath.Join(target, name), 0644); err != nil {
			return target, err
		}
	}
	override, err := composeOverride(config)
	if err != nil {
		return target, err
	}
	if err = writePrivate(filepath.Join(target, "docker-compose.override.yml"), override); err != nil {
		return target, err
	}
	if err = saveManifest(target, manifest); err != nil {
		return target, err
	}
	return target, nil
}

func saveManifest(directory string, manifest Manifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	temporary := filepath.Join(directory, "setup.json.new")
	if err = writePrivate(temporary, append(data, '\n')); err != nil {
		return err
	}
	if err = os.Rename(temporary, filepath.Join(directory, "setup.json")); err != nil {
		return err
	}
	return nil
}

func Load(directory string) (Manifest, error) {
	var manifest Manifest
	info, err := os.Lstat(filepath.Join(directory, "setup.json"))
	if err != nil || !info.Mode().IsRegular() || info.Size() > 32768 {
		return manifest, errors.New("setup manifest is missing, linked, or oversized")
	}
	file, err := os.Open(filepath.Join(directory, "setup.json"))
	if err != nil {
		return manifest, errors.New("setup manifest is unavailable")
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 32768))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&manifest); err != nil || manifest.Version != 1 || len(manifest.Files) != 17 {
		return manifest, errors.New("invalid setup manifest")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return manifest, errors.New("invalid setup manifest trailer")
	}
	expected := expectedOwners()
	for _, file := range manifest.Files {
		uid, ok := expected[file.Path]
		if !ok || uid != file.UID {
			return manifest, errors.New("invalid secret owner/path binding")
		}
		delete(expected, file.Path)
	}
	if len(expected) != 0 {
		return manifest, errors.New("incomplete secret manifest")
	}
	return manifest, nil
}

func expectedOwners() map[string]int {
	owners := map[string]int{}
	for _, role := range []string{"bootstrap", "nethub_owner", "nethub_web", "nethub_authz", "nethub_backup"} {
		owners["secrets/postgres/pg_"+role] = 999
	}
	for service, file := range map[string]string{"migrate": "pg_nethub_owner", "web": "pg_nethub_web", "authz": "pg_nethub_authz", "backup": "pg_nethub_backup"} {
		owners["secrets/"+service+"/"+file] = 65532
	}
	for _, name := range []string{"secrets/authz/claim_key", "secrets/web/secrets_key", "secrets/authz/frp_token", "secrets/frps/frp_token", "secrets/authz/frps_admin_user", "secrets/frps/frps_admin_user", "secrets/authz/frps_admin_password", "secrets/frps/frps_admin_password"} {
		owners[name] = 65532
	}
	return owners
}

func verifyFiles(directory string, files []SecretFile) error {
	seen := map[string]bool{}
	for _, file := range files {
		if !strings.HasPrefix(file.Path, "secrets/") || strings.Contains(file.Path, "..") || strings.Contains(file.Path, "\\") || seen[file.Path] {
			return errors.New("invalid secret manifest path")
		}
		seen[file.Path] = true
		path := filepath.Join(directory, filepath.FromSlash(file.Path))
		for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
			info, err := os.Lstat(parent)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("secret parent is missing or linked")
			}
			if parent == filepath.Clean(directory) {
				break
			}
			if filepath.Dir(parent) == parent {
				return errors.New("secret path escaped bundle")
			}
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() != 65 {
			return errors.New("secret file is missing, linked, or has unexpected size")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
			return errors.New("secret file must have mode 0600")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return errors.New("secret file is unreadable")
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != file.SHA256 {
			return fmt.Errorf("secret checksum mismatch for %s", file.Path)
		}
	}
	return nil
}

// Backup creates a new private copy outside the deployment directory, then
// verifies every file. This proves local copy coverage, not off-host durability.
func Backup(directory, destination string) (string, error) {
	manifest, err := Load(directory)
	if err != nil {
		return "", err
	}
	if err = verifyFiles(directory, manifest.Files); err != nil {
		return "", err
	}
	target, err := resolvedNewDirectory(destination)
	if err != nil {
		return "", err
	}
	source, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(source, target)
	if err != nil || rel == "." || !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("backup must be outside the deployment directory")
	}
	if err = os.Mkdir(target, 0700); err != nil {
		return "", err
	}
	if err = writePrivate(filepath.Join(target, ".gitignore"), []byte("*\n")); err != nil {
		return "", err
	}
	for _, file := range manifest.Files {
		data, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(file.Path)))
		if err != nil {
			return "", err
		}
		if err = writePrivate(filepath.Join(target, filepath.FromSlash(file.Path)), data); err != nil {
			return "", err
		}
	}
	if err = saveManifest(target, manifest); err != nil {
		return "", err
	}
	return target, verifyFiles(target, manifest.Files)
}

func VerifyBackup(directory, backup string) error {
	source, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	destination, err := filepath.Abs(backup)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(source, destination)
	if err != nil || rel == "." || !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("backup must be outside deployment directory")
	}
	manifest, err := Load(directory)
	if err != nil {
		return err
	}
	return verifyFiles(destination, manifest.Files)
}
