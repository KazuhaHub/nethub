package setup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaycert"
)

var relayRuntimeFiles = []string{"runtime/relay/relay-cert.pem", "runtime/relay/relay-key.pem", "runtime/trust/relay-ca.pem"}

func generateRelay(directory string, manifest *Manifest) error {
	material, err := relaycert.Create(manifest.Config.ConsoleHost, time.Now())
	if err != nil {
		return errors.New("relay certificate creation failed")
	}
	files := []struct {
		path string
		data []byte
		uid  int
	}{
		{"secrets/issuer/ca.pem", material.CA, 0},
		{"secrets/issuer/ca-key.pem", material.CAKey, 0},
		{"secrets/issuer/initial/relay-cert.pem", material.Certificate, 0},
		{"secrets/issuer/initial/relay-key.pem", material.Key, 0},
	}
	config, err := renderRelayConfig(directory, manifest.Config)
	if err != nil {
		return err
	}
	files = append(files, struct {
		path string
		data []byte
		uid  int
	}{"secrets/frps/frps.toml", config, 65532})
	for _, file := range files {
		if err := writePrivate(filepath.Join(directory, filepath.FromSlash(file.path)), file.data); err != nil {
			return errors.New("relay issuance state creation failed; partial bundle preserved")
		}
		digest := sha256.Sum256(file.data)
		manifest.Files = append(manifest.Files, SecretFile{Path: file.path, SHA256: hex.EncodeToString(digest[:]), UID: file.uid, Size: int64(len(file.data))})
	}
	for index, data := range [][]byte{material.Certificate, material.Key, material.CA} {
		if err := writePrivate(filepath.Join(directory, filepath.FromSlash(relayRuntimeFiles[index])), data); err != nil {
			return errors.New("relay runtime material creation failed; partial bundle preserved")
		}
	}
	return checkRelayFiles(directory, manifest.Config, false)
}

func renderRelayConfig(directory string, config Config) ([]byte, error) {
	credentials := []string{}
	for _, name := range []string{"frps_admin_user", "frps_admin_password"} {
		data, err := os.ReadFile(filepath.Join(directory, "secrets", "frps", name))
		if err != nil {
			return nil, errors.New("relay credentials unavailable")
		}
		value := strings.TrimSuffix(string(data), "\n")
		if len(value) != 64 {
			return nil, errors.New("invalid relay credential")
		}
		if _, err := hex.DecodeString(value); err != nil {
			return nil, errors.New("invalid relay credential")
		}
		credentials = append(credentials, value)
	}
	gateway, _, _, authz := edgeAddresses(config)
	source, err := templates.ReadFile("templates/frps.toml.tmpl")
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New("frps").Option("missingkey=error").Parse(string(source))
	if err != nil {
		return nil, errors.New("invalid relay template")
	}
	var output bytes.Buffer
	if err := tmpl.Execute(&output, map[string]string{"Domain": config.DeviceDomain, "Gateway": gateway,
		"User": credentials[0], "Password": credentials[1], "Hook": authz + ":9000"}); err != nil {
		return nil, errors.New("relay template rendering failed")
	}
	return bytes.ReplaceAll(output.Bytes(), []byte("\r\n"), []byte("\n")), nil
}

// Current leaves may change without rewriting the immutable authority backup.
func checkRelayFiles(directory string, config Config, confirmed bool) error {
	read := func(name string) ([]byte, error) {
		path := filepath.Join(directory, filepath.FromSlash(name))
		for parent := filepath.Dir(path); parent != filepath.Clean(directory); parent = filepath.Dir(parent) {
			info, err := os.Lstat(parent)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || filepath.Dir(parent) == parent ||
				runtime.GOOS != "windows" && info.Mode().Perm() != 0700 {
				return nil, errors.New("invalid relay material directory")
			}
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 32768 ||
			runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
			return nil, errors.New("invalid relay runtime file")
		}
		if confirmed && (ownerUID(path) != 65532 || ownerUID(filepath.Dir(path)) != 65532) {
			return nil, errors.New("invalid relay runtime ownership")
		}
		return os.ReadFile(path)
	}
	data := make([][]byte, 0, len(relayRuntimeFiles))
	for _, name := range relayRuntimeFiles {
		value, err := read(name)
		if err != nil {
			return err
		}
		data = append(data, value)
	}
	root, err := os.ReadFile(filepath.Join(directory, "secrets", "issuer", "ca.pem"))
	if err != nil || !bytes.Equal(root, data[2]) {
		return errors.New("relay runtime trust differs from backed-up authority")
	}
	if err := relaycert.Check(data[2], data[0], data[1], config.ConsoleHost, time.Now()); err != nil {
		return errors.New("invalid relay runtime certificate identity, key or validity")
	}
	return nil
}
