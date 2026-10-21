package setup

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/KazuhaHub/nethub/server/internal/boundedjson"
	"github.com/KazuhaHub/nethub/server/internal/guiacme"
)

var ErrGUIIssuer = errors.New("GUI certificate host operation unavailable")
var ErrGUIIssuerBusy = errors.New("GUI certificate host operation already running")
var cleanupTimerName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,110}\.timer$`)

type GUIIssuerOptions struct{ Directory, Project, ConfigFile, ComposeFile string }
type GUIIssuerPolicy struct {
	Version              int      `json:"version"`
	AccountDirectory     string   `json:"account_directory"`
	DirectoryURL         string   `json:"directory_url"`
	ContactEmail         string   `json:"contact_email"`
	AdditionalOrigins    []string `json:"additional_origins"`
	APIRootsFile         string   `json:"api_roots_file"`
	CertificateRootsFile string   `json:"certificate_roots_file"`
	HTTPPolicyFile       string   `json:"http01_policy_file"`
	CleanupTimer         string   `json:"cleanup_timer"`
}

func decodeGUIIssuerPolicy(data []byte) (GUIIssuerPolicy, error) {
	var p GUIIssuerPolicy
	fields, err := boundedjson.Object(bytes.NewReader(data))
	if err != nil || len(fields) != 9 {
		return p, ErrGUIIssuer
	}
	for _, field := range []string{"version", "account_directory", "directory_url", "contact_email", "additional_origins", "api_roots_file", "certificate_roots_file", "http01_policy_file", "cleanup_timer"} {
		if _, ok := fields[field]; !ok {
			return p, ErrGUIIssuer
		}
	}
	if json.Unmarshal(data, &p) != nil || p.Version != 1 || p.AdditionalOrigins == nil || !cleanupTimerName.MatchString(p.CleanupTimer) {
		return GUIIssuerPolicy{}, ErrGUIIssuer
	}
	for _, path := range []string{p.AccountDirectory, p.HTTPPolicyFile, p.APIRootsFile, p.CertificateRootsFile} {
		if path != "" && (len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n")) {
			return GUIIssuerPolicy{}, ErrGUIIssuer
		}
	}
	if p.AccountDirectory == "" || p.HTTPPolicyFile == "" {
		return GUIIssuerPolicy{}, ErrGUIIssuer
	}
	if _, err := guiacme.NewAccountStore(p.AccountDirectory, guiacme.Config{DirectoryURL: p.DirectoryURL, ContactEmail: p.ContactEmail, AdditionalOrigins: p.AdditionalOrigins}); err != nil {
		return GUIIssuerPolicy{}, ErrGUIIssuer
	}
	return p, nil
}

func rootGUIFile(path string, limit int64, private bool) ([]byte, error) {
	if len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrGUIIssuer
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return nil, ErrGUIIssuer
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit || !guiRootFile(info) || private && info.Mode().Perm() != 0600 || !private && info.Mode().Perm()&0022 != 0 {
		return nil, ErrGUIIssuer
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || ownerUID(filepath.Dir(path)) != 0 || parent.Mode().Perm()&0022 != 0 {
		return nil, ErrGUIIssuer
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrGUIIssuer
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) {
		return nil, ErrGUIIssuer
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, ErrGUIIssuer
	}
	return data, nil
}

func guiTrustRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			return nil, ErrGUIIssuer
		}
		return roots, nil
	}
	data, err := rootGUIFile(path, 131072, false)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrGUIIssuer
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrGUIIssuer
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, ErrGUIIssuer
		}
		roots.AddCert(cert)
		count++
		if count > 128 {
			return nil, ErrGUIIssuer
		}
		data = rest
	}
	if count == 0 {
		return nil, ErrGUIIssuer
	}
	return roots, nil
}
