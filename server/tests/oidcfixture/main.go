// oidcfixture prepares disposable Dex identities and HTTPS material for the
// deployed SSO tests. It is not linked into the product command.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const consoleOrigin = "https://console.example.com"

type credentials struct {
	Password string            `json:"password"`
	Clients  map[string]string `json:"clients"`
}

func main() {
	var err error
	switch {
	case len(os.Args) == 2:
		err = prepare(os.Args[1], time.Now())
	case len(os.Args) == 4 && os.Args[1] == "check-provider":
		err = checkProvider(os.Args[2], os.Args[3], os.Stdout)
	case len(os.Args) == 5 && (os.Args[1] == "probe-begin" || os.Args[1] == "probe-finish"):
		var port int
		port, err = strconv.Atoi(os.Args[3])
		if err == nil {
			err = probe(os.Args[1], os.Args[2], port, os.Args[4], os.Stdin, os.Stdout)
		}
	default:
		err = errors.New("invalid fixture arguments")
	}
	if err != nil {
		// Errors can contain private filesystem paths. Keep CLI diagnostics fixed.
		os.Stderr.WriteString("Disposable OIDC fixture preparation failed\n")
		os.Exit(1)
	}
}

func randomHex() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func prepare(directory string, now time.Time) error {
	if !filepath.IsAbs(directory) {
		return errors.New("absolute fixture directory required")
	}
	// Refuse existing targets rather than overwriting an earlier test's secrets.
	if err := os.Mkdir(directory, 0700); err != nil {
		return err
	}
	write := func(name string, value []byte, mode os.FileMode) error {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, value, mode); err != nil {
			return err
		}
		// The orchestrator's 077 umask must not make public trust unreadable to
		// Web's non-root UID. Secret modes remain 0600 inside the private directory.
		return os.Chmod(path, mode)
	}
	writeJSON := func(name string, value any) error {
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		return write(name, raw, 0600)
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial := func() (*big.Int, error) {
		return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	}
	rootSerial, err := serial()
	if err != nil {
		return err
	}
	rootTemplate := &x509.Certificate{SerialNumber: rootSerial, Subject: pkix.Name{CommonName: "NetHub disposable SSO test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	leafSerial, err := serial()
	if err != nil {
		return err
	}
	leaf := &x509.Certificate{SerialNumber: leafSerial, Subject: pkix.Name{CommonName: "NetHub disposable SSO origin"}, DNSNames: []string{"console.example.com", "dex-one.test", "dex-two.test", "saml.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	leafPKCS8, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return err
	}
	for _, file := range []struct {
		name, kind string
		value      []byte
		mode       os.FileMode
	}{{"root.crt", "CERTIFICATE", rootDER, 0644}, {"origin.crt", "CERTIFICATE", leafDER, 0644}, {"origin.key", "PRIVATE KEY", leafPKCS8, 0600}} {
		if err := write(file.name, pem.EncodeToMemory(&pem.Block{Type: file.kind, Bytes: file.value}), file.mode); err != nil {
			return err
		}
	}
	password, err := randomHex()
	if err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	secrets := credentials{Password: password, Clients: make(map[string]string)}
	for _, slug := range []string{"one", "two"} {
		secret, err := randomHex()
		if err != nil {
			return err
		}
		secrets.Clients[slug] = secret
		user := func(email, id string, verified bool) map[string]any {
			userID := slug + "-" + id
			if id == "alice" {
				userID = "shared-alice-subject"
			}
			return map[string]any{"email": email, "username": id, "userID": userID, "hash": string(hash), "emailVerified": verified}
		}
		users := []map[string]any{user("alice@example.com", "alice", true), user("cross@example.com", "cross", true)}
		if slug == "one" {
			users = append(users, user("unverified@example.com", "unverified", false), user("compose-admin@example.com", "mailbox-confusion", true))
		} else {
			users = append(users, user("bob@example.com", "bob", true))
		}
		config := map[string]any{
			"issuer":           "https://dex-" + slug + ".test",
			"storage":          map[string]any{"type": "sqlite3", "config": map[string]string{"file": "/tmp/dex.db"}},
			"web":              map[string]string{"http": "0.0.0.0:5556"},
			"logger":           map[string]string{"level": "error", "format": "json"},
			"oauth2":           map[string]any{"grantTypes": []string{"authorization_code"}, "responseTypes": []string{"code"}, "skipApprovalScreen": true, "pkce": map[string]any{"enforce": true, "codeChallengeMethodsSupported": []string{"S256"}}},
			"frontend":         map[string]string{"dir": "/srv/dex/web", "theme": "light"},
			"enablePasswordDB": true,
			"staticPasswords":  users,
			"staticClients": []map[string]any{
				{"id": "nethub-" + slug, "name": "NetHub disposable integration", "secret": secret, "redirectURIs": []string{consoleOrigin + "/api/v1/console/oidc/" + slug + "/callback"}},
				{"id": "claim-probe", "name": "Signed claim verification", "secret": secret, "redirectURIs": []string{consoleOrigin + "/claim-probe"}},
			},
		}
		if err := writeJSON("dex-"+slug+".json", config); err != nil {
			return err
		}
	}
	return writeJSON("credentials.json", secrets)
}
