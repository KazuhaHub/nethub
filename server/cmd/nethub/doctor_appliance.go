package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"
)

const applianceFeed = "https://kazuhahub.github.io/OPNsense-repo/"
const applianceFeedKeySHA256 = "92e83cb0267c3ef27cb355bc2f045c3449fd5c741d1030c7a90c879b00fa5e9b"

var appliancePackagePath = regexp.MustCompile(`^repo/FreeBSD:15:amd64/All/os-nethub-agent-([0-9]+\.[0-9]+\.[0-9]+)\.pkg$`)
var applianceFRPVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

func fetchApplianceFeedFile(ctx context.Context, client *http.Client, name string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, applianceFeed+name, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("package feed file is unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > limit {
		return nil, errors.New("package feed file is empty, unreadable or oversized")
	}
	return raw, nil
}

func checkPublishedAppliance(ctx context.Context, relayVersion string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	publicKey, err := fetchApplianceFeedFile(ctx, client, "kazuhahub.pub", 8192)
	if err != nil {
		return "", err
	}
	fingerprint := sha256.Sum256(publicKey)
	if hex.EncodeToString(fingerprint[:]) != applianceFeedKeySHA256 {
		return "", errors.New("package feed key fingerprint differs")
	}
	report, err := fetchApplianceFeedFile(ctx, client, "release.json", 1<<20)
	if err != nil {
		return "", err
	}
	signature, err := fetchApplianceFeedFile(ctx, client, "release.sig", 8192)
	if err != nil {
		return "", err
	}
	return verifyPublishedAppliance(publicKey, report, signature, relayVersion)
}

func verifyPublishedAppliance(publicKey, report, signature []byte, relayVersion string) (string, error) {
	block, rest := pem.Decode(publicKey)
	if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 {
		return "", errors.New("invalid package feed key format")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	digest := sha256.Sum256(report)
	if !ok || rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest[:], signature) != nil {
		return "", errors.New("package feed release signature did not verify")
	}
	var manifest struct {
		SchemaVersion int `json:"schema_version"`
		Packages      []struct {
			Name       string `json:"name"`
			ABI        string `json:"abi"`
			Path       string `json:"path"`
			SHA256     string `json:"sha256"`
			FRPVersion string `json:"frp_version"`
		} `json:"additional_packages"`
	}
	if err := json.Unmarshal(report, &manifest); err != nil || manifest.SchemaVersion != 2 {
		return "", errors.New("unsupported package feed release report")
	}
	var packageVersion string
	for _, entry := range manifest.Packages {
		if entry.Name != "os-nethub-agent" || entry.ABI != "FreeBSD:15:amd64" {
			continue
		}
		path := appliancePackagePath.FindStringSubmatch(entry.Path)
		checksum, err := hex.DecodeString(entry.SHA256)
		if packageVersion != "" || path == nil || err != nil || len(checksum) != sha256.Size ||
			!applianceFRPVersion.MatchString(entry.FRPVersion) {
			return "", errors.New("invalid or duplicate NetHub package version record")
		}
		if entry.FRPVersion != relayVersion {
			return "", errors.New("published appliance frp version differs from the running relay")
		}
		packageVersion = path[1]
	}
	if packageVersion == "" {
		return "", errors.New("no signed NetHub package version record")
	}
	return packageVersion, nil
}
