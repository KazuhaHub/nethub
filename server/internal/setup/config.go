// Package setup prepares a private, service-separated deployment bundle.
package setup

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const BackupPhrase = "I HAVE VERIFIED THE NETHUB SECRET BACKUP"

type Config struct {
	ConsoleHost     string `json:"console_host"`
	DeviceDomain    string `json:"device_domain"`
	SourceDirectory string `json:"source_directory"`
	NetworkSubnet   string `json:"network_subnet"`
}

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func Validate(config Config) error {
	for _, host := range []string{config.ConsoleHost, config.DeviceDomain} {
		if host != strings.ToLower(host) || len(host) > 240 || !strings.Contains(host, ".") {
			return errors.New("use lowercase DNS names without ports, paths, or wildcards")
		}
		for _, label := range strings.Split(host, ".") {
			if !dnsLabel.MatchString(label) {
				return errors.New("invalid deployment DNS name")
			}
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return errors.New("deployment DNS names cannot be IP addresses")
		}
	}
	if config.ConsoleHost == config.DeviceDomain || strings.HasSuffix(config.ConsoleHost, "."+config.DeviceDomain) {
		return errors.New("the console hostname must be outside the device wildcard domain")
	}
	prefix, err := netip.ParsePrefix(config.NetworkSubnet)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 24 || prefix.Masked() != prefix || !prefix.Addr().IsPrivate() {
		return errors.New("the private Compose network must be an aligned RFC1918 IPv4 /24")
	}
	if !filepath.IsAbs(config.SourceDirectory) {
		return errors.New("source directory must be absolute")
	}
	info, err := os.Stat(filepath.Join(config.SourceDirectory, "deploy", "Dockerfile"))
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("source directory must contain deploy/Dockerfile")
	}
	return nil
}

func resolvedNewDirectory(directory string) (string, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return "", errors.New("invalid output directory")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", errors.New("output parent directory must already exist")
	}
	target := filepath.Join(parent, filepath.Base(absolute))
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		return "", errors.New("output already exists; initialization never overwrites or rotates existing files")
	}
	return target, nil
}
