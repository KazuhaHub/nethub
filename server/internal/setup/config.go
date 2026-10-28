// Package setup prepares a private, service-separated deployment bundle.
package setup

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"github.com/KazuhaHub/nethub/server/internal/sso"
)

const BackupPhrase = "I HAVE VERIFIED THE NETHUB SECRET BACKUP"

type Config struct {
	ConsoleHost        string   `json:"console_host"`
	DeviceDomain       string   `json:"device_domain"`
	SourceDirectory    string   `json:"source_directory"`
	NetworkSubnet      string   `json:"network_subnet"`
	ProxyMode          string   `json:"proxy_mode,omitempty"`
	WebPort            uint16   `json:"web_port,omitempty"`
	DevicePort         uint16   `json:"device_port,omitempty"`
	AnomalyActionLimit int      `json:"anomaly_action_limit,omitempty"`
	OIDCPrivateHosts   []string `json:"oidc_private_hosts,omitempty"`
}

func sameConfig(a, b Config) bool { return reflect.DeepEqual(a, b) }

func (c Config) externalProxy() bool { return c.ProxyMode == "external" }

func (c Config) originPorts() (uint16, uint16) {
	w, d := c.WebPort, c.DevicePort
	if w == 0 {
		w = 18080
	}
	if d == 0 {
		d = 18081
	}
	return w, d
}

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func validateIdentity(config Config) error {
	if len(config.OIDCPrivateHosts) > 16 {
		return errors.New("at most 16 private OIDC authorities are allowed")
	}
	for _, host := range config.OIDCPrivateHosts {
		if _, err := sso.NormalizePrivateHost(host); err != nil {
			return errors.New("private OIDC authorities must be exact HTTPS host[:port] values")
		}
	}
	if config.AnomalyActionLimit < 0 || config.AnomalyActionLimit > 1024 {
		return errors.New("anomaly action limit must be 1-1024, or omitted for the default")
	}
	if config.ProxyMode != "" && config.ProxyMode != "bundled" && !config.externalProxy() {
		return errors.New("proxy mode must be bundled or external")
	}
	if !config.externalProxy() && (config.WebPort != 0 || config.DevicePort != 0) {
		return errors.New("origin ports require external proxy mode")
	}
	if config.externalProxy() {
		w, d := config.originPorts()
		if w == d {
			return errors.New("external proxy origin ports must differ")
		}
		for _, port := range []uint16{w, d} {
			if port < 1024 || port == 7000 || port == 7500 || port == 8443 || port == 9000 {
				return errors.New("external proxy origin port conflicts with a reserved service")
			}
		}
	}
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
	return nil
}

func Validate(config Config) error {
	if err := validateIdentity(config); err != nil {
		return err
	}
	if !filepath.IsAbs(config.SourceDirectory) {
		return errors.New("source directory must be absolute")
	}
	for _, path := range []string{"deploy/Dockerfile", "deploy/images/caddy/Dockerfile", "deploy/images/postgres/Dockerfile", "deploy/images/frps/Dockerfile", "deploy/images/backup/passwd", "deploy/images/backup/group"} {
		info, err := os.Stat(filepath.Join(config.SourceDirectory, filepath.FromSlash(path)))
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("source directory must contain all deployment build inputs")
		}
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
