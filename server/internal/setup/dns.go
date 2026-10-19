package setup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
)

// CheckDNS compares unpredictable wildcard labels and the console hostname with
// an operator-supplied public relay address. It does not infer inbound reachability.
func CheckDNS(ctx context.Context, config Config, expected netip.Addr) error {
	if !expected.IsValid() || expected.Zone() != "" || !expected.IsGlobalUnicast() || expected.IsPrivate() || expected.IsLoopback() || expected.IsLinkLocalUnicast() {
		return errors.New("a valid public expected address is required")
	}
	lookup := func(host string) error {
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return errors.New("DNS resolution failed; configure the console and wildcard records")
		}
		for _, ip := range addresses {
			if ip.Unmap() == expected.Unmap() {
				return nil
			}
		}
		return errors.New("DNS does not include the expected relay address")
	}
	if err := lookup(config.ConsoleHost); err != nil {
		return err
	}
	for range 2 {
		raw := make([]byte, 12)
		if _, err := rand.Read(raw); err != nil {
			return errors.New("DNS probe randomness unavailable")
		}
		if err := lookup("probe-" + hex.EncodeToString(raw) + "." + config.DeviceDomain); err != nil {
			return err
		}
	}
	return nil
}
