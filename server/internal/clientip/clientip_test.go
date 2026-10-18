package clientip

import (
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestTrustedChainAndSpoofing(t *testing.T) {
	resolver, err := New([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/28"), netip.MustParsePrefix("2001:db8:1::/64")})
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		peer, xff, want string
		spoof, bad      bool
	}{
		"direct":                  {"192.0.2.100:1234", "", "192.0.2.100", false, false},
		"untrusted spoof":         {"192.0.2.100:1234", "192.0.2.200", "192.0.2.100", true, false},
		"proxy":                   {"192.0.2.1:1234", "192.0.2.100", "192.0.2.100", false, false},
		"stop before forged left": {"192.0.2.1:1234", "192.0.2.200, 192.0.2.100, 192.0.2.2", "192.0.2.100", false, false},
		"mapped IPv4 peer":        {"[::ffff:192.0.2.1]:1234", "::ffff:192.0.2.100", "192.0.2.100", false, false},
		"IPv6":                    {"[2001:db8:1::1]:1234", "2001:db8:2::1", "2001:db8:2::1", false, false},
		"missing chain":           {"192.0.2.1:1234", "", "192.0.2.1", false, false},
		"bad chain":               {"192.0.2.1:1234", "not-an-ip", "", false, true},
		"zone":                    {"192.0.2.1:1234", "fe80::1%eth0", "", false, true},
		"port in chain":           {"192.0.2.1:1234", "192.0.2.100:1234", "", false, true},
		"long chain":              {"192.0.2.1:1234", strings.Repeat("192.0.2.100,", 33) + "192.0.2.100", "", false, true},
		"bad peer":                {"hostname:1234", "", "", false, true},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "https://console.example.com/", nil)
			request.RemoteAddr = test.peer
			if test.xff != "" {
				request.Header.Set("X-Forwarded-For", test.xff)
			}
			got, spoof, err := resolver.Resolve(request)
			if (err != nil) != test.bad || !test.bad && (got.String() != test.want || spoof != test.spoof) {
				t.Fatalf("address=%s spoof=%v err=%v", got, spoof, err)
			}
		})
	}
	request := httptest.NewRequest("GET", "https://console.example.com/", nil)
	request.RemoteAddr = "192.0.2.100:443"
	request.Header.Set("Forwarded", "for=192.0.2.200")
	if got, spoof, err := resolver.Resolve(request); err != nil || !spoof || got.String() != "192.0.2.100" {
		t.Fatal("untrusted standard forwarding header was not reported")
	}
}
