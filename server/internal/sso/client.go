package sso

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ErrOutbound deliberately omits provider URLs, DNS answers and response bodies.
var ErrOutbound = errors.New("SSO endpoint unavailable")

const maxSSOResponse = 1 << 20

// Outbound owns the HTTP transport used for discovery, exchange and signing keys.
// PrivateHosts contains exact host:port authorities, never suffixes or wildcards.
// A missing port means 443. Allowing an authority does not bypass TLS validation.
type Outbound struct {
	private map[string]bool
	base    *http.Transport
	lookup  func(context.Context, string, string) ([]netip.Addr, error)
	dial    func(context.Context, string, string) (net.Conn, error)
}

func NewOutbound(privateHosts []string) (*Outbound, error) {
	return newOutbound(privateHosts, nil)
}

func newOutbound(privateHosts []string, roots *x509.CertPool) (*Outbound, error) {
	if len(privateHosts) > 16 {
		return nil, ErrOutbound
	}
	o := &Outbound{private: make(map[string]bool), lookup: net.DefaultResolver.LookupNetIP,
		dial: (&net.Dialer{Timeout: time.Second, KeepAlive: 15 * time.Second}).DialContext}
	for _, value := range privateHosts {
		authority, err := privateAuthority(value)
		if err != nil {
			return nil, err
		}
		o.private[authority] = true
	}
	if roots != nil {
		roots = roots.Clone()
	}
	o.base = &http.Transport{
		Proxy: nil, DialContext: o.dialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		IdleConnTimeout: 15 * time.Second, MaxIdleConns: 16, MaxIdleConnsPerHost: 2,
		MaxConnsPerHost: 4, MaxResponseHeaderBytes: 64 << 10, DisableCompression: true,
	}
	return o, nil
}

func (o *Outbound) Client() *http.Client {
	return &http.Client{Transport: o, Timeout: 10 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 3 || len(via) == 0 || via[0].Method != http.MethodGet || r.Method != http.MethodGet {
			return ErrOutbound
		}
		_, err := outboundURL(r.URL)
		return err
	}}
}

func (o *Outbound) CloseIdleConnections() {
	if o != nil && o.base != nil {
		o.base.CloseIdleConnections()
	}
}

// ValidateEndpoint also checks advertised browser-only authorization endpoints.
// Dialing repeats resolution and validation; this preflight is not a DNS cache.
func (o *Outbound) ValidateEndpoint(ctx context.Context, value string) error {
	u, err := url.Parse(value)
	if err != nil {
		return ErrOutbound
	}
	authority, err := outboundURL(u)
	if err != nil {
		return err
	}
	_, err = o.addresses(ctx, authority)
	return err
}

func outboundURL(u *url.URL) (string, error) {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.RawFragment != "" || len(u.String()) > 4096 || strings.ContainsAny(u.String(), "\x00\r\n\\") {
		return "", ErrOutbound
	}
	return privateAuthority(u.Host)
}

// NormalizePrivateHost validates a deployment exception without doing DNS I/O.
func NormalizePrivateHost(value string) (string, error) { return privateAuthority(value) }

func privateAuthority(value string) (string, error) {
	if value == "" || len(value) > 320 || strings.ContainsAny(value, " /\\?#@%\t\r\n\x00") {
		return "", ErrOutbound
	}
	u, err := url.Parse("https://" + value)
	if err != nil || u.Host != value || u.Hostname() == "" || strings.HasSuffix(value, ":") {
		return "", ErrOutbound
	}
	host := strings.ToLower(u.Hostname())
	if strings.HasSuffix(host, ".") {
		return "", ErrOutbound
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" || strings.HasPrefix(value, "[") && !ip.Is6() {
			return "", ErrOutbound
		}
		host = ip.Unmap().String()
	} else {
		if len(host) > 253 || strings.ContainsAny(value, "[]") {
			return "", ErrOutbound
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", ErrOutbound
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return "", ErrOutbound
				}
			}
		}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return "", ErrOutbound
	}
	return net.JoinHostPort(host, port), nil
}

func (o *Outbound) addresses(ctx context.Context, authority string) ([]netip.Addr, error) {
	if o == nil {
		return nil, ErrOutbound
	}
	host, _, err := net.SplitHostPort(authority)
	if err != nil {
		return nil, ErrOutbound
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var addresses []netip.Addr
	if ip, e := netip.ParseAddr(host); e == nil {
		addresses = []netip.Addr{ip}
	} else {
		addresses, err = o.lookup(ctx, "ip", host)
	}
	if err != nil || ctx.Err() != nil || len(addresses) == 0 || len(addresses) > 16 {
		return nil, ErrOutbound
	}
	for i, ip := range addresses {
		ip = ip.Unmap()
		// Validate the whole answer before dialing any address. A mixed public/
		// private response cannot smuggle a fallback onto the internal network.
		if !ip.IsValid() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || !(ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) || !o.private[authority] && !publicSSOAddress(ip) {
			return nil, ErrOutbound
		}
		addresses[i] = ip
	}
	// Try IPv4 first so an unavailable IPv6 route does not consume the budget.
	slices.SortStableFunc(addresses, func(a, b netip.Addr) int {
		if a.Is4() == b.Is4() {
			return 0
		}
		if a.Is4() {
			return -1
		}
		return 1
	})
	return addresses, nil
}

func (o *Outbound) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, ErrOutbound
	}
	authority, err := privateAuthority(address)
	if err != nil {
		return nil, err
	}
	addresses, err := o.addresses(ctx, authority)
	if err != nil {
		return nil, err
	}
	_, port, _ := net.SplitHostPort(authority)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, ip := range addresses {
		attempt, done := context.WithTimeout(ctx, time.Second)
		// Dial a validated literal, never resolve the hostname a second time.
		conn, err := o.dial(attempt, "tcp", net.JoinHostPort(ip.String(), port))
		done()
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, ErrOutbound
}

func (o *Outbound) RoundTrip(request *http.Request) (*http.Response, error) {
	if o == nil || o.base == nil || request == nil || request.Method != http.MethodGet && request.Method != http.MethodPost {
		return nil, ErrOutbound
	}
	if _, err := outboundURL(request.URL); err != nil || request.Host != "" && request.Host != request.URL.Host {
		return nil, ErrOutbound
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	response, err := o.base.RoundTrip(request.Clone(ctx))
	if err != nil {
		return nil, ErrOutbound
	}
	defer response.Body.Close()
	if response.ContentLength > maxSSOResponse || response.Header.Get("Content-Encoding") != "" || request.Method == http.MethodPost && response.StatusCode >= 300 && response.StatusCode < 400 {
		return nil, ErrOutbound
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxSSOResponse+1))
	if err != nil || ctx.Err() != nil || len(body) > maxSSOResponse {
		return nil, ErrOutbound
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}

// Deny special-purpose ranges even when an individual exception is globally
// reachable. Explicit authority exceptions cover intentional internal IdPs.
// Sources: IANA IPv4/IPv6 special registries and Azure's 168.63.129.16 host VIP.
var ssoSpecialPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"), netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("168.63.129.16/32"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"), netip.MustParsePrefix("3fff::/20"),
}

func publicSSOAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Zone() != "" {
		return false
	}
	// Limit IPv6 to allocated global unicast, excluding translation/tunnel ranges.
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range ssoSpecialPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}
