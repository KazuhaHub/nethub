// Package clientip resolves console client addresses through explicitly trusted proxies.
package clientip

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type Resolver struct{ trusted []netip.Prefix }

func New(trusted []netip.Prefix) (*Resolver, error) {
	copyOf := append([]netip.Prefix(nil), trusted...)
	for _, prefix := range copyOf {
		if !prefix.IsValid() || prefix.Addr().Is4In6() {
			return nil, errors.New("invalid trusted proxy prefix")
		}
	}
	return &Resolver{trusted: copyOf}, nil
}

func (r *Resolver) isTrusted(ip netip.Addr) bool {
	for _, prefix := range r.trusted {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// Resolve walks X-Forwarded-For from the socket peer towards the client, stopping
// at the first untrusted hop. Spoofed reports forwarding headers from an
// untrusted peer so the caller can emit a warning without logging header data.
func (r *Resolver) Resolve(request *http.Request) (ip netip.Addr, spoofed bool, err error) {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false, errors.New("invalid peer address")
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || peer.Zone() != "" {
		return netip.Addr{}, false, errors.New("invalid peer address")
	}
	peer = peer.Unmap()
	xff := strings.Join(request.Header.Values("X-Forwarded-For"), ",")
	if !r.isTrusted(peer) {
		return peer, len(request.Header.Values("X-Forwarded-For")) > 0 || len(request.Header.Values("Forwarded")) > 0 || len(request.Header.Values("X-Real-IP")) > 0, nil
	}
	if xff == "" {
		return peer, false, nil
	}
	if len(xff) > 4096 {
		return netip.Addr{}, false, errors.New("forwarding chain exceeds limit")
	}
	parts := strings.Split(xff, ",")
	if len(parts) > 32 {
		return netip.Addr{}, false, errors.New("forwarding chain exceeds limit")
	}
	addresses := make([]netip.Addr, len(parts))
	for i, part := range parts {
		addresses[i], err = netip.ParseAddr(strings.TrimSpace(part))
		if err != nil || addresses[i].Zone() != "" {
			return netip.Addr{}, false, errors.New("invalid forwarding chain")
		}
		addresses[i] = addresses[i].Unmap()
	}
	for i := len(addresses) - 1; i >= 0; i-- {
		peer = addresses[i]
		if !r.isTrusted(peer) {
			return peer, false, nil
		}
	}
	return peer, false, nil
}
