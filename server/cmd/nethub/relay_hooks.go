package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

type hookPeers []netip.Addr

func (p *hookPeers) String() string {
	values := make([]string, 0, len(*p))
	for _, address := range *p {
		values = append(values, address.String())
	}
	return strings.Join(values, ",")
}

func (p *hookPeers) Set(value string) error {
	address, err := netip.ParseAddr(value)
	normalized := address.Unmap()
	if err != nil || address.Zone() != "" || normalized.IsUnspecified() || normalized.IsMulticast() || len(*p) >= 16 {
		return errors.New("hook-peer requires an exact relay IP, with at most 16 peers")
	}
	*p = append(*p, normalized)
	return nil
}

func validHookListener(address string, peers hookPeers) bool {
	if address == "" {
		return len(peers) == 0
	}
	host, port, err := net.SplitHostPort(address)
	ip, parseError := netip.ParseAddr(host)
	_, portError := strconv.ParseUint(port, 10, 16)
	return err == nil && parseError == nil && ip.Zone() == "" && portError == nil &&
		(ip.Unmap().IsLoopback() || ip.Unmap().IsPrivate()) && len(peers) > 0
}

// Stop both listeners if either exits, including an unexpected clean close.
func serveAuthz(ctx context.Context, public *http.Server, publicListener net.Listener, hooks *http.Server, hookListener net.Listener) error {
	if hooks == nil {
		return serveHTTP(ctx, public, publicListener)
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- serveHTTP(child, public, publicListener) }()
	go func() { results <- serveHTTP(child, hooks, hookListener) }()
	first := <-results
	unexpected := ctx.Err() == nil
	cancel()
	second := <-results
	if first != nil {
		return first
	}
	if second != nil {
		return second
	}
	if unexpected {
		return errors.New("an authorization listener stopped unexpectedly")
	}
	return nil
}
