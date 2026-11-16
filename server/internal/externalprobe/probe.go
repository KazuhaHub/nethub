// Package externalprobe checks public TCP reachability through Check-Host.
package externalprobe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

const provider = "https://check-host.net"

var requestID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var nodeID = regexp.MustCompile(`^[a-z0-9-]{1,40}\.node\.check-host\.net$`)

type Port struct {
	Number uint16
	Nodes  int
}

// Check sends only the public IP and ports to the provider. Reports can be public.
// TCP success does not establish TLS, Login admission or application health.
func Check(ctx context.Context, address netip.Addr) ([]Port, error) {
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("external probe redirects refused")
		},
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	return check(ctx, address, client, time.Now, pause)
}

func pause(ctx context.Context) error {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func read(ctx context.Context, client *http.Client, path string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, provider+path, nil)
	if err != nil {
		return errors.New("invalid external probe request")
	}
	req.Header.Set("Accept", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return errors.New("external probe service unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("external probe service rejected the request")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(raw) == 0 || len(raw) > 65536 || !json.Valid(raw) {
		return errors.New("invalid external probe response")
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return errors.New("invalid external probe response")
	}
	return nil
}

func check(ctx context.Context, address netip.Addr, client *http.Client, now func() time.Time, wait func(context.Context) error) ([]Port, error) {
	if !address.IsValid() || address.Zone() != "" || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return nil, errors.New("external TCP checks require a public expected address")
	}
	address = address.Unmap()
	var result []Port
	for _, port := range []uint16{443, 7000, 8443} {
		if err := ctx.Err(); err != nil {
			return nil, errors.New("external TCP check deadline exceeded")
		}
		target := net.JoinHostPort(address.String(), strconv.Itoa(int(port)))
		started := now()
		var created struct {
			OK    int                          `json:"ok"`
			ID    string                       `json:"request_id"`
			Nodes map[string][]json.RawMessage `json:"nodes"`
		}
		query := url.Values{"host": {target}, "max_nodes": {"3"}}
		if err := read(ctx, client, "/check-tcp?"+query.Encode(), &created); err != nil {
			return nil, fmt.Errorf("TCP %d: %w", port, err)
		}
		if created.OK != 1 || !requestID.MatchString(created.ID) || len(created.Nodes) != 3 {
			return nil, fmt.Errorf("TCP %d: external service did not schedule three observers", port)
		}
		for name := range created.Nodes {
			if !nodeID.MatchString(name) {
				return nil, errors.New("unexpected external observer identity")
			}
		}
		for poll := 0; ; poll++ {
			if poll >= 30 {
				return nil, fmt.Errorf("TCP %d: external observers did not finish", port)
			}
			var observed struct {
				Command string                     `json:"command"`
				Created int64                      `json:"created"`
				Host    string                     `json:"host"`
				Port    string                     `json:"port"`
				Results map[string]json.RawMessage `json:"results"`
			}
			if err := read(ctx, client, "/check-result-extended/"+created.ID, &observed); err != nil {
				return nil, fmt.Errorf("TCP %d: %w", port, err)
			}
			if observed.Command != "tcp" || observed.Host != address.String() || observed.Port != strconv.Itoa(int(port)) || observed.Created < started.Unix()-10 || observed.Created > now().Unix()+10 || len(observed.Results) != len(created.Nodes) {
				return nil, fmt.Errorf("TCP %d: external report does not match this request", port)
			}
			pending := false
			for name, raw := range observed.Results {
				if _, ok := created.Nodes[name]; !ok {
					return nil, errors.New("external report changed observer identities")
				}
				if string(raw) == "null" {
					pending = true
					continue
				}
				var items []struct {
					Time    *float64 `json:"time"`
					Address string   `json:"address"`
					Error   string   `json:"error"`
				}
				if err := json.Unmarshal(raw, &items); err != nil || len(items) != 1 {
					return nil, errors.New("invalid external TCP observation")
				}
				item := items[0]
				peer, err := netip.ParseAddr(item.Address)
				if err != nil || peer.Zone() != "" || peer.Unmap() != address || item.Error != "" || item.Time == nil || math.IsNaN(*item.Time) || math.IsInf(*item.Time, 0) || *item.Time < 0 || *item.Time > 45 {
					return nil, fmt.Errorf("TCP %d: an external observer could not connect to the expected address", port)
				}
			}
			if !pending {
				if ctx.Err() != nil {
					return nil, errors.New("external TCP check deadline exceeded")
				}
				result = append(result, Port{Number: port, Nodes: len(created.Nodes)})
				break
			}
			if err := wait(ctx); err != nil {
				return nil, errors.New("external TCP check deadline exceeded")
			}
		}
	}
	return result, nil
}
