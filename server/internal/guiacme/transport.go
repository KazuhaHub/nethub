package guiacme

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxResponse = 128 << 10

type transport struct {
	base    *http.Transport
	origins map[string]bool
}

func endpoint(value string) (*url.URL, bool) {
	if len(value) == 0 || len(value) > 2048 || strings.ContainsAny(value, "\x00\r\n\\") {
		return nil, false
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Host != strings.ToLower(u.Host) || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" || u.RawPath != "" || strings.Contains(u.Host, "%") || u.String() != value {
		return nil, false
	}
	if strings.ContainsAny(u.Path, "\x00\r\n\\") {
		return nil, false
	}
	// Canonical origin comparison includes the explicit port. HTTPS :443 and an
	// omitted port are intentionally different configured origins.
	if port := u.Port(); port != "" {
		if _, err := net.LookupPort("tcp", port); err != nil {
			return nil, false
		}
	}
	if strings.HasSuffix(u.Host, ":") || strings.HasSuffix(u.Hostname(), ".") {
		return nil, false
	}
	return u, true
}

func newTransport(origins map[string]bool, roots *x509.CertPool) *transport {
	if roots != nil {
		roots = roots.Clone()
	}
	return &transport{origins: origins, base: &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 15 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout: 15 * time.Second, MaxIdleConns: 4, MaxConnsPerHost: 2,
		MaxResponseHeaderBytes: 64 << 10, DisableCompression: true,
	}}
}

func (t *transport) allowed(value string) bool {
	u, ok := endpoint(value)
	return ok && t.origins[u.Scheme+"://"+u.Host]
}

func (t *transport) client() *http.Client {
	return &http.Client{Transport: t, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRemote }}
}

func (t *transport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL == nil || !t.allowed(request.URL.String()) || request.Host != "" && request.Host != request.URL.Host || request.Method != http.MethodGet && request.Method != http.MethodHead && request.Method != http.MethodPost {
		return nil, ErrRemote
	}
	// Fully consume a bounded response inside the request deadline. JSON decoders
	// in the SDK need not otherwise read a malicious oversized trailing body.
	ctx, cancel := context.WithTimeout(request.Context(), 15*time.Second)
	defer cancel()
	response, err := t.base.RoundTrip(request.Clone(ctx))
	if err != nil {
		return nil, ErrRemote
	}
	defer response.Body.Close()
	if response.ContentLength > maxResponse || response.Header.Get("Content-Encoding") != "" || response.StatusCode >= 300 && response.StatusCode < 400 {
		return nil, ErrRemote
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil || ctx.Err() != nil || len(body) > maxResponse {
		return nil, ErrRemote
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}
