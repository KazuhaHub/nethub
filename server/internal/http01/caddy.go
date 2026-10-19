package http01

import (
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// CaddyHTTPRoute adds an HTTP-only catch-all. Caddy's console-specific automatic
// redirects retain precedence; no GUI hostname is added to TLS automation.
// ServingDirectory is the public directory as mounted inside the proxy.
func (p *Publisher) CaddyHTTPRoute(servingDirectory string) (string, error) {
	if len(servingDirectory) > 4096 || !path.IsAbs(servingDirectory) || path.Clean(servingDirectory) != servingDirectory || strings.ContainsAny(servingDirectory, "\x00\r\n") {
		return "", ErrInput
	}
	hostPattern := "^[a-z0-9]{8}\\." + regexp.QuoteMeta(p.domain) + "$"
	uriPattern := `^/\.well-known/acme-challenge/[A-Za-z0-9_-]{22,128}$`
	expression := "{host}.matches(" + strconv.Quote(hostPattern) + ") && {orig_uri}.matches(" + strconv.Quote(uriPattern) + ")"
	var excluded []string
	for host := range p.excluded {
		excluded = append(excluded, host)
	}
	sort.Strings(excluded)
	for _, host := range excluded {
		expression += " && {host} != " + strconv.Quote(host)
	}
	return ":80 {\n" +
		"    @nethub_http01 {\n        method GET HEAD\n        expression `" + expression + "`\n    }\n" +
		"    handle @nethub_http01 {\n        root * " + strconv.Quote(servingDirectory) + "\n" +
		"        rewrite * /{host}{orig_uri}\n" +
		"        header Content-Type application/octet-stream\n" +
		"        header Cache-Control no-store\n" +
		"        header X-Content-Type-Options nosniff\n" +
		"        file_server {\n            disable_canonical_uris\n        }\n    }\n    respond 404\n}\n", nil
}
