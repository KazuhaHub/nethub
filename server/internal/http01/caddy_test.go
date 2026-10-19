package http01

import (
	"strings"
	"testing"
)

func TestCaddyRouteContainsOnlyExplicitPublicHTTP(t *testing.T) {
	p, _, _ := fixture(t)
	text, err := p.CaddyHTTPRoute("/srv/nethub-http01")
	if err != nil || !strings.HasPrefix(text, ":80 {\n") || !strings.Contains(text, "{orig_uri}.matches(") || !strings.Contains(text, "console1.routers.example.test") || !strings.Contains(text, "root * \"/srv/nethub-http01\"") {
		t.Fatal("public route missing its scope")
	}
	for _, forbidden := range []string{"https://", "tls ", "reverse_proxy", "templates", "browse", "php_fastcgi", p.state} {
		if strings.Contains(text, forbidden) {
			t.Fatal("route expands serving or certificate ownership")
		}
	}
	for _, dir := range []string{"relative", "/srv/../private", "/srv\nrespond ok"} {
		if _, err := p.CaddyHTTPRoute(dir); err != ErrInput {
			t.Fatal("invalid serving directory accepted")
		}
	}
}
