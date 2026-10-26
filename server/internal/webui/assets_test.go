package webui

import (
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func TestAssetPathsAndMissingBuild(t *testing.T) {
	h := handler{fstest.MapFS{"index.html": {Data: []byte("<html>console</html>")}, "assets/app-abc.js": {Data: []byte("export{}")}, ".gitkeep": {}, "assets/app.js.map": {Data: []byte("private source")}}}
	for _, test := range []struct {
		path   string
		status int
	}{{"/", 200}, {"/login", 200}, {"/providers", 200}, {"/login/unknown", 404}, {"/providers/unknown", 404}, {"/users", 200}, {"/invitations", 200}, {"/invite", 200}, {"/invitations/unknown", 404}, {"/invite/unknown", 404}, {"/users/unknown", 404}, {"/assets/app-abc.js", 200}, {"/.gitkeep", 404}, {"/assets/", 404}, {"/assets/app.js.map", 404}, {"/../index.html", 404}, {"/api/v1/console/login", 404}, {"/unknown", 404}} {
		r := httptest.NewRequest("GET", test.path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatalf("%s status=%d", test.path, w.Code)
		}
		if test.path == "/assets/app-abc.js" && w.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatal("hashed assets not cacheable")
		}
	}
	w := httptest.NewRecorder()
	handler{fstest.MapFS{}}.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 503 {
		t.Fatal("missing build returned success")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("HEAD", "/", nil))
	if w.Body.Len() != 0 || w.Code != 200 {
		t.Fatal("HEAD asset response incorrect")
	}
}

func TestSAMLProviderPageDoesNotExposeNestedFiles(t *testing.T) {
	h := handler{fstest.MapFS{"index.html": {Data: []byte("<html>console</html>")}}}
	for _, path := range []string{"/saml-providers", "/saml-providers/unknown"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		expected := 404
		if path == "/saml-providers" {
			expected = 200
		}
		if w.Code != expected {
			t.Fatal("SAML console route", path, w.Code)
		}
	}
}
