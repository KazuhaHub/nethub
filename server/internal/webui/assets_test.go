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
	}{{"/", 200}, {"/users", 200}, {"/users/unknown", 404}, {"/assets/app-abc.js", 200}, {"/.gitkeep", 404}, {"/assets/", 404}, {"/assets/app.js.map", 404}, {"/../index.html", 404}, {"/api/v1/console/login", 404}, {"/unknown", 404}} {
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
