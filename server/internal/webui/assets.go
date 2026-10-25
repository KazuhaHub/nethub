// Package webui serves the built console without directory listings or source files.
package webui

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var assets embed.FS

func Ready() bool { _, err := assets.ReadFile("dist/index.html"); return err == nil }

func Handler() http.Handler { root, _ := fs.Sub(assets, "dist"); return handler{root} }

type handler struct{ root fs.FS }

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", 405)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" || name == "users" {
		name = "index.html"
	}
	if !fs.ValidPath(name) || strings.Contains(name, "..") || strings.Contains(name, "\\") || strings.HasPrefix(name, ".") || strings.Contains(name, "/.") {
		http.NotFound(w, r)
		return
	}
	allowed := name == "index.html" || name == "third-party-licenses.txt" || strings.HasPrefix(name, "assets/") && (path.Ext(name) == ".js" || path.Ext(name) == ".css" || path.Ext(name) == ".woff2" || path.Ext(name) == ".svg")
	if !allowed {
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(h.root, name)
	if err != nil {
		if name == "index.html" {
			http.Error(w, "Console assets are not built", 503)
		} else {
			http.NotFound(w, r)
		}
		return
	}
	w.Header().Set("Content-Type", mime.TypeByExtension(path.Ext(name)))
	if strings.HasPrefix(name, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	if r.Method != "HEAD" {
		w.Write(data)
	}
}
