//go:build linux

package setup

import "testing"

func TestPrivateAccountPathsCannotOverlapRuntimeNamespaces(t *testing.T) {
	for _, pair := range [][2]string{{"/srv/runtime", "/srv/runtime/account"}, {"/srv/runtime", "/srv/runtime"}, {"/srv/runtime/account", "/srv/runtime"}, {"/", "/var/lib/private"}} {
		if !pathsOverlap(pair[0], pair[1]) {
			t.Fatal("overlapping private/runtime namespace accepted")
		}
	}
	for _, pair := range [][2]string{{"/srv/runtime", "/srv/runtime-backup"}, {"/var/lib/http01", "/var/lib/gui-account"}} {
		if pathsOverlap(pair[0], pair[1]) {
			t.Fatal("independent private namespace refused")
		}
	}
}
