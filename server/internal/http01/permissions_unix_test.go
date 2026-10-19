//go:build !windows

package http01

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

func TestRestrictiveIssuerUmaskPreservesPublicReadOnlyAccess(t *testing.T) {
	previous := unix.Umask(0077)
	defer unix.Umask(previous)
	p, value, _ := fixture(t)
	if err := p.Publish(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	path, _ := p.publicPath(value, false)
	for file, want := range map[string]os.FileMode{p.public: 0755, p.state: 0700, path: 0644} {
		info, err := os.Stat(file)
		if err != nil || info.Mode().Perm() != want {
			t.Fatal("issuer umask broke intended access")
		}
	}
}
