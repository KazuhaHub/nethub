//go:build !windows

package guiacme

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAccountPrivateFilesystemBoundaries(t *testing.T) {
	for _, kind := range []string{"state-symlink", "state-hardlink", "lease-symlink", "lease-hardlink", "dangling-lease", "state-mode", "lease-mode", "directory-mode", "parent-alias"} {
		t.Run(kind, func(t *testing.T) {
			s, f, config := storeFixture(t)
			outside := filepath.Join(t.TempDir(), "outside")
			data := []byte("retain outside file")
			if kind == "state-symlink" || kind == "state-hardlink" {
				data, _ = os.ReadFile(s.path("account.json"))
			}
			if kind == "lease-hardlink" || kind == "lease-symlink" {
				data = nil
			}
			if kind != "dangling-lease" {
				if os.WriteFile(outside, data, 0600) != nil {
					t.Fatal("outside fixture")
				}
			}
			switch kind {
			case "state-symlink", "state-hardlink":
				if os.Remove(s.path("account.json")) != nil {
					t.Fatal("state fixture")
				}
				if kind == "state-symlink" {
					if os.Symlink(outside, s.path("account.json")) != nil {
						t.Fatal("link fixture")
					}
				} else if os.Link(outside, s.path("account.json")) != nil {
					t.Fatal("link fixture")
				}
			case "lease-symlink", "lease-hardlink", "dangling-lease":
				if os.Remove(s.path("account.lock")) != nil {
					t.Fatal("lease fixture")
				}
				if kind == "lease-hardlink" {
					if os.Link(outside, s.path("account.lock")) != nil {
						t.Fatal("link fixture")
					}
				} else if os.Symlink(outside, s.path("account.lock")) != nil {
					t.Fatal("link fixture")
				}
			case "state-mode":
				if os.Chmod(s.path("account.json"), 0644) != nil {
					t.Fatal("mode fixture")
				}
			case "lease-mode":
				if os.Chmod(s.path("account.lock"), 0644) != nil {
					t.Fatal("mode fixture")
				}
			case "directory-mode":
				if os.Chmod(s.directory, 0755) != nil {
					t.Fatal("mode fixture")
				}
			case "parent-alias":
				alias := filepath.Join(t.TempDir(), "alias")
				if os.Symlink(filepath.Dir(s.directory), alias) != nil {
					t.Fatal("alias fixture")
				}
				var err error
				s, err = NewAccountStore(filepath.Join(alias, "account"), config)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.EnsureAccount(context.Background(), true, f.terms); err != ErrState {
				t.Fatal("unsafe namespace accepted")
			}
			if s.Initialize(context.Background()) != ErrState {
				t.Fatal("unsafe namespace repaired silently")
			}
			if kind == "dangling-lease" {
				if _, err := os.Lstat(outside); !os.IsNotExist(err) {
					t.Fatal("dangling lease created an outside file")
				}
			} else if after, _ := os.ReadFile(outside); string(after) != string(data) {
				t.Fatal("outside target changed")
			}
			if f.counts().requests != 0 {
				t.Fatal("unsafe storage contacted CA")
			}
		})
	}
}

func TestAccountInitializationWithRestrictiveUmask(t *testing.T) {
	previous := unix.Umask(0077)
	defer unix.Umask(previous)
	s, _, _ := storeFixture(t)
	for path, mode := range map[string]os.FileMode{s.directory: 0700, s.path("account.json"): 0600, s.path("account.lock"): 0600} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != mode || !accountOwned(info) {
			t.Fatal("private ownership or mode changed under issuer umask")
		}
	}
}
