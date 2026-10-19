package http01

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Publisher, Publication, *time.Time) {
	t.Helper()
	root := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	p, err := New(Config{PublicDirectory: filepath.Join(root, "public"), StateDirectory: filepath.Join(root, "private"), DeviceDomain: "routers.example.test", ExcludedHosts: []string{"console1.routers.example.test"}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("A", 43)
	value := Publication{Host: "a1b2c3d4.routers.example.test", Generation: strings.Repeat("a", 32), Token: token, KeyAuthorization: token + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ExpiresAt: now.Add(15 * time.Minute)}
	return p, value, &now
}

func TestPublicFileAndPrivateOperationLifecycle(t *testing.T) {
	p, value, _ := fixture(t)
	ctx := context.Background()
	if err := p.Publish(ctx, value); err != nil {
		t.Fatal(err)
	}
	path, err := p.publicPath(value, false)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != value.KeyAuthorization {
		t.Fatal("wrong public response")
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(ctx, value); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) {
		t.Fatal("idempotent publication replaced the public inode")
	}
	if err := p.Remove(ctx, value.Host, value.Generation); err != nil {
		t.Fatal(err)
	}
	if !missing(path) {
		t.Fatal("completed token remained public")
	}
	if err := p.Remove(ctx, value.Host, value.Generation); err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(ctx, value); !errors.Is(err, ErrRetired) {
		t.Fatal("retired generation resurrected")
	}
}

func TestStaleCleanupCannotDeleteAnotherGeneration(t *testing.T) {
	p, first, _ := fixture(t)
	ctx := context.Background()
	if err := p.Publish(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.Generation = strings.Repeat("b", 32)
	second.Token = strings.Repeat("B", 43)
	second.KeyAuthorization = second.Token + "." + strings.Split(first.KeyAuthorization, ".")[1]
	if err := p.Publish(ctx, second); !errors.Is(err, ErrBusy) {
		t.Fatal("two active host generations accepted")
	}
	if err := p.Remove(ctx, first.Host, first.Generation); err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := p.Remove(ctx, first.Host, first.Generation); err != nil {
		t.Fatal(err)
	}
	path, _ := p.publicPath(second, false)
	if samePublic(path, second.KeyAuthorization) != nil || missing(path) {
		t.Fatal("stale cleanup removed a replacement")
	}
}

func TestExpirationIsEnforcedByExplicitCleanup(t *testing.T) {
	p, value, now := fixture(t)
	ctx := context.Background()
	if err := p.Publish(ctx, value); err != nil {
		t.Fatal(err)
	}
	path, _ := p.publicPath(value, false)
	*now = value.ExpiresAt
	if missing(path) {
		t.Fatal("fixture does not establish static-file cleanup semantics")
	}
	if err := p.CleanupExpired(ctx, value.Host); err != nil || !missing(path) {
		t.Fatal("expired publication not cleaned")
	}
	newValue := value
	newValue.Generation = strings.Repeat("c", 32)
	newValue.ExpiresAt = now.Add(time.Minute)
	if err := p.Publish(ctx, newValue); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidPublicationNeverCreatesHostState(t *testing.T) {
	p, value, now := fixture(t)
	for _, mutate := range []func(*Publication){
		func(v *Publication) { v.Host = "console1.routers.example.test" }, func(v *Publication) { v.Host = "a1b2c3d4.attacker.test" }, func(v *Publication) { v.Host = "A1B2C3D4.routers.example.test" },
		func(v *Publication) { v.Token = "../outside" }, func(v *Publication) { v.Token = strings.Repeat("A", 21) }, func(v *Publication) { v.Token = strings.Repeat("A", 129) },
		func(v *Publication) { v.KeyAuthorization = "arbitrary content" }, func(v *Publication) { v.KeyAuthorization = v.Token + "." + strings.Repeat("B", 43) },
		func(v *Publication) { v.Generation = "../outside" }, func(v *Publication) { v.ExpiresAt = *now }, func(v *Publication) { v.ExpiresAt = now.Add(time.Hour + time.Second) },
	} {
		input := value
		mutate(&input)
		if err := p.Publish(context.Background(), input); !errors.Is(err, ErrInput) {
			t.Fatal("invalid input accepted")
		}
	}
	entries, err := os.ReadDir(p.state)
	if err != nil || len(entries) != 1 || entries[0].Name() != "namespace.json" {
		t.Fatal("invalid publication created host state")
	}
}

func TestOperationInputAndNamespaceAreImmutable(t *testing.T) {
	p, value, _ := fixture(t)
	ctx := context.Background()
	if err := p.Publish(ctx, value); err != nil {
		t.Fatal(err)
	}
	changed := value
	changed.ExpiresAt = changed.ExpiresAt.Add(time.Minute)
	if err := p.Publish(ctx, changed); !errors.Is(err, ErrState) {
		t.Fatal("operation identity changed")
	}
	otherState := filepath.Join(filepath.Dir(p.state), "another-private")
	if _, err := New(Config{PublicDirectory: p.public, StateDirectory: otherState, DeviceDomain: p.domain}); !errors.Is(err, ErrState) {
		t.Fatal("another state root claimed the public namespace")
	}
	if _, err := New(Config{PublicDirectory: p.public, StateDirectory: p.state, DeviceDomain: "another.example.test"}); !errors.Is(err, ErrState) {
		t.Fatal("domain changed without a namespace migration")
	}
	otherPublic := filepath.Join(filepath.Dir(p.public), "another-public")
	if _, err := New(Config{PublicDirectory: otherPublic, StateDirectory: p.state, DeviceDomain: p.domain, ExcludedHosts: []string{"console1.routers.example.test"}}); !errors.Is(err, ErrState) {
		t.Fatal("another public root adopted live private state")
	}
	if _, err := New(Config{PublicDirectory: p.public, StateDirectory: p.state, DeviceDomain: p.domain, ExcludedHosts: []string{"console1.routers.example.test"}}); err != nil {
		t.Fatal("identical namespace could not be reopened")
	}
}

func TestInterruptedPublicationAndRemovalResume(t *testing.T) {
	for _, boundary := range []string{"intent", "active", "public", "removing", "removed"} {
		t.Run(boundary, func(t *testing.T) {
			p, value, _ := fixture(t)
			ctx := context.Background()
			dir, lease, err := p.lease(ctx, value.Host)
			if err != nil {
				t.Fatal(err)
			}
			op := operation{Version: 1, Phase: "publishing", Publication: value}
			if saveOperation(dir, op) != nil {
				t.Fatal("intent fixture")
			}
			if boundary != "intent" && writeCanonical(filepath.Join(dir, "active.json"), active{value.Generation}) != nil {
				t.Fatal("active fixture")
			}
			path, err := p.publicPath(value, true)
			if err != nil {
				t.Fatal(err)
			}
			if boundary == "public" || boundary == "removing" {
				if atomic(path, []byte(value.KeyAuthorization), 0644) != nil {
					t.Fatal("public fixture")
				}
			}
			if boundary == "removing" || boundary == "removed" {
				op.Phase = boundary
				if saveOperation(dir, op) != nil {
					t.Fatal("cleanup fixture")
				}
			}
			release(lease)
			if boundary == "removing" || boundary == "removed" {
				if err := p.CleanupExpired(ctx, value.Host); err != nil || !missing(path) {
					t.Fatal("interrupted cleanup did not finish")
				}
				if err := p.Publish(ctx, value); !errors.Is(err, ErrRetired) {
					t.Fatal("cleanup intent resurrected")
				}
			} else if err := p.Publish(ctx, value); err != nil || samePublic(path, value.KeyAuthorization) != nil || missing(path) {
				t.Fatal("interrupted publication did not resume")
			}
		})
	}
}

func TestHostLeaseAndCancelledOperation(t *testing.T) {
	p, value, _ := fixture(t)
	dir, lease, err := p.lease(context.Background(), value.Host)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(context.Background(), value); !errors.Is(err, ErrBusy) {
		t.Fatal("concurrent publication acquired host lease")
	}
	release(lease)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Publish(ctx, value); !errors.Is(err, ErrCancelled) || !missing(operationPath(dir, value.Generation)) {
		t.Fatal("cancelled publication persisted intent")
	}
}

func TestUnexpectedPublicContentIsNeverOverwrittenOrDeleted(t *testing.T) {
	p, value, _ := fixture(t)
	ctx := context.Background()
	if err := p.Publish(ctx, value); err != nil {
		t.Fatal(err)
	}
	path, _ := p.publicPath(value, false)
	if os.WriteFile(path, []byte("unexpected public file"), 0644) != nil {
		t.Fatal("content fixture")
	}
	if err := p.Remove(ctx, value.Host, value.Generation); !errors.Is(err, ErrState) {
		t.Fatal("unrecognized public content removed")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "unexpected public file" {
		t.Fatal("unrecognized data changed")
	}
}

func TestSymlinkHardlinkAndPermissionBoundaries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Linux filesystem access and link validation")
	}
	for _, kind := range []string{"symlink", "hardlink", "writable"} {
		t.Run(kind, func(t *testing.T) {
			p, value, _ := fixture(t)
			if err := p.Publish(context.Background(), value); err != nil {
				t.Fatal(err)
			}
			path, err := p.publicPath(value, true)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "untouched")
			if os.WriteFile(outside, []byte(value.KeyAuthorization), 0644) != nil {
				t.Fatal("link target")
			}
			switch kind {
			case "symlink":
				err = os.Symlink(outside, path)
			case "hardlink":
				err = os.Link(outside, path)
			case "writable":
				err = os.WriteFile(path, []byte(value.KeyAuthorization), 0666)
				if err == nil {
					err = os.Chmod(path, 0666)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Publish(context.Background(), value); !errors.Is(err, ErrState) {
				t.Fatal("unsafe public file accepted")
			}
			if err := p.Remove(context.Background(), value.Host, value.Generation); !errors.Is(err, ErrState) {
				t.Fatal("unsafe public file deleted")
			}
			data, _ := os.ReadFile(outside)
			if string(data) != value.KeyAuthorization {
				t.Fatal("outside file changed")
			}
		})
	}
}
