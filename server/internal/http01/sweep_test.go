package http01

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSweepExpiresWithoutDatabaseOrAccountAndKeepsLiveProof(t *testing.T) {
	p, first, now := fixture(t)
	ctx := context.Background()
	second := first
	second.Host = "b1b2c3d4.routers.example.test"
	for _, v := range []Publication{first, second} {
		if err := p.Publish(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	*now = now.Add(16 * time.Minute)
	live := first
	live.Host = "c1b2c3d4.routers.example.test"
	live.ExpiresAt = now.Add(time.Minute)
	if err := p.Publish(ctx, live); err != nil {
		t.Fatal(err)
	}
	result, err := p.SweepExpired(ctx)
	if err != nil || result.Scanned != 3 || result.Retired != 2 || !result.CycleComplete {
		t.Fatal("independent cleanup mismatch", result, err)
	}
	for _, v := range []Publication{first, second} {
		path, _ := p.publicPath(v, false)
		if !missing(path) {
			t.Fatal("expired proof remained public")
		}
	}
	path, _ := p.publicPath(live, false)
	if missing(path) {
		t.Fatal("live proof deleted")
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), first.Host) || strings.Contains(string(encoded), first.Token) {
		t.Fatal("cleanup status exposed publication material")
	}
}

func TestSweepCursorSurvivesReopenAndBusyHostCannotStarveOthers(t *testing.T) {
	p, first, now := fixture(t)
	ctx := context.Background()
	second := first
	second.Host = "b1b2c3d4.routers.example.test"
	for _, v := range []Publication{first, second} {
		if err := p.Publish(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	*now = now.Add(16 * time.Minute)
	_, lease, err := p.lease(ctx, first.Host)
	if err != nil {
		t.Fatal(err)
	}
	result, err := p.sweepExpired(ctx, 1)
	if err != nil || result.Busy != 1 || result.CycleComplete {
		t.Fatal("busy prefix did not advance cursor", result, err)
	}
	config := Config{PublicDirectory: p.public, StateDirectory: p.state, DeviceDomain: p.domain, ExcludedHosts: []string{"console1.routers.example.test"}, Now: func() time.Time { return *now }}
	reopened, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	result, err = reopened.sweepExpired(ctx, 1)
	if err != nil || result.Retired != 1 || !result.CycleComplete {
		t.Fatal("restart starved later host", result, err)
	}
	release(lease)
	result, err = reopened.sweepExpired(ctx, 1)
	if err != nil || result.Retired != 1 {
		t.Fatal("next cycle did not revisit previously busy host", result, err)
	}
}

func TestSweepRefusesCorruptCursorAndDoesNotFollowUnknownLinks(t *testing.T) {
	p, value, now := fixture(t)
	ctx := context.Background()
	if err := p.Publish(ctx, value); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(16 * time.Minute)
	cursor := filepath.Join(p.state, "sweep.json")
	if os.WriteFile(cursor, []byte("corrupt"), 0600) != nil {
		t.Fatal("fixture cursor write")
	}
	if _, err := p.SweepExpired(ctx); !errors.Is(err, ErrState) {
		t.Fatal("corrupt cursor adopted")
	}
	path, _ := p.publicPath(value, false)
	if missing(path) {
		t.Fatal("untrusted cursor caused deletion")
	}
	if os.Remove(cursor) != nil {
		t.Fatal("fixture cursor remove")
	}
	if runtime.GOOS == "windows" {
		return
	}
	outside := t.TempDir()
	canary := filepath.Join(outside, "canary")
	if os.WriteFile(canary, []byte("untouched"), 0600) != nil {
		t.Fatal("fixture canary")
	}
	if os.Symlink(outside, filepath.Join(p.state, "b1b2c3d4.routers.example.test")) != nil {
		t.Fatal("fixture link")
	}
	result, err := p.SweepExpired(ctx)
	if err != ErrState || result.Errors != 1 || result.Retired != 1 {
		t.Fatal("unsafe entry blocked unrelated cleanup or was followed", result, err)
	}
	if body, err := os.ReadFile(canary); err != nil || string(body) != "untouched" {
		t.Fatal("unknown linked directory mutated")
	}
}

func TestSweepNamespaceLeaseAndCancellationDoNotMutateProof(t *testing.T) {
	p, value, now := fixture(t)
	if err := p.Publish(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(16 * time.Minute)
	file, err := os.OpenFile(filepath.Join(p.public, ".publisher-lease"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if lockFile(file) != nil {
		t.Fatal("fixture namespace lease")
	}
	if _, err := p.SweepExpired(context.Background()); err != ErrBusy {
		t.Fatal("concurrent sweep did not skip")
	}
	unlockFile(file)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.SweepExpired(ctx); err != ErrCancelled {
		t.Fatal("cancelled sweep started")
	}
	path, _ := p.publicPath(value, false)
	if missing(path) {
		t.Fatal("cancelled sweep deleted proof")
	}
}

func TestSweepDoesNotInitializeEmptyHostState(t *testing.T) {
	p, _, _ := fixture(t)
	directory := filepath.Join(p.state, "a1b2c3d4.routers.example.test")
	if os.Mkdir(directory, 0700) != nil {
		t.Fatal("fixture empty host")
	}
	result, err := p.SweepExpired(context.Background())
	if err != nil || result.Scanned != 1 || result.Retired != 0 {
		t.Fatal("empty host cleanup mismatch", err)
	}
	for _, name := range []string{"operations", "lease", "active.json"} {
		if !missing(filepath.Join(directory, name)) {
			t.Fatal("cleanup initialized missing host metadata")
		}
	}
}
