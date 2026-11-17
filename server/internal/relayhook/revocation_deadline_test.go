package relayhook

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestExpiredSnapshotPreservesDenialsWithoutAdmittingUnknownPing(t *testing.T) {
	now := time.Now()
	var reads atomic.Int32
	cache := cacheFixture(t, revocationsFunc(func(context.Context) ([]RevokedDevice, error) {
		reads.Add(1)
		return []RevokedDevice{revokedFixture}, nil
	}))
	cache.now = func() time.Time { return now }
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	unknown := pingIdentity()
	unknown.DeviceID = "33333333-3333-4333-8333-333333333333"
	if err := cache.AuthorizePing(unknown); err != nil {
		t.Fatal("fresh snapshot refused an unrelated identity", err)
	}
	now = now.Add(cache.maxAge + time.Nanosecond)
	if !errors.Is(cache.AuthorizePing(unknown), ErrUnavailable) || cache.selfCheck() {
		t.Fatal("expired snapshot remained an admission authority")
	}
	if !errors.Is(cache.AuthorizePing(pingIdentity()), ErrDenied) || reads.Load() != 1 {
		t.Fatal("expiration lost a known denial or Ping queried SQL")
	}
	if err := cache.Refresh(context.Background()); err != nil || cache.AuthorizePing(unknown) != nil {
		t.Fatal("a new successful snapshot did not recover admission", err)
	}
	now = now.Add(-time.Second)
	if !errors.Is(cache.AuthorizePing(unknown), ErrUnavailable) {
		t.Fatal("a future-dated snapshot admitted a Ping")
	}
}

func TestSlowSnapshotCannotResetItsAgeAtPublication(t *testing.T) {
	now := time.Now()
	var slow bool
	cache := cacheFixture(t, revocationsFunc(func(context.Context) ([]RevokedDevice, error) {
		if slow {
			now = now.Add(3 * time.Second)
		}
		return nil, nil
	}))
	cache.now = func() time.Time { return now }
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	previous := cache.snapshot.Load()
	slow = true
	if !errors.Is(cache.Refresh(context.Background()), ErrUnavailable) || cache.snapshot.Load() != previous {
		t.Fatal("an already expired database read replaced the snapshot")
	}
	if !errors.Is(cache.AuthorizePing(pingIdentity()), ErrUnavailable) {
		t.Fatal("slow completion renewed the age of old authority")
	}
}

func TestDisconnectWorkCannotQueueRevocationPublication(t *testing.T) {
	var revoked atomic.Bool
	entered, exited := make(chan struct{}), make(chan struct{})
	var once sync.Once
	repository := disconnectFixture{revocationsFunc: func(context.Context) ([]RevokedDevice, error) {
		if revoked.Load() {
			return []RevokedDevice{revokedFixture}, nil
		}
		return nil, nil
	}, process: func(ctx context.Context, _ func(RevokedDevice) bool) error {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		select {
		case <-exited:
		default:
			close(exited)
		}
		return ctx.Err()
	}}
	cache := cacheFixture(t, repository)
	cache.interval = 5 * time.Millisecond
	cache.budget = 750 * time.Millisecond
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cache.Run(ctx) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("disconnect worker did not start")
	}
	revoked.Store(true)
	deadline := time.Now().Add(250 * time.Millisecond)
	for !errors.Is(cache.AuthorizePing(pingIdentity()), ErrDenied) {
		if time.Now().After(deadline) {
			t.Fatal("revocation publication queued behind disconnect SQL")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-exited:
		t.Fatal("test did not observe publication during blocked disconnect work")
	default:
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("owned workers did not stop after cancellation")
	}
}

func TestCooperativeDatabaseFailureEventuallyExpiresAuthority(t *testing.T) {
	var failed atomic.Bool
	cache := cacheFixture(t, revocationsFunc(func(context.Context) ([]RevokedDevice, error) {
		if failed.Load() {
			return nil, ErrUnavailable
		}
		return nil, nil
	}))
	cache.interval, cache.checkInterval = 5*time.Millisecond, 5*time.Millisecond
	cache.maxAge = 40 * time.Millisecond
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	failed.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := cache.Run(ctx); !errors.Is(err, ErrRevocationLiveness) {
		t.Fatal("cooperative failures retained admission indefinitely", err)
	}
	if !errors.Is(cache.AuthorizePing(pingIdentity()), ErrUnavailable) {
		t.Fatal("expired worker still admitted an unknown identity")
	}
}
