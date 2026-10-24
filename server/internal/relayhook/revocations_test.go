package relayhook

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

type revocationsFunc func(context.Context) ([]RevokedDevice, error)

func (f revocationsFunc) Revocations(ctx context.Context) ([]RevokedDevice, error) { return f(ctx) }

func cacheFixture(t *testing.T, repository RevocationRepository) *RevocationCache {
	t.Helper()
	cache, err := NewRevocationCache(repository, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return cache
}

var revokedFixture = RevokedDevice{TenantID: "22222222-2222-4222-8222-222222222222", DeviceID: "11111111-1111-4111-8111-111111111111"}

func pingIdentity() protocol.ClaimPayload {
	return protocol.ClaimPayload{TenantID: revokedFixture.TenantID, DeviceID: revokedFixture.DeviceID}
}

func TestPingSnapshotIsMemoryOnlyMonotonicAndKeepsLastGood(t *testing.T) {
	var reads atomic.Int32
	var state atomic.Int32
	cache := cacheFixture(t, revocationsFunc(func(context.Context) ([]RevokedDevice, error) {
		reads.Add(1)
		switch state.Load() {
		case 1:
			return []RevokedDevice{revokedFixture}, nil
		case 2:
			return nil, errors.New("private database error")
		default:
			return nil, nil
		}
	}))
	if !errors.Is(cache.AuthorizePing(pingIdentity()), ErrUnavailable) {
		t.Fatal("uninitialized snapshot admitted Ping")
	}
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	state.Store(1)
	for range 10000 {
		if cache.AuthorizePing(pingIdentity()) != nil {
			t.Fatal("memory snapshot unexpectedly changed")
		}
	}
	if reads.Load() != 1 {
		t.Fatal("Ping queried its database loader")
	}
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(cache.AuthorizePing(pingIdentity()), ErrDenied) {
		t.Fatal("revocation not published")
	}
	state.Store(2)
	if cache.Refresh(context.Background()) == nil {
		t.Fatal("failed refresh accepted")
	}
	state.Store(0)
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(cache.AuthorizePing(pingIdentity()), ErrDenied) {
		t.Fatal("known one-way revocation disappeared")
	}
	other := pingIdentity()
	other.TenantID = "33333333-3333-4333-8333-333333333333"
	if cache.AuthorizePing(other) != nil {
		t.Fatal("snapshot key omitted tenant identity")
	}
}

func TestInvalidOrOversizedRefreshDoesNotReplaceSnapshot(t *testing.T) {
	for _, devices := range [][]RevokedDevice{{{TenantID: "invalid", DeviceID: revokedFixture.DeviceID}}, make([]RevokedDevice, MaxRevocations+1)} {
		var invalid atomic.Bool
		cache := cacheFixture(t, revocationsFunc(func(context.Context) ([]RevokedDevice, error) {
			if invalid.Load() {
				return devices, nil
			}
			return []RevokedDevice{revokedFixture}, nil
		}))
		if cache.Refresh(context.Background()) != nil {
			t.Fatal("initial refresh failed")
		}
		invalid.Store(true)
		if cache.Refresh(context.Background()) == nil || !errors.Is(cache.AuthorizePing(pingIdentity()), ErrDenied) {
			t.Fatal("invalid refresh replaced last-good snapshot")
		}
	}
}

func TestRevocationWorkerDistinguishesDatabaseFailureFromStalledCancellation(t *testing.T) {
	for _, stalled := range []bool{false, true} {
		t.Run(map[bool]string{false: "cooperative_timeout", true: "ignored_cancellation"}[stalled], func(t *testing.T) {
			var block atomic.Bool
			release := make(chan struct{})
			defer close(release)
			cache := cacheFixture(t, revocationsFunc(func(ctx context.Context) ([]RevokedDevice, error) {
				if !block.Load() {
					return []RevokedDevice{revokedFixture}, nil
				}
				if stalled {
					<-release
				} else {
					<-ctx.Done()
				}
				return nil, ctx.Err()
			}))
			cache.budget = 20 * time.Millisecond
			cache.grace = 100 * time.Millisecond
			cache.interval = 5 * time.Millisecond
			cache.checkInterval = 5 * time.Millisecond
			if cache.Refresh(context.Background()) != nil {
				t.Fatal("initial snapshot failed")
			}
			block.Store(true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- cache.Run(ctx) }()
			if stalled {
				select {
				case err := <-done:
					if !errors.Is(err, ErrRevocationLiveness) {
						t.Fatal("stalled dependency was not fatal", err)
					}
				case <-time.After(time.Second):
					t.Fatal("stalled refresh escaped deadline")
				}
			} else {
				select {
				case err := <-done:
					t.Fatal("normal database timeout stopped the worker", err)
				case <-time.After(150 * time.Millisecond):
				}
				cancel()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			}
			if !errors.Is(cache.AuthorizePing(pingIdentity()), ErrDenied) {
				t.Fatal("last-good snapshot lost during outage")
			}
		})
	}
}

func TestRevocationSelfCheckFailureStopsWorker(t *testing.T) {
	cache := cacheFixture(t, revocationsFunc(func(context.Context) ([]RevokedDevice, error) { return nil, nil }))
	if cache.Refresh(context.Background()) != nil {
		t.Fatal("initial snapshot failed")
	}
	cache.checkInterval = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cache.Run(ctx) }()
	cache.snapshot.Store(nil)
	select {
	case err := <-done:
		if !errors.Is(err, ErrRevocationLiveness) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("broken self-check did not stop worker")
	}
}

func TestSignedPingNeverUsesFreshAdmissionRepository(t *testing.T) {
	var admissions atomic.Int32
	var logs bytes.Buffer
	server, encoded := fixture(t, repositoryFunc(func(context.Context, protocol.ClaimPayload) error { admissions.Add(1); return nil }), &logs)
	cache := cacheFixture(t, revocationsFunc(func(context.Context) ([]RevokedDevice, error) { return nil, nil }))
	server.ping = cache
	object := envelope("Ping", encoded)
	object["content"] = map[string]any{"user": map[string]any{"metas": map[string]string{"device_id": revokedFixture.DeviceID, "domain_claim": encoded}}, "timestamp": 1}
	outcome(t, server, request(t, object), true, 200)
	if cache.Refresh(context.Background()) != nil {
		t.Fatal("initial snapshot failed")
	}
	outcome(t, server, request(t, object), false, 200)
	invalid := envelope("Ping", encoded)
	invalid["content"] = map[string]any{"user": map[string]any{"metas": map[string]string{"device_id": revokedFixture.DeviceID, "domain_claim": encoded + "x"}}}
	outcome(t, server, request(t, invalid), true, 200)
	if admissions.Load() != 0 {
		t.Fatal("Ping performed fresh admission SQL")
	}
	cache.repository = revocationsFunc(func(context.Context) ([]RevokedDevice, error) { return []RevokedDevice{revokedFixture}, nil })
	if cache.Refresh(context.Background()) != nil {
		t.Fatal("revocation refresh failed")
	}
	outcome(t, server, request(t, object), true, 200)
	outcome(t, server, request(t, envelope("Login", encoded)), false, 200)
	outcome(t, server, request(t, envelope("NewProxy", encoded)), false, 200)
	if admissions.Load() != 2 {
		t.Fatal("Ping cache replaced fresh Login/NewProxy admission")
	}
	if bytes.Contains(logs.Bytes(), []byte(encoded)) {
		t.Fatal("Ping exposed signed identity")
	}
}
