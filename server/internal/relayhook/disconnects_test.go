package relayhook

import (
	"context"
	"errors"
	"testing"
	"time"
)

type disconnectFixture struct {
	revocationsFunc
	process func(context.Context, func(RevokedDevice) bool) error
}

func (f disconnectFixture) ProcessDisconnects(ctx context.Context, ready func(RevokedDevice) bool) error {
	return f.process(ctx, ready)
}

func TestDisconnectAcknowledgementRequiresPublishedDenial(t *testing.T) {
	var revoked bool
	var acknowledged int
	repository := disconnectFixture{revocationsFunc: func(context.Context) ([]RevokedDevice, error) {
		if revoked {
			return []RevokedDevice{revokedFixture}, nil
		}
		return nil, nil
	}, process: func(_ context.Context, ready func(RevokedDevice) bool) error {
		if ready(revokedFixture) {
			acknowledged++
		}
		return nil
	}}
	cache := cacheFixture(t, repository)
	if cache.ProcessDisconnects(context.Background()) != nil || acknowledged != 0 {
		t.Fatal("uninitialized cache acknowledged a request")
	}
	if cache.Refresh(context.Background()) != nil {
		t.Fatal("initial refresh failed")
	}
	revoked = true
	if cache.ProcessDisconnects(context.Background()) != nil || acknowledged != 0 {
		t.Fatal("SQL revocation acknowledged before memory publication")
	}
	if cache.Refresh(context.Background()) != nil || cache.ProcessDisconnects(context.Background()) != nil || acknowledged != 1 {
		t.Fatal("published denial was not acknowledged")
	}
}

func TestStalledDisconnectProcessorHasTheRefreshLivenessBound(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	repository := disconnectFixture{revocationsFunc: func(context.Context) ([]RevokedDevice, error) { return []RevokedDevice{revokedFixture}, nil }, process: func(context.Context, func(RevokedDevice) bool) error { <-release; return nil }}
	cache := cacheFixture(t, repository)
	cache.budget = 20 * time.Millisecond
	cache.grace = 30 * time.Millisecond
	if cache.Refresh(context.Background()) != nil {
		t.Fatal("initial refresh failed")
	}
	started := time.Now()
	if err := cache.ProcessDisconnects(context.Background()); !errors.Is(err, ErrRevocationLiveness) || time.Since(started) > time.Second {
		t.Fatal("stalled cutoff processor escaped its deadline", err)
	}
}
