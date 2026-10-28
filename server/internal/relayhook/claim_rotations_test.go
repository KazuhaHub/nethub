package relayhook

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

type rotationSnapshotRepository struct {
	revoked            []RevokedDevice
	rotated            []RotatedClaim
	err                error
	reads              atomic.Int32
	completionObserved bool
}

func (r *rotationSnapshotRepository) Revocations(context.Context) ([]RevokedDevice, error) {
	return r.revoked, nil
}
func (r *rotationSnapshotRepository) ClaimRotations(context.Context) ([]RotatedClaim, error) {
	r.reads.Add(1)
	return r.rotated, r.err
}
func (r *rotationSnapshotRepository) ProcessDisconnects(_ context.Context, complete func(RevokedDevice) bool) error {
	r.completionObserved = complete(revokedFixture)
	return nil
}

func TestRotationPingFloorIsMonotonicAndNeverCompletesRevocation(t *testing.T) {
	floor := time.Date(2026, 10, 28, 0, 0, 0, 1_000, time.UTC)
	repository := &rotationSnapshotRepository{rotated: []RotatedClaim{{Device: revokedFixture, IssuedAt: floor}}}
	cache := cacheFixture(t, repository)
	if cache.Refresh(context.Background()) != nil || !cache.selfCheck() {
		t.Fatal("rotation floor not published")
	}
	current := protocol.ClaimPayload{TenantID: revokedFixture.TenantID, DeviceID: revokedFixture.DeviceID,
		IssuedAt: floor.Format("2006-01-02T15:04:05.000000Z")}
	old := current
	old.IssuedAt = floor.Add(-time.Microsecond).Format("2006-01-02T15:04:05.000000Z")
	for range 10000 {
		if cache.AuthorizePing(current) != nil || !errors.Is(cache.AuthorizePing(old), ErrDenied) {
			t.Fatal("rotation floor failed to distinguish old and replacement claims")
		}
	}
	if repository.reads.Load() != 1 {
		t.Fatal("Ping queried rotation storage")
	}
	if cache.ProcessDisconnects(context.Background()) != nil || repository.completionObserved {
		t.Fatal("rotation was mistaken for completed device revocation")
	}
	repository.rotated[0].IssuedAt = floor.Add(-time.Second)
	if cache.Refresh(context.Background()) != nil || !errors.Is(cache.AuthorizePing(old), ErrDenied) {
		t.Fatal("older snapshot lowered a known floor")
	}
	repository.rotated = nil
	if cache.Refresh(context.Background()) != nil || !errors.Is(cache.AuthorizePing(old), ErrDenied) {
		t.Fatal("incomplete snapshot discarded a known rotation floor")
	}
	repository.err = errors.New("private loader diagnostic")
	if cache.Refresh(context.Background()) == nil || !errors.Is(cache.AuthorizePing(old), ErrDenied) {
		t.Fatal("failed refresh lost the previous floor")
	}
	repository.err = nil
	repository.revoked = []RevokedDevice{revokedFixture}
	if cache.Refresh(context.Background()) != nil || !errors.Is(cache.AuthorizePing(current), ErrDenied) || !cache.selfCheck() {
		t.Fatal("rotation bypassed a subsequent revocation")
	}
	if cache.ProcessDisconnects(context.Background()) != nil || !repository.completionObserved {
		t.Fatal("actual revocation was not recognized")
	}
}

func TestInvalidRotationFloorPreservesTheLastGoodSnapshot(t *testing.T) {
	floor := time.Date(2026, 10, 28, 0, 0, 0, 1_000, time.UTC)
	for _, invalid := range [][]RotatedClaim{
		{{Device: revokedFixture}},
		{{Device: RevokedDevice{TenantID: "bad", DeviceID: revokedFixture.DeviceID}, IssuedAt: floor}},
		{{Device: revokedFixture, IssuedAt: floor.Add(time.Nanosecond)}},
		make([]RotatedClaim, MaxRevocations+1),
	} {
		repository := &rotationSnapshotRepository{rotated: []RotatedClaim{{Device: revokedFixture, IssuedAt: floor}}}
		cache := cacheFixture(t, repository)
		if cache.Refresh(context.Background()) != nil {
			t.Fatal("initial floor unavailable")
		}
		repository.rotated = invalid
		if cache.Refresh(context.Background()) == nil || !cache.selfCheck() {
			t.Fatal("invalid floor replaced the last good snapshot")
		}
	}
}
