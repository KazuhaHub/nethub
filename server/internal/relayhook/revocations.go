package relayhook

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

const RevocationInterval = 5 * time.Second
const RevocationBudget = 2 * time.Second
const MaxRevocations = 100000

var ErrRevocationLiveness = errors.New("revocation refresh or self-check stopped")
var revocationUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type RevokedDevice struct{ TenantID, DeviceID string }

type RevocationRepository interface {
	Revocations(context.Context) ([]RevokedDevice, error)
}

type RotatedClaim struct {
	Device   RevokedDevice
	IssuedAt time.Time
}

type ClaimRotationRepository interface {
	ClaimRotations(context.Context) ([]RotatedClaim, error)
}

type DisconnectProcessor interface {
	ProcessDisconnects(context.Context, func(RevokedDevice) bool) error
}

func (c *RevocationCache) ProcessDisconnects(ctx context.Context) error {
	processor, ok := c.repository.(DisconnectProcessor)
	if !ok {
		return nil
	}
	read, cancel := context.WithTimeout(ctx, c.budget)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- processor.ProcessDisconnects(read, func(device RevokedDevice) bool {
			// A rotated claim is not a revoked device. Disconnect completion must
			// inspect the one-way revocation set rather than a missing timestamp.
			snapshot := c.snapshot.Load()
			if snapshot == nil {
				return false
			}
			_, revoked := snapshot.devices[device]
			return revoked
		})
	}()
	select {
	case err := <-done:
		if read.Err() != nil {
			return ErrUnavailable
		}
		return err
	case <-read.Done():
		timer := time.NewTimer(c.grace)
		defer timer.Stop()
		select {
		case <-done:
			return ErrUnavailable
		case <-timer.C:
			return ErrRevocationLiveness
		}
	}
}

type revocationSnapshot struct {
	devices       map[RevokedDevice]struct{}
	probe         RevokedDevice
	rotated       map[RevokedDevice]time.Time
	rotationProbe RotatedClaim
}

// RevocationCache is used only for Ping. Login and proxy admission still use SQL.
type RevocationCache struct {
	repository                             RevocationRepository
	logger                                 *slog.Logger
	snapshot                               atomic.Pointer[revocationSnapshot]
	publish                                sync.Mutex
	interval, budget, grace, checkInterval time.Duration
}

func NewRevocationCache(repository RevocationRepository, logger *slog.Logger) (*RevocationCache, error) {
	if repository == nil || logger == nil {
		return nil, ErrUnavailable
	}
	return &RevocationCache{repository: repository, logger: logger, interval: RevocationInterval,
		budget: RevocationBudget, grace: 250 * time.Millisecond, checkInterval: time.Second}, nil
}

func (c *RevocationCache) AuthorizePing(identity protocol.ClaimPayload) error {
	if c == nil {
		return ErrUnavailable
	}
	snapshot := c.snapshot.Load()
	if snapshot == nil || snapshot.devices == nil || len(snapshot.devices) > MaxRevocations {
		return ErrUnavailable
	}
	if _, revoked := snapshot.devices[RevokedDevice{identity.TenantID, identity.DeviceID}]; revoked {
		return ErrDenied
	}
	if len(snapshot.rotated) > MaxRevocations {
		return ErrUnavailable
	}
	if floor, rotated := snapshot.rotated[RevokedDevice{identity.TenantID, identity.DeviceID}]; rotated {
		issued, err := time.Parse("2006-01-02T15:04:05.000000Z", identity.IssuedAt)
		if err != nil || issued.Format("2006-01-02T15:04:05.000000Z") != identity.IssuedAt || issued.Before(floor) {
			return ErrDenied
		}
	}
	return nil
}

func (c *RevocationCache) selfCheck() bool {
	snapshot := c.snapshot.Load()
	if snapshot == nil || snapshot.devices == nil || len(snapshot.devices) > MaxRevocations {
		return false
	}
	err := c.AuthorizePing(protocol.ClaimPayload{TenantID: snapshot.probe.TenantID, DeviceID: snapshot.probe.DeviceID})
	if len(snapshot.devices) == 0 && err != nil || len(snapshot.devices) != 0 && !errors.Is(err, ErrDenied) {
		return false
	}
	if len(snapshot.rotated) > MaxRevocations {
		return false
	}
	if len(snapshot.rotated) > 0 {
		probe := snapshot.rotationProbe
		if probe.IssuedAt.IsZero() {
			return false
		}
		identity := protocol.ClaimPayload{TenantID: probe.Device.TenantID, DeviceID: probe.Device.DeviceID,
			IssuedAt: probe.IssuedAt.Add(-time.Microsecond).Format("2006-01-02T15:04:05.000000Z")}
		if !errors.Is(c.AuthorizePing(identity), ErrDenied) {
			return false
		}
	}
	return true
}

// Refresh bounds both the database request and a dependency ignoring cancellation.
// A stalled dependency is fatal; normal database failures retain the last snapshot.
func (c *RevocationCache) Refresh(ctx context.Context) error {
	read, cancel := context.WithTimeout(ctx, c.budget)
	defer cancel()
	type result struct {
		devices []RevokedDevice
		rotated []RotatedClaim
		err     error
	}
	done := make(chan result, 1)
	go func() {
		devices, err := c.repository.Revocations(read)
		var rotated []RotatedClaim
		if repository, ok := c.repository.(ClaimRotationRepository); err == nil && ok {
			rotated, err = repository.ClaimRotations(read)
		}
		done <- result{devices: devices, rotated: rotated, err: err}
	}()
	var value result
	select {
	case value = <-done:
	case <-read.Done():
		timer := time.NewTimer(c.grace)
		defer timer.Stop()
		select {
		case <-done:
			return ErrUnavailable
		case <-timer.C:
			return ErrRevocationLiveness
		}
	}
	if value.err != nil || read.Err() != nil || len(value.devices) > MaxRevocations || len(value.rotated) > MaxRevocations {
		return ErrUnavailable
	}
	for _, device := range value.devices {
		if !revocationUUID.MatchString(device.TenantID) || !revocationUUID.MatchString(device.DeviceID) {
			return ErrUnavailable
		}
	}
	for _, rotation := range value.rotated {
		if !revocationUUID.MatchString(rotation.Device.TenantID) || !revocationUUID.MatchString(rotation.Device.DeviceID) ||
			rotation.IssuedAt.IsZero() || rotation.IssuedAt.UTC().Year() < 1 || rotation.IssuedAt.UTC().Year() > 9999 || rotation.IssuedAt.Nanosecond()%1000 != 0 {
			return ErrUnavailable
		}
	}
	c.publish.Lock()
	defer c.publish.Unlock()
	// Revocation is one-way. An older or incomplete read cannot re-admit a known ID.
	next := &revocationSnapshot{devices: make(map[RevokedDevice]struct{}, len(value.devices)), rotated: make(map[RevokedDevice]time.Time)}
	if previous := c.snapshot.Load(); previous != nil {
		for device := range previous.devices {
			next.devices[device] = struct{}{}
			next.probe = device
		}
		for device, issued := range previous.rotated {
			next.rotated[device] = issued
			next.rotationProbe = RotatedClaim{Device: device, IssuedAt: issued}
		}
	}
	for _, device := range value.devices {
		next.devices[device] = struct{}{}
		next.probe = device
	}
	for _, rotation := range value.rotated {
		// Out-of-order reads must never lower a known claim issuance floor.
		if current, exists := next.rotated[rotation.Device]; !exists || rotation.IssuedAt.After(current) {
			next.rotated[rotation.Device] = rotation.IssuedAt.UTC()
			next.rotationProbe = RotatedClaim{Device: rotation.Device, IssuedAt: rotation.IssuedAt.UTC()}
		}
	}
	if len(next.devices) > MaxRevocations || len(next.rotated) > MaxRevocations {
		return ErrUnavailable
	}
	c.snapshot.Store(next)
	return nil
}

func (c *RevocationCache) Run(ctx context.Context) error {
	if !c.selfCheck() {
		return ErrRevocationLiveness
	}
	refresh := time.NewTicker(c.interval)
	defer refresh.Stop()
	check := time.NewTicker(c.checkInterval)
	defer check.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-check.C:
			if !c.selfCheck() {
				return ErrRevocationLiveness
			}
		case <-refresh.C:
			err := c.Refresh(ctx)
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, ErrRevocationLiveness) {
				return err
			}
			if err != nil {
				c.logger.Warn("Revocation refresh failed; retaining previous snapshot")
			}
			err = c.ProcessDisconnects(ctx)
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, ErrRevocationLiveness) {
				return err
			}
			if err != nil {
				c.logger.Warn("Disconnect requests remain pending")
			}
		}
	}
}
