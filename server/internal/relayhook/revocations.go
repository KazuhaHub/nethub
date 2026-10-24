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

type revocationSnapshot struct {
	devices map[RevokedDevice]struct{}
	probe   RevokedDevice
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
	return nil
}

func (c *RevocationCache) selfCheck() bool {
	snapshot := c.snapshot.Load()
	if snapshot == nil || snapshot.devices == nil || len(snapshot.devices) > MaxRevocations {
		return false
	}
	err := c.AuthorizePing(protocol.ClaimPayload{TenantID: snapshot.probe.TenantID, DeviceID: snapshot.probe.DeviceID})
	if len(snapshot.devices) == 0 {
		return err == nil
	}
	return errors.Is(err, ErrDenied)
}

// Refresh bounds both the database request and a dependency ignoring cancellation.
// A stalled dependency is fatal; normal database failures retain the last snapshot.
func (c *RevocationCache) Refresh(ctx context.Context) error {
	read, cancel := context.WithTimeout(ctx, c.budget)
	defer cancel()
	type result struct {
		devices []RevokedDevice
		err     error
	}
	done := make(chan result, 1)
	go func() { devices, err := c.repository.Revocations(read); done <- result{devices, err} }()
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
	if value.err != nil || read.Err() != nil || len(value.devices) > MaxRevocations {
		return ErrUnavailable
	}
	for _, device := range value.devices {
		if !revocationUUID.MatchString(device.TenantID) || !revocationUUID.MatchString(device.DeviceID) {
			return ErrUnavailable
		}
	}
	c.publish.Lock()
	defer c.publish.Unlock()
	// Revocation is one-way. An older or incomplete read cannot re-admit a known ID.
	next := &revocationSnapshot{devices: make(map[RevokedDevice]struct{}, len(value.devices))}
	if previous := c.snapshot.Load(); previous != nil {
		for device := range previous.devices {
			next.devices[device] = struct{}{}
			next.probe = device
		}
	}
	for _, device := range value.devices {
		next.devices[device] = struct{}{}
		next.probe = device
	}
	if len(next.devices) > MaxRevocations {
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
		}
	}
}
