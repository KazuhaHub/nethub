package device

import (
	"context"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

// PublishedTrustReader returns only independently validated current public
// trust after checking repository role/readiness. Nil means an uninitialized
// head, never a missing/unavailable/wrong-name/expired publication. Enrollment
// must still select its actual response under the registration transaction lock.
type PublishedTrustReader interface {
	CurrentRelayTrust(context.Context, string) (*relaytrust.Generation, error)
}

func initialPublishedTrust(repository Repository, serverName string) (*relaytrust.Generation, error) {
	reader, ok := repository.(PublishedTrustReader)
	if !ok {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	generation, err := reader.CurrentRelayTrust(ctx, serverName)
	if err != nil || ctx.Err() != nil || generation != nil && !generation.Valid(serverName, time.Now()) {
		return nil, ErrUnavailable
	}
	return generation, nil
}

func (s *Service) trustReady(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	if reader, ok := s.repository.(PublishedTrustReader); ok {
		generation, err := reader.CurrentRelayTrust(ctx, s.relay.ServerName)
		if err != nil || ctx.Err() != nil {
			return false
		}
		if generation != nil {
			if !generation.Valid(s.relay.ServerName, s.now()) {
				return false
			}
			s.publishedTrustSeen.Store(true)
			return true
		}
	}
	return !s.publishedTrustSeen.Load() && s.trustValid(s.now())
}
