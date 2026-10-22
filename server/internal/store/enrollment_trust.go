package store

import (
	"context"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/relaytrust"
)

var _ device.PublishedTrustReader = (*EnrollmentStore)(nil)

// CurrentRelayTrust is a readiness preflight, not enrollment admission. The
// registration transaction independently locks/reselects the head before it
// consumes a token and supplies the trust used by the signing callback.
func (s *EnrollmentStore) CurrentRelayTrust(ctx context.Context, serverName string) (*relaytrust.Generation, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return (&RelayTrustStore{Enrollment: s, ServerName: serverName}).currentPublic(ctx)
}
