package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/sso"
)

func TestSAMLReplayCacheRefusesUnavailableStore(t *testing.T) {
	now := time.Now()
	var absent *samlReplayCache
	for _, cache := range []*samlReplayCache{absent, {}, {store: &ConsoleStore{}, providerID: "provider"}} {
		if seen, err := cache.SeenOrAdd(context.Background(), "assertion", now.Add(time.Hour), now); seen || !errors.Is(err, sso.ErrFlow) {
			t.Fatal("missing replay persistence was treated as a fresh assertion")
		}
	}
}
