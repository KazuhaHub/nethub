package guiacme

import (
	"context"
	"time"
)

// CurrentTerms fetches fresh directory metadata for operator review. It never
// follows the terms reference, accepts it, looks up an account or registers one.
// The returned reference is comparison-only data; do not render it as HTML.
func (c *Client) CurrentTerms(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	case <-ctx.Done():
		return "", ErrCancelled
	}
	if ctx.Err() != nil {
		return "", ErrCancelled
	}
	directory, err := c.discoverDirectory(ctx, c.newSDK())
	if err != nil {
		return "", err
	}
	return directory.Terms, nil
}

// CurrentTerms requires the existing durable key namespace but does not mutate
// it. Missing state cannot trigger initialization, registration or key creation.
func (s *AccountStore) CurrentTerms(ctx context.Context) (string, error) {
	if ctx.Err() != nil {
		return "", ErrCancelled
	}
	lease, err := s.lease(false)
	if err != nil {
		return "", err
	}
	defer accountRelease(lease)
	_, key, err := s.load()
	if err != nil {
		return "", err
	}
	config := s.config
	config.Key = key
	client, err := New(config)
	if err != nil {
		return "", ErrState
	}
	defer client.Close()
	return client.CurrentTerms(ctx)
}
