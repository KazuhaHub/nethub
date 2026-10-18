package auth

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

type testRepository struct {
	candidate Candidate
	record    SessionRecord
	failure   error
	entered   chan struct{}
	release   chan struct{}
}

func (r *testRepository) PasswordCandidate(ctx context.Context, _ string) (Candidate, error) {
	if r.entered != nil {
		r.entered <- struct{}{}
		select {
		case <-r.release:
		case <-ctx.Done():
			return Candidate{}, ctx.Err()
		}
	}
	return r.candidate, r.failure
}
func (r *testRepository) CreateSession(_ context.Context, _ Candidate, record SessionRecord) (SessionRecord, error) {
	record.User = r.candidate.User
	r.record = record
	return record, r.failure
}
func (r *testRepository) LookupSession(context.Context, []byte, time.Duration) (SessionRecord, error) {
	return r.record, r.failure
}
func (r *testRepository) DeleteSession(context.Context, []byte) error { return r.failure }

func TestServiceFailuresAndSynchronizerPersistence(t *testing.T) {
	hash, err := HashPassword("a test passphrase")
	if err != nil {
		t.Fatal(err)
	}
	repository := &testRepository{candidate: Candidate{User: User{ID: "fixture", Email: "member@example.com", Role: "member"}, PasswordHash: hash}}
	service, err := NewService(repository, Config{})
	if err != nil {
		t.Fatal(err)
	}
	login, err := service.Login(context.Background(), "member@example.com", "a test passphrase", netip.MustParseAddr("192.0.2.1"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if repository.record.ExpiresAt.Sub(repository.record.CreatedAt) != 12*time.Hour {
		t.Fatal("absolute timeout default changed")
	}
	if service.config.IdleTimeout != 30*time.Minute {
		t.Fatal("idle timeout default changed")
	}
	if _, err = service.Authenticate(context.Background(), login.Token); err != nil {
		t.Fatal(err)
	}
	repository.record.CSRFHash[0] ^= 1
	if _, err = service.Authenticate(context.Background(), login.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("corrupted CSRF binding accepted")
	}
	repository.failure = errors.New("private database diagnostic")
	if _, err = service.Login(context.Background(), "member@example.com", "a test passphrase", netip.MustParseAddr("192.0.2.1"), "test"); err != ErrUnavailable {
		t.Fatalf("repository failure leaked: %v", err)
	}
	if _, err = service.Authenticate(context.Background(), login.Token); err != ErrUnavailable {
		t.Fatal("lookup failure did not fail closed")
	}
	if err = service.Logout(context.Background(), login.Token); err != ErrUnavailable {
		t.Fatal("delete failure reported success")
	}
	for _, config := range []Config{{IdleTimeout: -1}, {AbsoluteTimeout: time.Second}, {AbsoluteTimeout: 8 * 24 * time.Hour}} {
		if _, err = NewService(repository, config); err == nil {
			t.Fatal("invalid timeout configuration accepted")
		}
	}
}

func TestServiceBoundsPasswordConcurrencyAndHonorsCancellation(t *testing.T) {
	repository := &testRepository{entered: make(chan struct{}, 2), release: make(chan struct{})}
	service, err := NewService(repository, Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := service.Login(ctx, "member@example.com", "test", netip.MustParseAddr("192.0.2.1"), "test")
			results <- err
		}()
	}
	for range 2 {
		select {
		case <-repository.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("verification did not enter repository")
		}
	}
	if _, err := service.Login(ctx, "member@example.com", "test", netip.MustParseAddr("192.0.2.1"), "test"); err != ErrBusy {
		t.Fatal("password concurrency bound exceeded")
	}
	cancel()
	for range 2 {
		select {
		case err := <-results:
			if err != ErrUnavailable {
				t.Fatal("canceled login accepted")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("canceled verification remained blocked")
		}
	}
}
