package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type invitationTestRepository struct {
	*testRepository
	digest       []byte
	passwordHash string
	accepted     int
	inviteError  error
}

func (r *invitationTestRepository) AcceptInvitation(_ context.Context, digest []byte, hash string, record SessionRecord) (SessionRecord, error) {
	r.accepted++
	r.digest = append([]byte(nil), digest...)
	r.passwordHash = hash
	record.User = User{ID: "invited-user", Email: "invited@example.com", Role: "member"}
	r.record = record
	return record, r.inviteError
}

func TestNewPasswordPolicy(t *testing.T) {
	for _, password := range []string{"", strings.Repeat("x", 14), strings.Repeat("x", MaxPasswordBytes+1), strings.Repeat("x", 15) + "\x00", strings.Repeat("x", 15) + "\n", strings.Repeat("x", 15) + "\r", strings.Repeat("x", 15) + "\xff"} {
		if !errors.Is(ValidateNewPassword(password), ErrWeakPassword) {
			t.Fatal("unsupported new password accepted")
		}
	}
	for _, password := range []string{strings.Repeat("x", 15), strings.Repeat("🔑", 15), strings.Repeat("x", MaxPasswordBytes)} {
		if err := ValidateNewPassword(password); err != nil {
			t.Fatal("supported password rejected", err)
		}
	}
}

func TestInvitationActivationUsesTheSessionAndHashBudgets(t *testing.T) {
	repository := &invitationTestRepository{testRepository: &testRepository{}}
	service, err := NewService(repository, Config{IdleTimeout: time.Minute, AbsoluteTimeout: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{29}, 32))
	password := "a new invitation passphrase"
	ip := netip.MustParseAddr("::ffff:192.0.2.29")
	for range 2 {
		service.workers <- struct{}{}
	}
	if _, err = service.AcceptInvitation(context.Background(), token, password, ip, "test"); !errors.Is(err, ErrBusy) || repository.accepted != 0 {
		t.Fatal("invitation hashing bypassed shared worker budget", err)
	}
	if _, err = service.Login(context.Background(), "member@example.com", password, ip, "test"); !errors.Is(err, ErrBusy) {
		t.Fatal("login used a different worker budget", err)
	}
	<-service.workers
	<-service.workers
	if _, err = service.AcceptInvitation(context.Background(), token, "too short", ip, "test"); !errors.Is(err, ErrWeakPassword) || repository.accepted != 0 {
		t.Fatal("weak password reached activation", err)
	}
	result, err := service.AcceptInvitation(context.Background(), token, password, ip, "test")
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := InvitationDigest(token)
	if repository.accepted != 1 || !bytes.Equal(repository.digest, digest) || repository.record.IP.String() != "192.0.2.29" || repository.record.ExpiresAt.Sub(repository.record.CreatedAt) != time.Hour {
		t.Fatal("activation lost invite/session binding")
	}
	if valid, e := VerifyPassword(repository.passwordHash, password); e != nil || !valid || strings.Contains(repository.passwordHash, password) {
		t.Fatal("activation did not hash the new password", e)
	}
	if got, e := service.AuthenticatePassive(context.Background(), result.Token); e != nil || got.User != result.User || got.CSRFToken != result.CSRFToken {
		t.Fatal("new invitation session lost synchronizer binding", e)
	}
	encoded, _ := json.Marshal(result)
	for _, secret := range []string{token, result.Token, repository.passwordHash, password} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatal("activation reply exposed a credential")
		}
	}
	repository.inviteError = ErrInviteInvalid
	if got, e := service.AcceptInvitation(context.Background(), token, password, ip, "test"); !errors.Is(e, ErrInviteInvalid) || got.Token != "" {
		t.Fatal("rejected invite produced a session", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, e := service.AcceptInvitation(ctx, token, password, ip, "test"); !errors.Is(e, ErrUnavailable) || got.Token != "" {
		t.Fatal("cancelled activation produced a session", e)
	}
}
