package guiacme

import (
	"context"
	"encoding/hex"
	"regexp"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guicert"
	"golang.org/x/crypto/acme"
)

var challengeToken = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)

// HTTP01 is private durable job metadata, not an ordinary JSON/status payload.
type HTTP01 struct {
	Order            Order     `json:"-"`
	URI              string    `json:"-"`
	Token            string    `json:"-"`
	KeyAuthorization string    `json:"-"`
	Status           string    `json:"-"`
	ExpiresAt        time.Time `json:"-"`
	Complete         bool      `json:"-"`
}

// PrepareHTTP01 checks a saved order's immutable identity before deriving an
// account-bound key authorization. It does not publish or accept a challenge.
func (s *AccountStore) PrepareHTTP01(ctx context.Context, saved Order, csr []byte, boundKey string) (HTTP01, error) {
	session, err := s.knownOrder(ctx, saved, csr, boundKey)
	if err != nil {
		return HTTP01{}, err
	}
	defer session.close()
	return session.http01(saved)
}

// AcceptHTTP01 is only for a job whose exact public response has already been
// durably published and whose live assignment has been reauthorized. It rechecks
// the order, authorization and challenge before POST, never accepts an arbitrary
// supplied URL and does not repeat acceptance of processing/validated challenges.
func (s *AccountStore) AcceptHTTP01(ctx context.Context, saved HTTP01, csr []byte, boundKey string) (HTTP01, error) {
	session, err := s.knownOrder(ctx, saved.Order, csr, boundKey)
	if err != nil {
		return HTTP01{}, err
	}
	defer session.close()
	current, err := session.http01(saved.Order)
	if err != nil || current.Complete {
		return current, err
	}
	if current.URI != saved.URI || current.Token != saved.Token || current.KeyAuthorization != saved.KeyAuthorization ||
		saved.Complete || !saved.ExpiresAt.After(time.Now()) || saved.ExpiresAt.After(current.ExpiresAt) {
		return HTTP01{}, ErrOrder
	}
	if current.Status != acme.StatusPending {
		return current, nil
	}
	result, err := session.sdk.Accept(session.ctx, &acme.Challenge{Type: "http-01", URI: current.URI, Token: current.Token})
	if err != nil {
		return HTTP01{}, remoteError(session.ctx)
	}
	if session.ctx.Err() != nil {
		return HTTP01{}, ErrCancelled
	}
	if !validHTTPChallenge(session.client.transport, result) || result.URI != current.URI || result.Token != current.Token {
		return HTTP01{}, ErrOrder
	}
	current.Status = result.Status
	return current, nil
}

func (s *AccountStore) knownOrder(ctx context.Context, saved Order, csr []byte, boundKey string) (*orderSession, error) {
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	request, err := guicert.ValidateBoundCSR(csr, saved.Host, boundKey)
	if err != nil || saved.URI == "" || saved.RequestFingerprint != hex.EncodeToString(request.Fingerprint[:]) {
		return nil, ErrOrder
	}
	return s.openOrder(ctx, saved.URI, csr, saved.Host, boundKey)
}

func (session *orderSession) http01(saved Order) (HTTP01, error) {
	order, _, err := session.savedOrder(saved)
	if err != nil {
		return HTTP01{}, err
	}
	if order.Status != acme.StatusPending && order.Status != acme.StatusReady {
		return HTTP01{}, ErrOrder
	}
	auth, err := session.sdk.GetAuthorization(session.ctx, order.AuthorizationURL)
	if err != nil {
		return HTTP01{}, remoteError(session.ctx)
	}
	if session.ctx.Err() != nil {
		return HTTP01{}, ErrCancelled
	}
	if auth == nil || auth.URI != order.AuthorizationURL || auth.Identifier.Type != "dns" || auth.Identifier.Value != order.Host || auth.Wildcard ||
		!auth.Expires.After(time.Now()) || len(auth.Challenges) > 16 {
		return HTTP01{}, ErrOrder
	}
	expires := order.Expires
	if auth.Expires.Before(expires) {
		expires = auth.Expires
	}
	if !expires.After(time.Now()) {
		return HTTP01{}, ErrOrder
	}
	if auth.Status == acme.StatusValid {
		return HTTP01{Order: order, Status: acme.StatusValid, ExpiresAt: expires, Complete: true}, nil
	}
	if auth.Status != acme.StatusPending || order.Status != acme.StatusPending {
		return HTTP01{}, ErrOrder
	}
	var selected *acme.Challenge
	for _, challenge := range auth.Challenges {
		if challenge == nil || challenge.Type != "http-01" {
			continue
		}
		if selected != nil || !validHTTPChallenge(session.client.transport, challenge) {
			return HTTP01{}, ErrOrder
		}
		selected = challenge
	}
	if selected == nil {
		return HTTP01{}, ErrOrder
	}
	authorization, err := session.sdk.HTTP01ChallengeResponse(selected.Token)
	if err != nil {
		return HTTP01{}, ErrOrder
	}
	return HTTP01{Order: order, URI: selected.URI, Token: selected.Token, KeyAuthorization: authorization,
		Status: selected.Status, ExpiresAt: expires}, nil
}

func validHTTPChallenge(t *transport, challenge *acme.Challenge) bool {
	if challenge == nil || challenge.Type != "http-01" || !t.allowed(challenge.URI) || !challengeToken.MatchString(challenge.Token) || challenge.Error != nil {
		return false
	}
	return challenge.Status == acme.StatusPending || challenge.Status == acme.StatusProcessing || challenge.Status == acme.StatusValid
}
