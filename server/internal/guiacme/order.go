package guiacme

import (
	"context"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"golang.org/x/crypto/acme"
)

var ErrOrder = errors.New("ACME order unavailable or mismatched")
var orderProfile = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// Order is private issuer job metadata, never a console response or log payload.
// A durable job must save URI before publishing or accepting any challenge.
type Order struct {
	URI                string    `json:"-"`
	Host               string    `json:"-"`
	RequestFingerprint string    `json:"-"`
	Status             string    `json:"-"`
	Profile            string    `json:"-"`
	AuthorizationURL   string    `json:"-"`
	FinalizeURL        string    `json:"-"`
	CertificateURL     string    `json:"-"`
	Expires            time.Time `json:"-"`
}

// CreateOrder creates only a single-name order for a validated bound request.
// The caller must authorize the live tenant/device/assignment and durably track
// the attempt. Losing this response can leave an unvalidated orphan order; this
// method does not claim exactly-once order creation or retry automatically.
func (s *AccountStore) CreateOrder(ctx context.Context, csr []byte, host, boundKey string) (Order, error) {
	return s.order(ctx, "", csr, host, boundKey)
}

// InspectOrder recovers the same persisted URI, never creates another order and
// performs one observation rather than waiting or polling inside the SDK.
func (s *AccountStore) InspectOrder(ctx context.Context, uri string, csr []byte, host, boundKey string) (Order, error) {
	if uri == "" {
		return Order{}, ErrOrder
	}
	return s.order(ctx, uri, csr, host, boundKey)
}

func (s *AccountStore) order(ctx context.Context, uri string, csr []byte, host, boundKey string) (Order, error) {
	session, err := s.openOrder(ctx, uri, csr, host, boundKey)
	if err != nil {
		return Order{}, err
	}
	defer session.close()
	var result *acme.Order
	if uri == "" {
		result, err = session.sdk.AuthorizeOrder(session.ctx, []acme.AuthzID{{Type: "dns", Value: host}})
	} else {
		result, err = session.sdk.GetOrder(session.ctx, uri)
	}
	if err != nil {
		return Order{}, remoteError(session.ctx)
	}
	return session.result(result, uri, host)
}

func (session *orderSession) result(result *acme.Order, uri, host string) (Order, error) {
	if session.ctx.Err() != nil {
		return Order{}, ErrCancelled
	}
	if !validOrder(session.client.transport, result, uri, host, session.directory.Profiles, time.Now()) {
		return Order{}, ErrOrder
	}
	return Order{URI: result.URI, Host: host, RequestFingerprint: hex.EncodeToString(session.request.Fingerprint[:]),
		Status: result.Status, Profile: string(result.Profile), AuthorizationURL: result.AuthzURLs[0], FinalizeURL: result.FinalizeURL,
		CertificateURL: result.CertURL, Expires: result.Expires}, nil
}

func validOrder(t *transport, order *acme.Order, expectedURI, host string, profiles map[acme.ProfileName]string, now time.Time) bool {
	if order == nil || !t.allowed(order.URI) || expectedURI != "" && order.URI != expectedURI ||
		len(order.Identifiers) != 1 || order.Identifiers[0].Type != "dns" || order.Identifiers[0].Value != host ||
		len(order.AuthzURLs) != 1 || !t.allowed(order.AuthzURLs[0]) || !t.allowed(order.FinalizeURL) ||
		order.CertURL != "" && !t.allowed(order.CertURL) {
		return false
	}
	if order.Profile != "" {
		if _, advertised := profiles[order.Profile]; !advertised || !orderProfile.MatchString(string(order.Profile)) {
			return false
		}
	}
	switch order.Status {
	case acme.StatusPending, acme.StatusReady, acme.StatusProcessing:
		return !order.Expires.IsZero() && order.Expires.After(now) && order.CertURL == "" && order.Error == nil
	case acme.StatusValid:
		return order.CertURL != "" && order.Error == nil
	case acme.StatusInvalid:
		return order.CertURL == ""
	default:
		return false
	}
}
