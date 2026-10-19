package guiacme

import (
	"context"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guicert"
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
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return Order{}, ErrCancelled
	}
	request, err := guicert.ValidateBoundCSR(csr, host, boundKey)
	if err != nil {
		return Order{}, ErrOrder
	}
	lease, err := s.lease(false)
	if err != nil {
		return Order{}, err
	}
	defer accountRelease(lease)
	state, key, err := s.load()
	if err != nil {
		return Order{}, err
	}
	// Ordinary jobs cannot create an account, adopt another identity after state
	// loss or agree to terms. Explicit account initialization/registration comes
	// first and remains a separate operator action.
	if state.URI == "" {
		return Order{}, ErrAccount
	}
	config := s.config
	config.Key = key
	client, err := New(config)
	if err != nil {
		return Order{}, ErrState
	}
	defer client.Close()
	if uri != "" && !client.transport.allowed(uri) {
		return Order{}, ErrOrder
	}
	account, err := client.EnsureAccount(ctx, Registration{ExpectedURI: state.URI})
	if err != nil {
		return Order{}, err
	}
	sdk := client.newSDK()
	sdk.KID = acme.KeyID(account.URI)
	directory, err := sdk.Discover(ctx)
	if err != nil {
		return Order{}, remoteError(ctx)
	}
	if len(directory.Profiles) > 32 {
		return Order{}, ErrOrder
	}
	var result *acme.Order
	if uri == "" {
		result, err = sdk.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: host}})
	} else {
		result, err = sdk.GetOrder(ctx, uri)
	}
	if err != nil {
		return Order{}, remoteError(ctx)
	}
	if ctx.Err() != nil {
		return Order{}, ErrCancelled
	}
	if !validOrder(client.transport, result, uri, host, directory.Profiles, time.Now()) {
		return Order{}, ErrOrder
	}
	return Order{URI: result.URI, Host: host, RequestFingerprint: hex.EncodeToString(request.Fingerprint[:]),
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
