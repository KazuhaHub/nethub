// Package guiacme confines the ACME account client to operator-approved origins.
package guiacme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"math/big"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

var (
	ErrConfig    = errors.New("invalid ACME client configuration")
	ErrRemote    = errors.New("ACME service unavailable or invalid")
	ErrConsent   = errors.New("ACME account creation requires explicit consent")
	ErrAccount   = errors.New("ACME account unavailable or mismatched")
	ErrCancelled = errors.New("ACME operation cancelled")
)

type Config struct {
	DirectoryURL string
	// AdditionalOrigins is operator configuration, never CA or device input.
	AdditionalOrigins []string
	Roots             *x509.CertPool
	// Key must already be durably stored in private issuer state. This package
	// neither generates nor rotates it, including after an ambiguous response.
	Key          *ecdsa.PrivateKey
	ContactEmail string
}

// Account is private issuer metadata, not a console status or log value.
type Account struct {
	URI       string `json:"-"`
	OrdersURL string `json:"-"`
}

type Registration struct {
	// AllowCreate is false for ordinary lookup/recovery. A new registration is
	// permitted only with the exact currently advertised Terms of Service URL.
	AllowCreate      bool
	AcceptedTermsURL string
	// ExpectedURI binds recovery to a persisted account identity, when known.
	ExpectedURI string
}

type Client struct {
	gate      chan struct{}
	key       *ecdsa.PrivateKey
	directory string
	transport *transport
	contact   []string
}

func New(config Config) (*Client, error) {
	if !validKey(config.Key) || len(config.AdditionalOrigins) > 8 {
		return nil, ErrConfig
	}
	directory, ok := endpoint(config.DirectoryURL)
	if !ok {
		return nil, ErrConfig
	}
	origins := map[string]bool{directory.Scheme + "://" + directory.Host: true}
	for _, value := range config.AdditionalOrigins {
		u, ok := endpoint(value)
		if !ok || u.Path != "" || u.RawQuery != "" || u.ForceQuery {
			return nil, ErrConfig
		}
		origins[value] = true
	}
	var contact []string
	if config.ContactEmail != "" {
		address, err := mail.ParseAddress(config.ContactEmail)
		if err != nil || address.Address != config.ContactEmail || address.Name != "" || len(config.ContactEmail) > 254 || strings.ContainsAny(config.ContactEmail, "\r\n\x00") {
			return nil, ErrConfig
		}
		contact = []string{"mailto:" + address.Address}
	}
	key := *config.Key
	key.D = new(big.Int).Set(config.Key.D)
	key.X, key.Y = new(big.Int).Set(config.Key.X), new(big.Int).Set(config.Key.Y)
	t := newTransport(origins, config.Roots)
	return &Client{gate: make(chan struct{}, 1), transport: t, contact: contact, key: &key, directory: config.DirectoryURL}, nil
}

func (c *Client) newSDK() *acme.Client {
	return &acme.Client{
		Key: c.key, DirectoryURL: c.directory, HTTPClient: c.transport.client(), UserAgent: "NetHub",
		// The durable job owns retry policy. An SDK retry must not multiply
		// attempts within one scheduler invocation.
		RetryBackoff: func(int, *http.Request, *http.Response) time.Duration { return 0 },
	}
}

func validKey(key *ecdsa.PrivateKey) bool {
	if key == nil || key.Curve != elliptic.P256() || key.D == nil || key.X == nil || key.Y == nil || key.D.Sign() <= 0 || key.D.Cmp(key.Curve.Params().N) >= 0 || !key.Curve.IsOnCurve(key.X, key.Y) {
		return false
	}
	x, y := key.Curve.ScalarBaseMult(key.D.Bytes())
	return x.Cmp(key.X) == 0 && y.Cmp(key.Y) == 0
}

// EnsureAccount looks up the existing key before considering registration. The
// same persisted key recovers a lost registration response without making a new
// account. No raw CA error, response body, URL or token leaves this boundary.
func (c *Client) EnsureAccount(ctx context.Context, registration Registration) (Account, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	case <-ctx.Done():
		return Account{}, ErrCancelled
	}
	if ctx.Err() != nil {
		return Account{}, ErrCancelled
	}
	if registration.ExpectedURI != "" && !c.transport.allowed(registration.ExpectedURI) {
		return Account{}, ErrConfig
	}
	// Discovery is fresh for each operation: cached old terms must never be
	// silently accepted after a CA changes its advertised agreement.
	sdk := c.newSDK()
	directory, err := sdk.Discover(ctx)
	if err != nil {
		return Account{}, remoteError(ctx)
	}
	for _, value := range []string{directory.RegURL, directory.OrderURL, directory.NonceURL} {
		if !c.transport.allowed(value) {
			return Account{}, ErrRemote
		}
	}
	for _, value := range []string{directory.RevokeURL, directory.KeyChangeURL, directory.AuthzURL} {
		if value != "" && !c.transport.allowed(value) {
			return Account{}, ErrRemote
		}
	}
	if directory.Terms != "" {
		if _, ok := endpoint(directory.Terms); !ok {
			return Account{}, ErrRemote
		}
	}
	account, err := sdk.GetReg(ctx, "")
	if errors.Is(err, acme.ErrNoAccount) {
		if registration.ExpectedURI != "" {
			return Account{}, ErrAccount
		}
		if !registration.AllowCreate || registration.AcceptedTermsURL != directory.Terms {
			return Account{}, ErrConsent
		}
		// External account binding needs a separate explicit credential workflow.
		if directory.ExternalAccountRequired {
			return Account{}, ErrAccount
		}
		account, err = sdk.Register(ctx, &acme.Account{Contact: c.contact}, func(terms string) bool {
			return terms == registration.AcceptedTermsURL
		})
		if errors.Is(err, acme.ErrAccountAlreadyExists) {
			account, err = sdk.GetReg(ctx, "")
		}
	}
	if err != nil {
		return Account{}, remoteError(ctx)
	}
	if account == nil || account.Status != acme.StatusValid || !c.transport.allowed(account.URI) || account.OrdersURL != "" && !c.transport.allowed(account.OrdersURL) || registration.ExpectedURI != "" && account.URI != registration.ExpectedURI {
		return Account{}, ErrAccount
	}
	return Account{URI: account.URI, OrdersURL: account.OrdersURL}, nil
}

func remoteError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ErrCancelled
	}
	return ErrRemote
}

func (c *Client) Close() { c.transport.base.CloseIdleConnections() }
