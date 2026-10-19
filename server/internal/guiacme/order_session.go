package guiacme

import (
	"context"
	"os"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guicert"
	"golang.org/x/crypto/acme"
)

// Each scheduler operation owns one bounded account lease and SDK lifetime.
// The key and raw SDK are deliberately confined to this package.
type orderSession struct {
	ctx       context.Context
	cancel    context.CancelFunc
	lease     *os.File
	client    *Client
	sdk       *acme.Client
	directory acme.Directory
	request   guicert.Request
}

func (session *orderSession) close() {
	if session.client != nil {
		session.client.Close()
	}
	if session.lease != nil {
		accountRelease(session.lease)
	}
	session.cancel()
}

func (s *AccountStore) openOrder(ctx context.Context, uri string, csr []byte, host, boundKey string) (_ *orderSession, err error) {
	session := &orderSession{}
	session.ctx, session.cancel = context.WithTimeout(ctx, 45*time.Second)
	defer func() {
		if err != nil {
			session.close()
		}
	}()
	if session.ctx.Err() != nil {
		return nil, ErrCancelled
	}
	session.request, err = guicert.ValidateBoundCSR(csr, host, boundKey)
	if err != nil {
		return nil, ErrOrder
	}
	session.lease, err = s.lease(false)
	if err != nil {
		return nil, err
	}
	state, key, err := s.load()
	if err != nil {
		return nil, err
	}
	// Jobs cannot initialize, replace or register the durable account identity.
	if state.URI == "" {
		return nil, ErrAccount
	}
	config := s.config
	config.Key = key
	session.client, err = New(config)
	if err != nil {
		return nil, ErrState
	}
	if uri != "" && !session.client.transport.allowed(uri) {
		return nil, ErrOrder
	}
	account, err := session.client.EnsureAccount(session.ctx, Registration{ExpectedURI: state.URI})
	if err != nil {
		return nil, err
	}
	session.sdk = session.client.newSDK()
	session.sdk.KID = acme.KeyID(account.URI)
	session.directory, err = session.sdk.Discover(session.ctx)
	if err != nil {
		return nil, remoteError(session.ctx)
	}
	if len(session.directory.Profiles) > 32 {
		return nil, ErrOrder
	}
	return session, nil
}
