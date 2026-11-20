package setup

import (
	"context"
	"errors"
	"net"
	"slices"
	"time"
)

// manualGUIPublisher observes operator-managed DNS. The CA independently
// resolves the authoritative record before authorizing the device name.
type manualGUIPublisher struct {
	lookup func(context.Context, string) ([]string, error)
	record func(GUIIssuerTXT)
}

func (p manualGUIPublisher) PublishTXT(ctx context.Context, name, value, _ string, expires time.Time) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if !expires.After(time.Now()) {
		return false, ErrGUIIssuer
	}
	records, err := p.lookup(ctx, name)
	var dnsErr *net.DNSError
	if err != nil && (!errors.As(err, &dnsErr) || !dnsErr.IsNotFound) {
		return false, ErrGUIIssuer
	}
	if err == nil && slices.Contains(records, value) {
		return true, nil
	}
	if p.record != nil {
		p.record(GUIIssuerTXT{Name: name, Value: value, Action: "add"})
	}
	return false, nil
}

func (p manualGUIPublisher) RemoveTXT(_ context.Context, name, value, _ string) error {
	if p.record != nil {
		p.record(GUIIssuerTXT{Name: name, Value: value, Action: "remove"})
	}
	return nil
}
