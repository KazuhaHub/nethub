package relayhook

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
)

type sourceRepository struct {
	calls int
	check func(context.Context, protocol.ClaimPayload, netip.Addr) error
}

func (r *sourceRepository) Authorize(context.Context, protocol.ClaimPayload) error {
	return errors.New("connection used identity-only authorization")
}
func (r *sourceRepository) AuthorizeConnection(ctx context.Context, identity protocol.ClaimPayload, ip netip.Addr) error {
	r.calls++
	return r.check(ctx, identity, ip)
}

func TestNewUserConnBindsSignedRouteAndActualSource(t *testing.T) {
	for _, remote := range []string{"192.0.2.100:42000", "[::ffff:192.0.2.100]:42000", "[2001:db8::100]:42000"} {
		t.Run(remote, func(t *testing.T) {
			repository := &sourceRepository{check: func(ctx context.Context, p protocol.ClaimPayload, ip netip.Addr) error {
				parsed, _ := netip.ParseAddrPort(remote)
				if ip != parsed.Addr().Unmap() || p.DeviceID != "11111111-1111-4111-8111-111111111111" {
					t.Fatal("source or signed device binding changed")
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("connection authorization had no internal deadline")
				}
				return nil
			}}
			var logs bytes.Buffer
			server, encoded := fixture(t, repository, &logs)
			object := envelope("NewUserConn", encoded)
			object["content"].(map[string]any)["remote_addr"] = remote
			r := request(t, object)
			r.Header.Set("X-Forwarded-For", "203.0.113.100")
			outcome(t, server, r, false, 200)
			if repository.calls != 1 {
				t.Fatal("source authorization was bypassed")
			}
			for _, private := range []string{remote, encoded, "private-run-id-fixture", "203.0.113.100"} {
				if bytes.Contains(logs.Bytes(), []byte(private)) {
					t.Fatal("connection diagnostics exposed protected input")
				}
			}
		})
	}
}

func TestNewUserConnRejectsInvalidSourceAndRouteBeforeStorage(t *testing.T) {
	for _, change := range []struct{ field, value string }{
		{"proxy_name", ProxyName("33333333-3333-4333-8333-333333333333")}, {"proxy_type", "tcp"},
		{"remote_addr", "192.0.2.100"}, {"remote_addr", "192.0.2.100:0"}, {"remote_addr", "192.0.2.100:70000"},
		{"remote_addr", "192.0.2.0/24:123"}, {"remote_addr", "hostname.example.com:123"}, {"remote_addr", "[fe80::1%test]:123"},
		{"remote_addr", "0.0.0.0:123"}, {"remote_addr", "224.0.0.1:123"},
		{"remote_addr", "[::ffff:0.0.0.0]:123"}, {"remote_addr", "[::ffff:224.0.0.1]:123"},
	} {
		t.Run(change.field+"/"+change.value, func(t *testing.T) {
			repository := &sourceRepository{check: func(context.Context, protocol.ClaimPayload, netip.Addr) error { return nil }}
			server, encoded := fixture(t, repository, io.Discard)
			object := envelope("NewUserConn", encoded)
			object["content"].(map[string]any)[change.field] = change.value
			outcome(t, server, request(t, object), true, 200)
			if repository.calls != 0 {
				t.Fatal("invalid connection reached the database")
			}
		})
	}
}

func TestNewUserConnDeniesMissingGrantAndUnavailableStorage(t *testing.T) {
	for _, failure := range []error{ErrDenied, ErrUnavailable, errors.New("private dependency diagnostic")} {
		repository := &sourceRepository{check: func(context.Context, protocol.ClaimPayload, netip.Addr) error { return failure }}
		var logs bytes.Buffer
		server, encoded := fixture(t, repository, &logs)
		outcome(t, server, request(t, envelope("NewUserConn", encoded)), true, 200)
		if repository.calls != 1 || bytes.Contains(logs.Bytes(), []byte("private dependency diagnostic")) {
			t.Fatal("connection denial was bypassed or exposed its cause")
		}
	}
}
