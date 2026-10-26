package main

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"testing"

	authoidc "github.com/KazuhaHub/authcore/oidc"
	"github.com/KazuhaHub/nethub/server/internal/sso"
)

func TestProviderDiagnosticNeverReturnsRawErrors(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{nil, "none"},
		{&net.DNSError{Err: "private-token", Name: "private-host"}, "dns"},
		{x509.UnknownAuthorityError{}, "certificate_authority"},
		{sso.ErrOutbound, "console_outbound"},
		{authoidc.ErrDiscovery, "console_discovery"},
		{authoidc.ErrUnsupportedAuthMethod, "console_auth_method"},
		{authoidc.ErrInvalidConfig, "console_configuration"},
		{errors.New("private-secret"), "transport_or_protocol"},
	} {
		err := test.err
		if err != nil {
			err = fmt.Errorf("private-wrapper: %w", err)
		}
		if got := diagnosticError(err); got != test.want {
			t.Fatal("diagnostic returned a non-fixed error category")
		}
	}
	for _, target := range [][2]string{{"relative", "one"}, {t.TempDir(), "unknown"}} {
		var out bytes.Buffer
		if err := checkProvider(target[0], target[1], &out); err == nil || out.Len() != 0 {
			t.Fatal("invalid provider diagnostic target was used")
		}
	}
}
