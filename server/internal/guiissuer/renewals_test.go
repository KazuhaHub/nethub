package guiissuer

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRenewalAdmissionBoundsPolicyAndPrivateOutput(t *testing.T) {
	calls := 0
	response := []byte("0")
	s := SQLStore{Domain: "devices.example.com", AllowsURL: func(string) bool { return true }, Run: func(_ context.Context, input []byte) ([]byte, error) {
		calls++
		if !strings.Contains(string(input), "SET SESSION AUTHORIZATION nethub_issuer;") ||
			!strings.Contains(string(input), "enqueue_due_gui_certificate_renewals('devices.example.com',convert_from(decode('") {
			t.Fatal("renewal escaped protected policy/SQL identity")
		}
		return response, nil
	}}
	for _, value := range []string{"0", "1"} {
		response = []byte(value)
		if _, err := s.EnqueueRenewals(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"", "2", "32", "-1", "01", "1\n1", "null", "sensitive diagnostic"} {
		response = []byte(value)
		if _, err := s.EnqueueRenewals(context.Background()); !errors.Is(err, ErrDatabase) {
			t.Fatal("ambiguous renewal count accepted")
		}
	}
	before := calls
	for _, domain := range []string{"", "127.0.0.1", "Devices.example.com", "devices.example.com'"} {
		s.Domain = domain
		if _, err := s.EnqueueRenewals(context.Background()); err != ErrDatabase || calls != before {
			t.Fatal("untrusted renewal policy entered SQL")
		}
	}
	s.Domain = "devices.example.com"
	s.Excluded = []string{"bad'host.example.com"}
	if _, err := s.EnqueueRenewals(context.Background()); err != ErrDatabase || calls != before {
		t.Fatal("invalid exclusion entered SQL")
	}
	s.Excluded = make([]string, 33)
	if _, err := s.EnqueueRenewals(context.Background()); err != ErrDatabase || calls != before {
		t.Fatal("unbounded exclusions entered SQL")
	}
	s.Excluded = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.EnqueueRenewals(ctx); err != ErrDatabase || calls != before {
		t.Fatal("cancelled renewal started SQL")
	}
}
