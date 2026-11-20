package guiacme

import "context"

// DNS01 contains private job metadata for an account-bound DNS challenge.
type DNS01 HTTP01

// Record returns the TXT owner and value for a pending authorization.
// A complete authorization does not need another record.
func (d DNS01) Record() (name, value string, required bool) {
	if d.Complete || d.URI == "" {
		return "", "", false
	}
	return "_acme-challenge." + d.Order.Host + ".", d.KeyAuthorization, true
}

// PrepareDNS01 derives a TXT proof for the saved order and bound device CSR.
func (s *AccountStore) PrepareDNS01(ctx context.Context, saved Order, csr []byte, boundKey string) (DNS01, error) {
	proof, err := s.prepareChallenge(ctx, saved, csr, boundKey, dnsChallenge)
	return DNS01(proof), err
}

// AcceptDNS01 rechecks the order and proof. The caller must first verify TXT
// publication and reauthorize the device's live assignment.
func (s *AccountStore) AcceptDNS01(ctx context.Context, saved DNS01, csr []byte, boundKey string) (DNS01, error) {
	proof, err := s.acceptChallenge(ctx, HTTP01(saved), csr, boundKey, dnsChallenge)
	return DNS01(proof), err
}
