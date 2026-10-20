package guiissuer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/netip"
)

// EnqueueRenewals visits at most 32 due candidates and admits one generation
// under its live assignment lock, matching the host's one-job invocation.
// Only the protected issuer calls this; polling and application reports never do.
// Existing work, including exhausted work, is retained rather than reissued.
func (s *SQLStore) EnqueueRenewals(ctx context.Context) (int, error) {
	if len(s.Domain) > 244 || !domainPattern.MatchString(s.Domain) || len(s.Excluded) > 32 {
		return 0, ErrDatabase
	}
	if _, err := netip.ParseAddr(s.Domain); err == nil {
		return 0, ErrDatabase
	}
	for _, host := range s.Excluded {
		if len(host) > 253 || !domainPattern.MatchString(host) {
			return 0, ErrDatabase
		}
	}
	excluded := s.Excluded
	if excluded == nil {
		excluded = []string{}
	}
	encoded, err := json.Marshal(excluded)
	if err != nil {
		return 0, ErrDatabase
	}
	// Domain syntax excludes SQL quoting; exclusions cross as encoded JSON data.
	body, err := s.query(ctx, "SELECT public.enqueue_due_gui_certificate_renewals('"+s.Domain+"',convert_from(decode('"+hex.EncodeToString(encoded)+"','hex'),'UTF8')::jsonb)")
	if err != nil || len(body) != 1 || body[0] < '0' || body[0] > '1' {
		return 0, ErrDatabase
	}
	return int(body[0] - '0'), nil
}
