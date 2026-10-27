package web

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/traffic"
)

type TrafficQuery struct {
	Month, AfterID string
	Limit          int
}

type TrafficDevice struct {
	DeviceID        string    `json:"device_id"`
	Label           string    `json:"label"`
	Hostname        string    `json:"hostname"`
	Removed         bool      `json:"removed"`
	InBytes         string    `json:"in_bytes"`
	OutBytes        string    `json:"out_bytes"`
	TotalBytes      string    `json:"total_bytes"`
	ResetEvents     string    `json:"reset_events"`
	FirstObservedAt time.Time `json:"first_observed_at"`
	LastObservedAt  time.Time `json:"last_observed_at"`
}

type TrafficPage struct {
	Month           string          `json:"month"`
	InBytes         string          `json:"in_bytes"`
	OutBytes        string          `json:"out_bytes"`
	TotalBytes      string          `json:"total_bytes"`
	ResetEvents     string          `json:"reset_events"`
	FirstObservedAt *time.Time      `json:"first_observed_at"`
	LastObservedAt  *time.Time      `json:"last_observed_at"`
	WarningBytes    *string         `json:"warning_bytes"`
	Warning         bool            `json:"warning"`
	WarningRevision int64           `json:"warning_revision"`
	Items           []TrafficDevice `json:"items"`
	NextCursor      *string         `json:"next_cursor"`
}

type TrafficRepository interface {
	Traffic(context.Context, string, TrafficQuery) (TrafficPage, error)
	SetTrafficWarning(context.Context, string, string, int64, netip.Addr) (TrafficWarning, error)
}

var ErrTrafficChanged = errors.New("traffic warning changed")

type TrafficWarning struct {
	WarningBytes *string `json:"warning_bytes"`
	Revision     int64   `json:"revision"`
}

func (s *Server) trafficReport(w http.ResponseWriter, r *http.Request) {
	session, ok := s.adminSession(w, r, false)
	if !ok {
		return
	}
	values, err := netURLQuery(r)
	query := TrafficQuery{Month: time.Now().UTC().Format("2006-01"), Limit: 50}
	if err == nil {
		for key, list := range values {
			if len(list) != 1 {
				err = ErrProviderInput
				break
			}
			switch key {
			case "month":
				query.Month = list[0]
				if !traffic.ValidMonth(query.Month) {
					err = ErrProviderInput
				}
			case "limit":
				query.Limit, err = strconv.Atoi(list[0])
				if query.Limit < 1 || query.Limit > 200 {
					err = ErrProviderInput
				}
			case "cursor":
				var decoded []byte
				decoded, err = base64.RawURLEncoding.Strict().DecodeString(list[0])
				if len(list[0]) > 64 || !uuidPattern.Match(decoded) {
					err = ErrProviderInput
				}
				query.AfterID = string(decoded)
			default:
				err = ErrProviderInput
			}
			if err != nil {
				break
			}
		}
	}
	if err != nil {
		writeError(w, r, 400, "invalid_request", "Use a canonical month, limit and traffic cursor")
		return
	}
	page, err := s.repository.Traffic(r.Context(), session.User.ID, query)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	if page.Month != query.Month || !traffic.Consistent(page.InBytes, page.OutBytes, page.TotalBytes) {
		s.internal(w, r, "traffic projection")
		return
	}
	threshold := ""
	if page.WarningBytes != nil {
		threshold = *page.WarningBytes
	}
	page.WarningBytes, page.Warning, err = traffic.Warning(page.TotalBytes, threshold)
	if err != nil {
		s.internal(w, r, "traffic warning")
		return
	}
	writeJSON(w, r, 200, page)
}

func (s *Server) setTrafficWarning(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	session, ok := s.adminSession(w, r, true)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		writeError(w, r, 400, "invalid_request", "Traffic settings do not accept query parameters")
		return
	}
	var input struct {
		WarningBytes     *string `json:"warning_bytes"`
		ExpectedRevision *int64  `json:"expected_revision"`
	}
	if !readJSON(w, r, &input, "warning_bytes", "expected_revision") {
		return
	}
	if input.WarningBytes == nil || *input.WarningBytes == "" || !traffic.ValidWarning(*input.WarningBytes) || input.ExpectedRevision == nil || *input.ExpectedRevision < 0 || *input.ExpectedRevision > 9007199254740991 {
		writeError(w, r, 400, "invalid_request", "Provide whole decimal warning bytes and the current settings revision; zero disables warnings")
		return
	}
	result, err := s.repository.SetTrafficWarning(r.Context(), session.User.ID, *input.WarningBytes, *input.ExpectedRevision, ip.Unmap())
	if errors.Is(err, ErrTrafficChanged) {
		writeError(w, r, 409, "traffic_changed", "The warning changed; reload before editing")
		return
	}
	if err != nil {
		s.userError(w, r, err)
		return
	}
	writeJSON(w, r, 200, result)
}
