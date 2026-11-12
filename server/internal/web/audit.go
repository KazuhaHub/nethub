package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ErrAuditInput = errors.New("invalid audit query")
var auditAction = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,99}$`)

type AuditQuery struct {
	Action, DeviceID, UserID, Cursor string
	Since, Until                     *time.Time
	Limit                            int
}

type AuditDetails struct {
	TargetUserID    *string    `json:"target_user_id,omitempty"`
	Role            *string    `json:"role,omitempty"`
	Disabled        *bool      `json:"disabled,omitempty"`
	SessionsRevoked *int64     `json:"sessions_revoked,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	RequestID       *string    `json:"request_id,omitempty"`
}

type AuditEntry struct {
	ID             string       `json:"id"`
	CreatedAt      time.Time    `json:"created_at"`
	ActorType      string       `json:"actor_type"`
	Actor          *string      `json:"actor"`
	Action         string       `json:"action"`
	TargetDeviceID *string      `json:"target_device_id"`
	ClientIP       *string      `json:"client_ip,omitempty"`
	Details        AuditDetails `json:"details"`
}

type AuditPage struct {
	Items      []AuditEntry `json:"items"`
	NextCursor *string      `json:"next_cursor"`
}

type AuditRepository interface {
	Audit(context.Context, string, AuditQuery) (AuditPage, error)
}

func (q AuditQuery) Valid() bool {
	if q.Limit < 1 || q.Limit > 200 || len(q.Cursor) > 256 ||
		(q.Action != "" && !auditAction.MatchString(q.Action)) ||
		(q.DeviceID != "" && !uuidPattern.MatchString(q.DeviceID)) ||
		(q.UserID != "" && !uuidPattern.MatchString(q.UserID)) {
		return false
	}
	for _, stamp := range []*time.Time{q.Since, q.Until} {
		if stamp != nil && (stamp.IsZero() || stamp.Year() < 1 || stamp.Year() > 9999) {
			return false
		}
	}
	return q.Since == nil || q.Until == nil || q.Since.Before(*q.Until)
}

func auditFingerprint(scope string, q AuditQuery) string {
	// Bind cursors to authority and filters while allowing page-size changes.
	q.Cursor, q.Limit = "", 0
	if q.Since != nil {
		value := q.Since.UTC()
		q.Since = &value
	}
	if q.Until != nil {
		value := q.Until.UTC()
		q.Until = &value
	}
	raw, _ := json.Marshal(struct {
		Scope string
		Query AuditQuery
	}{scope, q})
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func AuditCursor(scope string, q AuditQuery, before int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte("1:" + auditFingerprint(scope, q) + ":" + strconv.FormatInt(before, 10)))
}

func AuditBefore(scope string, q AuditQuery) (int64, error) {
	if !q.Valid() {
		return 0, ErrAuditInput
	}
	if q.Cursor == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(q.Cursor)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != q.Cursor {
		return 0, ErrAuditInput
	}
	parts := strings.Split(string(raw), ":")
	if len(parts) != 3 || parts[0] != "1" || parts[1] != auditFingerprint(scope, q) {
		return 0, ErrAuditInput
	}
	value, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || value <= 0 || strconv.FormatInt(value, 10) != parts[2] {
		return 0, ErrAuditInput
	}
	return value, nil
}

func (s *Server) auditReport(w http.ResponseWriter, r *http.Request) {
	session, _, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	query := AuditQuery{Limit: 50}
	values, err := netURLQuery(r)
	if err == nil {
		for key, list := range values {
			if len(list) != 1 {
				err = ErrAuditInput
				break
			}
			value := list[0]
			switch key {
			case "action":
				query.Action = value
			case "device_id":
				query.DeviceID = value
			case "user_id":
				query.UserID = value
			case "cursor":
				query.Cursor = value
			case "limit":
				query.Limit, err = strconv.Atoi(value)
				if err == nil && strconv.Itoa(query.Limit) != value {
					err = ErrAuditInput
				}
			case "since", "until":
				var stamp time.Time
				stamp, err = time.Parse(time.RFC3339Nano, value)
				stamp = stamp.UTC()
				if key == "since" {
					query.Since = &stamp
				} else {
					query.Until = &stamp
				}
			default:
				err = ErrAuditInput
			}
			if err != nil || value == "" {
				err = ErrAuditInput
				break
			}
		}
	}
	if err != nil || !query.Valid() {
		writeError(w, r, 400, "invalid_request", "Invalid audit filters, limit or cursor")
		return
	}
	if query.UserID != "" && session.User.Role != "admin" {
		writeError(w, r, 403, "forbidden", "Administrator access required")
		return
	}
	page, err := s.repository.Audit(r.Context(), session.User.ID, query)
	if errors.Is(err, ErrAuditInput) {
		writeError(w, r, 400, "invalid_request", "Audit cursor does not match these filters")
		return
	}
	if err != nil {
		s.userError(w, r, err)
		return
	}
	for index := range page.Items {
		entry := &page.Items[index]
		if session.User.Role != "admin" && (entry.ActorType != "user" || entry.Actor == nil || *entry.Actor != session.User.ID) {
			entry.ClientIP = nil
		}
	}
	writeJSON(w, r, 200, page)
}
