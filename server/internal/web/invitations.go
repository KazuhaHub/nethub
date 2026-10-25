package web

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
)

func (s *Server) invitationError(w http.ResponseWriter, r *http.Request, err error) {
	if s.rateFailure(w, r, err) {
		return
	}
	switch {
	case errors.Is(err, auth.ErrInviteInvalid):
		writeError(w, r, 404, "invite_invalid", "Invitation unavailable")
	case errors.Is(err, auth.ErrWeakPassword):
		writeError(w, r, 422, "weak_password", "Use at least 15 characters and at most 1024 UTF-8 bytes, without line endings or NUL")
	case errors.Is(err, ErrUserExists):
		writeError(w, r, 409, "user_exists", "An account with this email already exists")
	case errors.Is(err, ErrInviteProviderUnavailable):
		writeError(w, r, 404, "provider_unavailable", "Provider unavailable")
	case errors.Is(err, auth.ErrUnauthenticated):
		writeError(w, r, 401, "unauthenticated", "Sign in to continue")
	case errors.Is(err, ErrForbidden):
		writeError(w, r, 403, "forbidden", "Administrator access required")
	default:
		s.internal(w, r, "invitation")
	}
}

func (s *Server) issueInvitation(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	session, ok := s.adminSession(w, r, true)
	if !ok {
		return
	}
	var input InvitationInput
	if !readJSON(w, r, &input, "email", "role", "provider_id") {
		return
	}
	email, err := auth.NormalizeEmail(input.Email)
	if err != nil || (input.Role != "admin" && input.Role != "member") || (input.ProviderID != nil && !uuidPattern.MatchString(*input.ProviderID)) || r.URL.RawQuery != "" {
		writeError(w, r, 400, "invalid_request", "Provide a valid email, role and optional provider ID")
		return
	}
	input.Email = email
	result, err := s.repository.IssueInvitation(r.Context(), session.User.ID, input, ip.Unmap())
	if err != nil {
		s.invitationError(w, r, err)
		return
	}
	if _, err = auth.InvitationDigest(result.Token); err != nil || !uuidPattern.MatchString(result.ID) || !result.ExpiresAt.After(time.Now()) {
		s.internal(w, r, "invitation response")
		return
	}
	writeJSON(w, r, 201, map[string]any{"id": result.ID, "invite_url": "https://" + s.host + "/invite#" + result.Token, "expires_at": result.ExpiresAt})
}

func (s *Server) invitations(w http.ResponseWriter, r *http.Request) {
	session, ok := s.adminSession(w, r, false)
	if !ok {
		return
	}
	values, err := netURLQuery(r)
	if err != nil {
		writeError(w, r, 400, "invalid_request", "Invalid invitation query")
		return
	}
	query := UserQuery{Limit: 50}
	for key, list := range values {
		if len(list) != 1 {
			writeError(w, r, 400, "invalid_request", "Repeated query parameter")
			return
		}
		switch key {
		case "limit":
			query.Limit, err = strconv.Atoi(list[0])
			if err != nil || query.Limit < 1 || query.Limit > 200 {
				writeError(w, r, 400, "invalid_request", "Limit must be between 1 and 200")
				return
			}
		case "cursor":
			value, e := base64.RawURLEncoding.Strict().DecodeString(list[0])
			if e != nil || len(list[0]) > 64 || !uuidPattern.Match(value) {
				writeError(w, r, 400, "invalid_request", "Invalid invitation cursor")
				return
			}
			query.AfterID = string(value)
		default:
			writeError(w, r, 400, "invalid_request", "Unknown invitation query parameter")
			return
		}
	}
	page, err := s.repository.Invitations(r.Context(), session.User.ID, query)
	if err != nil {
		s.invitationError(w, r, err)
		return
	}
	writeJSON(w, r, 200, page)
}

func (s *Server) withdrawInvitation(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	session, ok := s.adminSession(w, r, true)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, prefix+"/invites/")
	if !uuidPattern.MatchString(id) || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		writeError(w, r, 400, "invalid_request", "A canonical invitation ID and no body are required")
		return
	}
	if err := s.repository.WithdrawInvitation(r.Context(), session.User.ID, id, ip.Unmap()); err != nil {
		s.invitationError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) inspectInvitation(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	if !s.origin.Check(r, true) {
		writeError(w, r, 403, "csrf_failed", "A matching console Origin is required")
		return
	}
	if r.URL.RawQuery != "" {
		writeError(w, r, 400, "invalid_request", "Invitation requests do not accept query parameters")
		return
	}
	var input struct {
		Token string `json:"token"`
	}
	if !readJSON(w, r, &input, "token") {
		return
	}
	digest, err := auth.InvitationDigest(input.Token)
	if s.rateFailure(w, r, s.inviteInspectLimits.Allow(ip, hex.EncodeToString(digest), time.Now())) {
		return
	}
	if err != nil {
		s.invitationError(w, r, err)
		return
	}
	info, err := s.repository.InspectInvitation(r.Context(), digest)
	if err != nil {
		s.invitationError(w, r, err)
		return
	}
	writeJSON(w, r, 200, info)
}

func (s *Server) acceptInvitation(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	if !s.origin.Check(r, true) {
		writeError(w, r, 403, "csrf_failed", "A matching console Origin is required")
		return
	}
	if r.URL.RawQuery != "" {
		writeError(w, r, 400, "invalid_request", "Invitation requests do not accept query parameters")
		return
	}
	var input struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &input, "token", "password") {
		return
	}
	if input.Token == "" || input.Password == "" {
		writeError(w, r, 400, "invalid_request", "Invitation token and password are required")
		return
	}
	result, err := s.auth.AcceptInvitation(r.Context(), input.Token, input.Password, ip.Unmap(), r.UserAgent())
	if errors.Is(err, auth.ErrInviteInvalid) {
		if auditErr := s.repository.InvitationFailed(r.Context(), ip.Unmap()); auditErr != nil {
			s.internal(w, r, "invitation failure audit")
			return
		}
	}
	if err != nil {
		s.invitationError(w, r, err)
		return
	}
	http.SetCookie(w, auth.SessionCookie(result.Token, result.ExpiresAt))
	writeJSON(w, r, 200, result.Session)
}
