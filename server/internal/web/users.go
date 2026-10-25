package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
)

var (
	ErrForbidden       = errors.New("administrator required")
	ErrUserUnavailable = errors.New("user unavailable")
	ErrLastAdmin       = errors.New("an enabled administrator must remain")
	ErrLastLocalAdmin  = errors.New("an enabled local-password administrator must remain")
)

type UserIdentity struct {
	ProviderSlug string    `json:"provider_slug"`
	LinkedAt     time.Time `json:"linked_at"`
}

type ManagedUser struct {
	auth.User
	Disabled    bool           `json:"disabled"`
	HasPassword bool           `json:"has_password"`
	Identities  []UserIdentity `json:"identities"`
	CreatedAt   time.Time      `json:"created_at"`
}

type UserQuery struct {
	Limit   int
	AfterID string
}
type UserPage struct {
	Items      []ManagedUser `json:"items"`
	NextCursor *string       `json:"next_cursor"`
}
type UserPatch struct {
	Role     *string
	Disabled *bool
}

// UserRepository rechecks the active administrator inside each transaction.
type UserRepository interface {
	Users(context.Context, string, UserQuery) (UserPage, error)
	UpdateUser(context.Context, string, string, UserPatch, netip.Addr) (ManagedUser, error)
}

func (s *Server) adminSession(w http.ResponseWriter, r *http.Request, mutate bool) (auth.Session, bool) {
	var session auth.Session
	var ok bool
	if mutate {
		session, _, ok = s.mutation(w, r)
	} else {
		session, _, ok = s.authenticate(w, r)
	}
	if !ok {
		return auth.Session{}, false
	}
	if session.User.Role != "admin" {
		writeError(w, r, 403, "forbidden", "Administrator access required")
		return auth.Session{}, false
	}
	return session, true
}

func (s *Server) userError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, auth.ErrUnauthenticated):
		writeError(w, r, 401, "unauthenticated", "Sign in to continue")
	case errors.Is(err, ErrForbidden):
		writeError(w, r, 403, "forbidden", "Administrator access required")
	case errors.Is(err, ErrUserUnavailable):
		writeError(w, r, 404, "not_found", "User unavailable")
	case errors.Is(err, ErrLastAdmin):
		writeError(w, r, 409, "last_admin", "An enabled administrator must remain")
	case errors.Is(err, ErrLastLocalAdmin):
		writeError(w, r, 409, "last_local_admin", "An enabled local-password administrator must remain")
	default:
		s.internal(w, r, "user administration")
	}
}

func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	session, ok := s.adminSession(w, r, false)
	if !ok {
		return
	}
	values, err := netURLQuery(r)
	if err != nil {
		writeError(w, r, 400, "invalid_request", "Invalid user query")
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
			decoded, e := base64.RawURLEncoding.Strict().DecodeString(list[0])
			if e != nil || len(list[0]) > 64 || !uuidPattern.Match(decoded) {
				writeError(w, r, 400, "invalid_request", "Invalid user cursor")
				return
			}
			query.AfterID = string(decoded)
		default:
			writeError(w, r, 400, "invalid_request", "Unknown user query parameter")
			return
		}
	}
	page, err := s.repository.Users(r.Context(), session.User.ID, query)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	writeJSON(w, r, 200, page)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	session, ok := s.adminSession(w, r, true)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, prefix+"/users/")
	if !uuidPattern.MatchString(id) || r.URL.RawQuery != "" {
		writeError(w, r, 400, "invalid_request", "A canonical user ID is required")
		return
	}
	var input struct {
		Role     json.RawMessage `json:"role"`
		Disabled json.RawMessage `json:"disabled"`
	}
	if !readJSON(w, r, &input, "role", "disabled") {
		return
	}
	var patch UserPatch
	if input.Role != nil {
		var role string
		if json.Unmarshal(input.Role, &role) != nil || (role != "admin" && role != "member") {
			writeError(w, r, 400, "invalid_request", "Role must be admin or member")
			return
		}
		patch.Role = &role
	}
	if input.Disabled != nil {
		var disabled bool
		if bytes.Equal(bytes.TrimSpace(input.Disabled), []byte("null")) || json.Unmarshal(input.Disabled, &disabled) != nil {
			writeError(w, r, 400, "invalid_request", "Disabled must be a boolean")
			return
		}
		patch.Disabled = &disabled
	}
	if patch.Role == nil && patch.Disabled == nil {
		writeError(w, r, 400, "invalid_request", "Provide role or disabled")
		return
	}
	user, err := s.repository.UpdateUser(r.Context(), session.User.ID, id, patch, ip.Unmap())
	if err != nil {
		s.userError(w, r, err)
		return
	}
	writeJSON(w, r, 200, user)
}
