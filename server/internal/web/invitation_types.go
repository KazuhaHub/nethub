package web

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
)

var (
	ErrUserExists                = errors.New("account already exists")
	ErrInviteProviderUnavailable = errors.New("invitation provider unavailable")
)

type InvitationInput struct {
	Email      string  `json:"email"`
	Role       string  `json:"role"`
	ProviderID *string `json:"provider_id"`
}

type Invitation struct {
	ID         string    `json:"id"`
	Email      string    `json:"email"`
	Role       string    `json:"role"`
	ProviderID *string   `json:"provider_id"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedBy  Owner     `json:"created_by"`
}

type InvitationPage struct {
	Items      []Invitation `json:"items"`
	NextCursor *string      `json:"next_cursor"`
}

type IssuedInvitation struct {
	ID        string
	Token     string `json:"-"`
	ExpiresAt time.Time
}

type InvitationRepository interface {
	Invitations(context.Context, string, UserQuery) (InvitationPage, error)
	IssueInvitation(context.Context, string, InvitationInput, netip.Addr) (IssuedInvitation, error)
	WithdrawInvitation(context.Context, string, string, netip.Addr) error
	InspectInvitation(context.Context, []byte) (auth.InvitationInfo, error)
	InvitationFailed(context.Context, netip.Addr) error
}
