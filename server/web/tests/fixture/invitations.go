package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/web"
)

type fixtureInvitation struct{ web.Invitation }

func (r *repository) invitationAdminLocked(actor string) error {
	u, ok := r.users[actor]
	if !ok || u.Disabled {
		return auth.ErrUnauthenticated
	}
	if u.Role != "admin" {
		return web.ErrForbidden
	}
	return nil
}

func (r *repository) resetInvitationsLocked() {
	r.users = fixtureUsers()
	r.sessions = map[string]auth.SessionRecord{}
	r.passwords = map[string]string{}
	r.invites = map[string]fixtureInvitation{}
	r.inviteSequence = 2000
	now := time.Now().UTC()
	for i := range 52 {
		digest := sha256.Sum256([]byte(fmt.Sprintf("pending-ui-invitation-%d", i)))
		r.invites[string(digest[:])] = fixtureInvitation{web.Invitation{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", 1000+i), Email: fmt.Sprintf("pending-%02d@example.com", i), Role: "member", CreatedAt: now, ExpiresAt: now.Add(72 * time.Hour), CreatedBy: web.Owner{ID: "00000000-0000-4000-8000-000000000001", Email: "ui-test@example.com"}}}
	}
}

func (r *repository) issueInvitationLocked(actor string, input web.InvitationInput) (web.IssuedInvitation, error) {
	if err := r.invitationAdminLocked(actor); err != nil {
		return web.IssuedInvitation{}, err
	}
	for _, user := range r.users {
		if user.Email == input.Email {
			return web.IssuedInvitation{}, web.ErrUserExists
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return web.IssuedInvitation{}, err
	}
	digest := sha256.Sum256(raw)
	r.inviteSequence++
	id := fmt.Sprintf("00000000-0000-4000-8000-%012d", r.inviteSequence)
	now := time.Now().UTC()
	r.invites[string(digest[:])] = fixtureInvitation{web.Invitation{ID: id, Email: input.Email, Role: input.Role, ProviderID: input.ProviderID, CreatedAt: now, ExpiresAt: now.Add(72 * time.Hour), CreatedBy: web.Owner{ID: actor, Email: r.users[actor].Email}}}
	return web.IssuedInvitation{ID: id, Token: base64.RawURLEncoding.EncodeToString(raw), ExpiresAt: now.Add(72 * time.Hour)}, nil
}
func (r *repository) IssueInvitation(_ context.Context, actor string, input web.InvitationInput, _ netip.Addr) (web.IssuedInvitation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.issueInvitationLocked(actor, input)
}
func (r *repository) Invitations(_ context.Context, actor string, query web.UserQuery) (web.InvitationPage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.invitationAdminLocked(actor); err != nil {
		return web.InvitationPage{}, err
	}
	page := web.InvitationPage{Items: []web.Invitation{}}
	for _, invite := range r.invites {
		if invite.ID > query.AfterID && invite.ExpiresAt.After(time.Now()) {
			page.Items = append(page.Items, invite.Invitation)
		}
	}
	sort.Slice(page.Items, func(i, j int) bool { return page.Items[i].ID < page.Items[j].ID })
	if len(page.Items) > query.Limit {
		page.Items = page.Items[:query.Limit]
		next := base64.RawURLEncoding.EncodeToString([]byte(page.Items[len(page.Items)-1].ID))
		page.NextCursor = &next
	}
	return page, nil
}
func (r *repository) WithdrawInvitation(_ context.Context, actor, id string, _ netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.invitationAdminLocked(actor); err != nil {
		return err
	}
	for digest, invite := range r.invites {
		if invite.ID == id {
			delete(r.invites, digest)
			return nil
		}
	}
	return auth.ErrInviteInvalid
}
func (r *repository) InspectInvitation(_ context.Context, digest []byte) (auth.InvitationInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	invite, ok := r.invites[string(digest)]
	if !ok || !invite.ExpiresAt.After(time.Now()) {
		return auth.InvitationInfo{}, auth.ErrInviteInvalid
	}
	info := auth.InvitationInfo{Email: invite.Email, Role: invite.Role, ExpiresAt: invite.ExpiresAt, PasswordAllowed: invite.ProviderID == nil, Providers: []auth.InvitationProvider{}}
	if invite.ProviderID != nil {
		if p, ok := r.providers[*invite.ProviderID]; ok && p.Enabled {
			info.Providers = append(info.Providers, auth.InvitationProvider{Slug: p.Slug, DisplayName: p.DisplayName, Kind: "oidc"})
		} else if p, ok := r.samlProviders[*invite.ProviderID]; ok && p.Enabled {
			info.Providers = append(info.Providers, auth.InvitationProvider{Slug: p.Slug, DisplayName: p.DisplayName, Kind: "saml"})
		} else {
			info.Providers = append(info.Providers, auth.InvitationProvider{Slug: "restricted", DisplayName: "Restricted", Kind: "oidc"})
		}
	}
	return info, nil
}
func (r *repository) AcceptInvitation(_ context.Context, digest []byte, hash string, record auth.SessionRecord) (auth.SessionRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	invite, ok := r.invites[string(digest)]
	if !ok || invite.ProviderID != nil || !invite.ExpiresAt.After(time.Now()) {
		return auth.SessionRecord{}, auth.ErrInviteInvalid
	}
	for _, user := range r.users {
		if user.Email == invite.Email {
			return auth.SessionRecord{}, auth.ErrInviteInvalid
		}
	}
	record.User = auth.User{ID: invite.ID, Email: invite.Email, Role: invite.Role}
	r.users[record.ID] = web.ManagedUser{User: record.User, HasPassword: true, Identities: []web.UserIdentity{}, CreatedAt: time.Now().UTC()}
	r.passwords[record.ID] = hash
	r.sessions[string(record.TokenHash)] = record
	delete(r.invites, string(digest))
	return record, nil
}
