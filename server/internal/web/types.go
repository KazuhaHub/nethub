package web

import (
	"context"
	"net/netip"
	"time"
)

type Owner struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type Device struct {
	ID              string     `json:"id"`
	Label           string     `json:"label"`
	Hostname        string     `json:"hostname"`
	Subdomain       string     `json:"subdomain"`
	URL             string     `json:"url"`
	Platform        string     `json:"platform"`
	PlatformVersion string     `json:"platform_version"`
	AgentVersion    string     `json:"agent_version"`
	Capabilities    []string   `json:"capabilities"`
	ClusterHint     *string    `json:"cluster_hint"`
	Online          bool       `json:"online"`
	LastSeenAt      *time.Time `json:"last_seen_at"`
	EnrolledAt      time.Time  `json:"enrolled_at"`
	Revoked         bool       `json:"revoked"`
	RevokedAt       *time.Time `json:"revoked_at"`
	Owner           Owner      `json:"owner"`
}

type DeviceQuery struct {
	Limit           int
	AfterID         string
	Online, Revoked *bool
}

type DevicePage struct {
	Items      []Device `json:"items"`
	NextCursor *string  `json:"next_cursor"`
}

type EnrollToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Repository is tenant-bound at startup; HTTP cannot choose the tenant or pass
// an authorization role. Implementations recheck the active actor in SQL.
type Repository interface {
	Health(context.Context) error
	Devices(context.Context, string, DeviceQuery) (DevicePage, error)
	IssueEnrollToken(context.Context, string, netip.Addr) (EnrollToken, error)
	LoginFailed(context.Context, netip.Addr) error
}
