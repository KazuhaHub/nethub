package web

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

type Owner struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type Device struct {
	ID                   string               `json:"id"`
	Label                string               `json:"label"`
	Hostname             string               `json:"hostname"`
	Subdomain            string               `json:"subdomain"`
	URL                  string               `json:"url"`
	Platform             string               `json:"platform"`
	PlatformVersion      string               `json:"platform_version"`
	AgentVersion         string               `json:"agent_version"`
	Capabilities         []string             `json:"capabilities"`
	ClusterHint          *string              `json:"cluster_hint"`
	Online               bool                 `json:"online"`
	LastSeenAt           *time.Time           `json:"last_seen_at"`
	EnrolledAt           time.Time            `json:"enrolled_at"`
	Revoked              bool                 `json:"revoked"`
	RevokedAt            *time.Time           `json:"revoked_at"`
	Owner                Owner                `json:"owner"`
	ServiceState         *string              `json:"service_state"`
	LastReportAt         *time.Time           `json:"last_report_at"`
	LastReconcileSuccess *bool                `json:"last_reconcile_success"`
	LastReconcileAt      *time.Time           `json:"last_reconcile_at"`
	GUICertificate       GUICertificateStatus `json:"gui_certificate"`
	Disconnect           *DeviceDisconnect    `json:"disconnect"`
}

// GUICertificateStatus describes an authenticated installation report, not an
// independently verified relayed TLS connection.
type GUICertificateStatus struct {
	State        string     `json:"state"`
	AssignedHost *string    `json:"assigned_host"`
	ValidUntil   *time.Time `json:"valid_until"`
	ConfirmedAt  *time.Time `json:"confirmed_at"`
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

var ErrDeviceUnavailable = errors.New("device unavailable")
var ErrDeviceRevoked = errors.New("device revoked")
var ErrDeviceNotRevoked = errors.New("device is not revoked")

type DeviceAccess struct {
	Subdomain string    `json:"-"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"gate_expires_at"`
}

type DeviceRevocation struct {
	Revoked   bool      `json:"revoked"`
	RevokedAt time.Time `json:"revoked_at"`
}

type DeviceDisconnect struct {
	RequestID   string     `json:"request_id"`
	RequestedAt time.Time  `json:"requested_at"`
	ArmedAt     *time.Time `json:"armed_at"`
	State       string     `json:"state"`
}

// Repository is tenant-bound at startup; HTTP cannot choose the tenant or pass
// an authorization role. Implementations recheck the active actor in SQL.
type Repository interface {
	Health(context.Context) error
	Devices(context.Context, string, DeviceQuery) (DevicePage, error)
	IssueEnrollToken(context.Context, string, netip.Addr) (EnrollToken, error)
	OpenDevice(context.Context, string, string, netip.Addr) (DeviceAccess, error)
	RevokeDevice(context.Context, string, string, netip.Addr) (DeviceRevocation, error)
	RequestDisconnect(context.Context, string, string, netip.Addr) (DeviceDisconnect, error)
	LoginFailed(context.Context, netip.Addr) error
}
