package protocol

type Identity struct {
	AgentProtocolVersion string `json:"agent_protocol_version"`
	DeviceID             string `json:"device_id"`
}

type UnenrollRequest = Identity

type UnenrollResponse struct {
	Identity
	Revoked bool `json:"revoked"`
}

type StatusRequest struct {
	Identity
	PlatformVersion      string  `json:"platform_version"`
	AgentVersion         string  `json:"agent_version"`
	ServiceState         string  `json:"service_state"`
	LastReconcileSuccess *bool   `json:"last_reconcile_success"`
	LastReconcileAt      *string `json:"last_reconcile_at"`
}

type StatusResponse struct {
	Identity
	Accepted bool `json:"accepted"`
	Revoked  bool `json:"revoked"`
}

// ClaimPayload field order is part of the canonical signature representation.
type ClaimPayload struct {
	DeviceID  string `json:"device_id"`
	Subdomain string `json:"subdomain"`
	TenantID  string `json:"tenant_id"`
	IssuedAt  string `json:"issued_at"`
	KeyID     string `json:"key_id"`
}
