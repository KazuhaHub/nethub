-- +goose Up
CREATE TABLE oidc_flows (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    provider_id uuid NOT NULL,
    provider_revision bigint NOT NULL CHECK (provider_revision > 0),
    state_hash bytea NOT NULL UNIQUE CHECK (octet_length(state_hash)=32),
    browser_hash bytea NOT NULL CHECK (octet_length(browser_hash)=32),
    invitation_hash bytea CHECK (invitation_hash IS NULL OR octet_length(invitation_hash)=32),
    protocol_state_enc bytea,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    admitted_at timestamptz,
    CHECK (expires_at>created_at AND expires_at<=created_at+interval '5 minutes'),
    CHECK ((consumed_at IS NULL AND protocol_state_enc IS NOT NULL) OR (consumed_at IS NOT NULL AND protocol_state_enc IS NULL)),
    CHECK (admitted_at IS NULL OR consumed_at IS NOT NULL),
    FOREIGN KEY (tenant_id,provider_id) REFERENCES oidc_providers(tenant_id,id)
);
CREATE INDEX oidc_flows_expiry ON oidc_flows(tenant_id,expires_at);
ALTER TABLE oidc_flows ENABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_flows FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON oidc_flows
    USING (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON oidc_flows TO nethub_web;
REVOKE ALL ON oidc_flows FROM PUBLIC,nethub_authz;
GRANT SELECT ON oidc_flows TO nethub_backup;

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Restore a verified backup before reverting browser-flow admission'; END $$;
