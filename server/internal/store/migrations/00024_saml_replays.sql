-- +goose Up
CREATE TABLE saml_replays (
    tenant_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    assertion_hash bytea NOT NULL CHECK (octet_length(assertion_hash)=32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL CHECK (expires_at>created_at),
    PRIMARY KEY (tenant_id,provider_id,assertion_hash),
    FOREIGN KEY (tenant_id,provider_id) REFERENCES saml_providers(tenant_id,id)
);
CREATE INDEX saml_replays_expiry ON saml_replays(tenant_id,expires_at);
ALTER TABLE saml_replays ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_replays FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON saml_replays
    USING (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT,DELETE ON saml_replays TO nethub_web;
REVOKE ALL ON saml_replays FROM PUBLIC,nethub_authz;
GRANT SELECT ON saml_replays TO nethub_backup;

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Restore a verified backup before reverting durable SAML replay protection'; END $$;
