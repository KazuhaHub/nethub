-- +goose Up
CREATE TABLE tenant_traffic_settings (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    warning_bytes numeric(30,0) NOT NULL CHECK (warning_bytes>=0),
    revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    modified_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_id,modified_by_user_id) REFERENCES users(tenant_id,id),
    CHECK (updated_at>=created_at)
);
ALTER TABLE tenant_traffic_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_traffic_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_traffic_settings
    USING (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);
REVOKE ALL ON tenant_traffic_settings FROM PUBLIC,nethub_authz;
GRANT SELECT,INSERT ON tenant_traffic_settings TO nethub_web;
GRANT UPDATE(warning_bytes,revision,modified_by_user_id,updated_at) ON tenant_traffic_settings TO nethub_web;
GRANT SELECT ON tenant_traffic_settings TO nethub_backup;

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Traffic warning history requires an explicit restore procedure'; END $$;
