-- +goose Up
ALTER TABLE devices ADD COLUMN service_state text CHECK (service_state IN ('running','stopped','disabled','error'));
ALTER TABLE devices ADD COLUMN last_report_at timestamptz;
ALTER TABLE devices ADD COLUMN last_reconcile_success boolean;
ALTER TABLE devices ADD COLUMN last_reconcile_at timestamptz;
GRANT SELECT (service_state,last_report_at,last_reconcile_success,last_reconcile_at) ON devices TO nethub_web;

-- Keep revoked identities for audit while releasing their routing names.
ALTER TABLE devices DROP CONSTRAINT devices_subdomain_key;
CREATE UNIQUE INDEX devices_subdomain_key ON devices(subdomain) WHERE NOT revoked;

-- +goose StatementBegin
CREATE FUNCTION lookup_device_credential(p_device uuid)
RETURNS TABLE (tenant_id uuid, secret_hash text)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT d.tenant_id,d.device_secret_hash FROM public.devices d WHERE d.id=p_device;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION lookup_device_credential(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_device_credential(uuid) TO nethub_authz;

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Device lifecycle history must be retained; restore a verified backup instead'; END $$;
