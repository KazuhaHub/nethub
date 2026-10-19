-- +goose Up
-- One signed CSR per immutable enrollment binding, independent of renewal jobs.
CREATE TABLE gui_certificate_requests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    device_id uuid NOT NULL UNIQUE,
    assigned_host text NOT NULL CHECK (octet_length(assigned_host) <= 253),
    gui_public_key text NOT NULL,
    csr_der bytea NOT NULL CHECK (octet_length(csr_der) BETWEEN 1 AND 4096),
    csr_fingerprint text GENERATED ALWAYS AS (encode(public.digest(csr_der, 'sha256'), 'hex')) STORED,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, id),
    UNIQUE (tenant_id, id)
);
ALTER TABLE gui_certificate_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE gui_certificate_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON gui_certificate_requests
 USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
 WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- +goose StatementBegin
CREATE FUNCTION guard_gui_certificate_request() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE binding text; label text; disabled boolean;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'Signed certificate requests are immutable';
    END IF;
    -- The same parent lock serializes admission, credential checks and revocation.
    SELECT gui_public_key, subdomain, revoked INTO binding, label, disabled
      FROM public.devices WHERE id=NEW.device_id AND tenant_id=NEW.tenant_id FOR UPDATE;
    IF NOT FOUND OR disabled OR binding IS NULL OR binding <> NEW.gui_public_key
       OR label !~ '^[a-z0-9]{8}$'
       OR split_part(NEW.assigned_host, '.', 1) <> label
       OR NEW.assigned_host !~ '^[a-z0-9]{8}(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$' THEN
        RAISE EXCEPTION 'Certificate request assignment is not live' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_gui_certificate_request() FROM PUBLIC;
CREATE TRIGGER gui_certificate_request_binding BEFORE INSERT OR UPDATE OR DELETE
 ON gui_certificate_requests FOR EACH ROW EXECUTE FUNCTION guard_gui_certificate_request();
GRANT SELECT, INSERT ON gui_certificate_requests TO nethub_authz;

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Signed certificate requests must be retained; restore a verified backup instead'; END $$;
