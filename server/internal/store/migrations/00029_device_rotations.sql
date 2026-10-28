-- +goose Up
CREATE TABLE device_rotations (
    tenant_id uuid NOT NULL,
    device_id uuid NOT NULL,
    operation_id uuid NOT NULL CHECK (operation_id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    candidate_digest bytea NOT NULL CHECK (octet_length(candidate_digest)=32),
    credential_hash text NOT NULL CHECK (octet_length(credential_hash) BETWEEN 64 AND 256 AND credential_hash LIKE '$argon2id$%'),
    issued_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, device_id, operation_id),
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, id)
);
ALTER TABLE device_rotations ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_rotations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_rotations
 USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
 WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- +goose StatementBegin
CREATE FUNCTION guard_device_rotation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'Device rotation operations are immutable';
    END IF;
    PERFORM 1 FROM public.devices WHERE id=NEW.device_id AND tenant_id=NEW.tenant_id
      AND NOT revoked AND device_secret_hash=NEW.credential_hash
      AND domain_claim_issued_at=NEW.issued_at FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Device rotation is not bound to the live credential' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_device_rotation() FROM PUBLIC;
CREATE TRIGGER device_rotation_binding BEFORE INSERT OR UPDATE OR DELETE ON device_rotations
 FOR EACH ROW EXECUTE FUNCTION guard_device_rotation();
GRANT SELECT, INSERT ON device_rotations TO nethub_authz;
CREATE INDEX device_rotation_claim_snapshot ON device_rotations(tenant_id,device_id,issued_at DESC);

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Device rotation history must be retained; restore a verified backup instead'; END $$;
