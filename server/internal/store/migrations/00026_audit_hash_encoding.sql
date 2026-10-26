-- +goose Up
-- Existing hashes are retained with their original session-timezone encoding.
ALTER TABLE audit_log ADD COLUMN hash_version smallint NOT NULL DEFAULT 1
    CHECK (hash_version IN (1,2));

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION append_audit(p_actor_type text, p_actor uuid, p_action text, p_device uuid, p_payload jsonb)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE tenant uuid := nullif(current_setting('app.tenant_id', true), '')::uuid;
    entry_id uuid := gen_random_uuid(); previous bytea := ''::bytea;
    next_sequence bigint := 1; timestamp timestamptz := clock_timestamp(); content jsonb;
BEGIN
    PERFORM 1 FROM public.tenants WHERE id = tenant FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Tenant context is required' USING ERRCODE = '42501'; END IF;
    SELECT entry_hash, sequence + 1 INTO previous, next_sequence
    FROM public.audit_log WHERE tenant_id = tenant ORDER BY sequence DESC LIMIT 1;
    previous := coalesce(previous, ''::bytea); next_sequence := coalesce(next_sequence, 1);
    content := jsonb_build_object('id', entry_id, 'tenant_id', tenant, 'sequence', next_sequence,
        'actor_type', p_actor_type, 'actor_id', p_actor, 'action', p_action,
        'target_device_id', p_device, 'payload', p_payload,
        'created_at', to_char(timestamp AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'prev_hash', encode(previous, 'hex'), 'hash_version', 2);
    INSERT INTO public.audit_log(id, tenant_id, sequence, actor_type, actor_id, action,
        target_device_id, payload, prev_hash, entry_hash, created_at, hash_version)
    VALUES (entry_id, tenant, next_sequence, p_actor_type, p_actor, p_action, p_device,
        p_payload, previous, public.digest(convert_to(content::text, 'UTF8'), 'sha256'), timestamp, 2);
    RETURN entry_id;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION append_audit(text,uuid,text,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION append_audit(text,uuid,text,uuid,jsonb) TO nethub_web,nethub_authz;

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Audit hash history must not be rewritten or downgraded; restore a verified backup instead'; END $$;
