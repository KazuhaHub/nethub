-- +goose Up

-- +goose StatementBegin
CREATE FUNCTION require_device_actor(p_actor uuid, p_device uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE tenant uuid := nullif(current_setting('app.tenant_id', true), '')::uuid;
BEGIN
    PERFORM 1 FROM public.devices d JOIN public.users u ON u.tenant_id = d.tenant_id
    WHERE d.id = p_device AND d.tenant_id = tenant AND NOT d.revoked
      AND u.id = p_actor AND u.disabled_at IS NULL
      AND (u.role = 'admin' OR d.owner_user_id = u.id)
    FOR SHARE OF d, u;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Device operation is not permitted' USING ERRCODE = '42501';
    END IF;
    RETURN tenant;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION require_device_actor(uuid, uuid) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION open_device(p_actor uuid, p_device uuid, p_ip inet) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE tenant uuid; granted timestamptz := clock_timestamp();
BEGIN
    tenant := public.require_device_actor(p_actor, p_device);
    IF p_ip IS NULL OR masklen(p_ip) <> (CASE family(p_ip) WHEN 4 THEN 32 ELSE 128 END) THEN
        RAISE EXCEPTION 'An exact source IP is required' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.device_access_grants(tenant_id, device_id, user_id, source_ip, granted_at, expires_at)
    VALUES (tenant, p_device, p_actor, p_ip, granted, granted + interval '30 minutes')
    ON CONFLICT (tenant_id, device_id, user_id, source_ip) DO UPDATE
    SET granted_at = EXCLUDED.granted_at, expires_at = EXCLUDED.expires_at;
    RETURN granted + interval '30 minutes';
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION open_device(uuid, uuid, inet) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION open_device(uuid, uuid, inet) TO nethub_web;

-- +goose StatementBegin
CREATE FUNCTION request_device_disconnect(p_actor uuid, p_device uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE tenant uuid; request_id uuid;
BEGIN
    tenant := public.require_device_actor(p_actor, p_device);
    INSERT INTO public.device_disconnect_requests(tenant_id, device_id, requested_by_user_id)
    VALUES (tenant, p_device, p_actor) RETURNING id INTO request_id;
    RETURN request_id;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION request_device_disconnect(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION request_device_disconnect(uuid, uuid) TO nethub_web;

-- +goose StatementBegin
CREATE FUNCTION append_audit(p_actor_type text, p_actor uuid, p_action text, p_device uuid, p_payload jsonb)
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
        'target_device_id', p_device, 'payload', p_payload, 'created_at', timestamp,
        'prev_hash', encode(previous, 'hex'));
    INSERT INTO public.audit_log(id, tenant_id, sequence, actor_type, actor_id, action,
        target_device_id, payload, prev_hash, entry_hash, created_at)
    VALUES (entry_id, tenant, next_sequence, p_actor_type, p_actor, p_action, p_device,
        p_payload, previous, public.digest(convert_to(content::text, 'UTF8'), 'sha256'), timestamp);
    RETURN entry_id;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION append_audit(text, uuid, text, uuid, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION append_audit(text, uuid, text, uuid, jsonb) TO nethub_web, nethub_authz;

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Identity operation migration is irreversible; restore a verified backup instead'; END $$;
