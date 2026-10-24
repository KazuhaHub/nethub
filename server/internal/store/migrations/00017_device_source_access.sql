-- +goose Up

-- +goose StatementBegin
CREATE FUNCTION device_source_access(p_device uuid, p_ip inet) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE tenant uuid := nullif(current_setting('app.tenant_id', true), '')::uuid;
    owner_id uuid; actor_id uuid;
BEGIN
    IF p_ip IS NULL OR masklen(p_ip) <> (CASE family(p_ip) WHEN 4 THEN 32 ELSE 128 END) THEN
        RETURN false;
    END IF;
    SELECT owner_user_id INTO owner_id FROM public.devices
    WHERE tenant_id=tenant AND id=p_device AND NOT revoked FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;
    SELECT g.user_id INTO actor_id FROM public.device_access_grants g
    JOIN public.users u ON u.tenant_id=g.tenant_id AND u.id=g.user_id
    WHERE g.tenant_id=tenant AND g.device_id=p_device AND g.source_ip=p_ip
      AND g.expires_at>clock_timestamp() AND u.disabled_at IS NULL
      AND (u.role='admin' OR u.id=owner_id)
    ORDER BY g.expires_at DESC,g.user_id LIMIT 1 FOR SHARE OF g,u;
    IF NOT FOUND THEN RETURN false; END IF;
    -- Locks serialize actor/grant changes; the clock must be checked after waits.
    RETURN EXISTS (SELECT FROM public.device_access_grants g
    JOIN public.users u ON u.tenant_id=g.tenant_id AND u.id=g.user_id
    WHERE g.tenant_id=tenant AND g.device_id=p_device AND g.user_id=actor_id
      AND g.source_ip=p_ip AND g.expires_at>clock_timestamp()
      AND u.disabled_at IS NULL AND (u.role='admin' OR u.id=owner_id));
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION device_source_access(uuid, inet) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION device_source_access(uuid, inet) TO nethub_authz;

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Device source access is irreversible; restore a verified backup instead'; END $$;
