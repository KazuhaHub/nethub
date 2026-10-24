-- +goose Up
-- Cutoff is for an already revoked identity; Open remains active-device only.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION request_device_disconnect(p_actor uuid,p_device uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE tenant uuid:=nullif(current_setting('app.tenant_id',true),'')::uuid;
    actor_role text; device_owner uuid; is_revoked boolean; request_id uuid;
BEGIN
    SELECT role INTO actor_role FROM public.users
    WHERE tenant_id=tenant AND id=p_actor AND disabled_at IS NULL FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Device operation is not permitted' USING ERRCODE='42501';
    END IF;
    SELECT owner_user_id,revoked INTO device_owner,is_revoked FROM public.devices
    WHERE tenant_id=tenant AND id=p_device FOR UPDATE;
    IF NOT FOUND OR (actor_role<>'admin' AND device_owner<>p_actor) OR NOT is_revoked THEN
        RAISE EXCEPTION 'Device operation is not permitted' USING ERRCODE='42501';
    END IF;
    -- Revocation is permanent; retries preserve the first request and receipt.
    SELECT id INTO request_id FROM public.device_disconnect_requests
    WHERE tenant_id=tenant AND device_id=p_device
    ORDER BY requested_at,id LIMIT 1;
    IF FOUND THEN RETURN request_id; END IF;
    INSERT INTO public.device_disconnect_requests(tenant_id,device_id,requested_by_user_id)
    VALUES(tenant,p_device,p_actor) RETURNING id INTO request_id;
    RETURN request_id;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION request_device_disconnect(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION request_device_disconnect(uuid,uuid) TO nethub_web;

CREATE INDEX device_disconnect_requests_pending ON device_disconnect_requests(tenant_id,device_id,requested_at,id)
WHERE processed_at IS NULL;

-- +goose StatementBegin
CREATE FUNCTION console_disconnect_status(p_actor uuid,p_device uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT (SELECT jsonb_build_object('request_id',r.id,'requested_at',r.requested_at,
     'armed_at',r.processed_at,'state',CASE WHEN r.processed_at IS NULL THEN 'pending' ELSE 'armed' END)
   FROM public.device_disconnect_requests r WHERE r.tenant_id=d.tenant_id AND r.device_id=d.id
   ORDER BY r.requested_at,r.id LIMIT 1)
 FROM public.devices d JOIN public.users actor ON actor.tenant_id=d.tenant_id
 WHERE d.tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid AND d.id=p_device
   AND actor.id=p_actor AND actor.disabled_at IS NULL AND (actor.role='admin' OR d.owner_user_id=actor.id);
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION console_disconnect_status(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION console_disconnect_status(uuid,uuid) TO nethub_web;

-- +goose StatementBegin
CREATE FUNCTION retain_disconnect_receipt() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF (NEW.id,NEW.tenant_id,NEW.device_id,NEW.requested_by_user_id,NEW.requested_at)
       IS DISTINCT FROM (OLD.id,OLD.tenant_id,OLD.device_id,OLD.requested_by_user_id,OLD.requested_at)
       OR (OLD.processed_at IS NOT NULL AND NEW.processed_at IS DISTINCT FROM OLD.processed_at) THEN
        RAISE EXCEPTION 'Disconnect request receipts are immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION retain_disconnect_receipt() FROM PUBLIC;
CREATE TRIGGER retain_disconnect_receipt BEFORE UPDATE ON device_disconnect_requests
FOR EACH ROW EXECUTE FUNCTION retain_disconnect_receipt();

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Restore a verified backup before reverting cutoff authorization'; END $$;
