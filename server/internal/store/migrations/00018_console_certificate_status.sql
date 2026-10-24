-- +goose Up

-- Metadata only; console runtime cannot read requests, chains or report records.
-- +goose StatementBegin
CREATE FUNCTION console_certificate_status(p_actor uuid,p_device uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT jsonb_build_object(
   'state',CASE
     WHEN d.revoked THEN 'revoked'
     WHEN d.gui_public_key IS NULL THEN 'unsupported'
     WHEN applied.valid_until>statement_timestamp() THEN
       CASE WHEN work.generation>applied.generation AND work.state='failed' THEN 'renewal_failed'
            WHEN work.generation>applied.generation AND work.state<>'cancelled' THEN 'renewing' ELSE 'applied' END
     WHEN applied.valid_until<=statement_timestamp() THEN 'expired'
     WHEN work.state='failed' THEN 'failed'
     ELSE 'pending' END,
   'assigned_host',applied.assigned_host,'valid_until',applied.valid_until,
   'confirmed_at',applied.accepted_at)
 FROM public.devices d JOIN public.users actor ON actor.tenant_id=d.tenant_id
 LEFT JOIN LATERAL (
   SELECT g.generation,g.valid_until,a.accepted_at,r.assigned_host
   FROM public.gui_certificate_generations g
   JOIN public.gui_certificate_applications a ON a.generation_id=g.id AND a.tenant_id=g.tenant_id AND a.device_id=g.device_id
   JOIN public.gui_certificate_requests r ON r.id=g.request_id AND r.tenant_id=g.tenant_id AND r.device_id=g.device_id
   WHERE g.tenant_id=d.tenant_id AND g.device_id=d.id AND r.gui_public_key=d.gui_public_key
     AND split_part(r.assigned_host,'.',1)=d.subdomain
   ORDER BY g.generation DESC LIMIT 1
 ) applied ON true
 LEFT JOIN LATERAL (
   SELECT j.generation,j.state FROM public.gui_certificate_jobs j
   WHERE j.tenant_id=d.tenant_id AND j.device_id=d.id ORDER BY j.generation DESC LIMIT 1
 ) work ON true
 WHERE d.tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid AND d.id=p_device
   AND actor.id=p_actor AND actor.disabled_at IS NULL AND (actor.role='admin' OR d.owner_user_id=actor.id);
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION console_certificate_status(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION console_certificate_status(uuid,uuid) TO nethub_web;

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Console certificate metadata is irreversible; restore a verified backup instead'; END $$;
