-- +goose Up
-- Return public installation material only after rechecking the live assignment.
-- +goose StatementBegin
CREATE FUNCTION read_issued_gui_certificate(p_device uuid,p_request uuid,p_fingerprint text,p_host text)
RETURNS TABLE(id uuid,generation integer,chain_pem bytea,leaf_fingerprint text,
 not_before timestamptz,not_after timestamptz,valid_until timestamptz,renew_after timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE binding record;
BEGIN
    IF session_user<>'nethub_authz' THEN
        RAISE EXCEPTION 'Certificate delivery identity denied' USING ERRCODE='42501';
    END IF;
    SELECT d.id,d.tenant_id,d.gui_public_key,d.subdomain,d.revoked INTO binding
      FROM public.devices d WHERE d.id=p_device
       AND d.tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid FOR UPDATE;
    IF NOT FOUND OR binding.revoked OR binding.gui_public_key IS NULL THEN RETURN; END IF;
    RETURN QUERY
      SELECT g.id,g.generation,g.chain_pem,g.leaf_fingerprint,
       g.not_before,g.not_after,g.valid_until,g.renew_after
      FROM public.gui_certificate_generations g
      JOIN public.gui_certificate_requests r ON r.id=g.request_id AND r.tenant_id=g.tenant_id
       AND r.device_id=g.device_id
      JOIN public.gui_certificate_jobs j ON j.id=g.job_id AND j.tenant_id=g.tenant_id
       AND j.device_id=g.device_id AND j.request_id=g.request_id AND j.generation=g.generation
      WHERE g.device_id=binding.id AND g.tenant_id=binding.tenant_id AND r.id=p_request
       AND r.gui_public_key=binding.gui_public_key AND r.csr_fingerprint=p_fingerprint
       AND r.assigned_host=p_host AND split_part(p_host,'.',1)=binding.subdomain
       AND j.state='issued' AND g.not_before<=clock_timestamp()
       AND g.valid_until>clock_timestamp()
      ORDER BY g.generation DESC LIMIT 1;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION read_issued_gui_certificate(uuid,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION read_issued_gui_certificate(uuid,uuid,text,text) TO nethub_authz;

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Restore a verified backup instead of removing delivery authorization'; END $$;
