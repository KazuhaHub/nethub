-- +goose Up
CREATE INDEX gui_certificate_generations_renewal ON gui_certificate_generations(renew_after,device_id);

-- +goose StatementBegin
CREATE FUNCTION enqueue_due_gui_certificate_renewals(p_domain text,p_excluded jsonb) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE candidate record; current_generation public.gui_certificate_generations%ROWTYPE;
        request public.gui_certificate_requests%ROWTYPE; device public.devices%ROWTYPE;
        job_id uuid; queued integer:=0;
BEGIN
    IF session_user<>'nethub_issuer' THEN
        RAISE EXCEPTION 'Certificate issuer identity denied' USING ERRCODE='42501';
    END IF;
    IF p_domain IS NULL OR octet_length(p_domain)>244
      OR p_domain !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
      OR p_excluded IS NULL OR jsonb_typeof(p_excluded)<>'array' THEN
        RAISE EXCEPTION 'Invalid certificate renewal policy' USING ERRCODE='23514';
    END IF;
    IF jsonb_array_length(p_excluded)>32 OR EXISTS (SELECT FROM jsonb_array_elements(p_excluded) e
      WHERE jsonb_typeof(e)<>'string' OR octet_length(e#>>'{}')>253
        OR (e#>>'{}') !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$') THEN
        RAISE EXCEPTION 'Invalid certificate renewal exclusions' USING ERRCODE='23514';
    END IF;
    -- Parent-first SKIP LOCKED allows unrelated devices past busy rows. The
    -- latest-generation/job predicates are repeated under that parent lock.
    FOR candidate IN SELECT d.id,d.tenant_id FROM public.devices d
      JOIN public.gui_certificate_requests r ON (r.tenant_id,r.device_id)=(d.tenant_id,d.id)
      JOIN LATERAL (SELECT * FROM public.gui_certificate_generations g WHERE g.device_id=d.id
        ORDER BY g.generation DESC LIMIT 1) g ON true
      WHERE NOT d.revoked AND d.gui_public_key=r.gui_public_key
        AND r.assigned_host=d.subdomain||'.'||p_domain AND NOT p_excluded ? r.assigned_host
        AND g.request_id=r.id AND g.renew_after<=clock_timestamp() AND g.generation<2147483647
        AND NOT EXISTS (SELECT FROM public.gui_certificate_jobs j WHERE j.device_id=d.id
          AND (j.generation>g.generation OR j.state IN ('queued','leased','retry_wait')))
      ORDER BY g.renew_after,d.id LIMIT 32 FOR UPDATE OF d SKIP LOCKED
    LOOP
        SELECT * INTO device FROM public.devices WHERE id=candidate.id AND tenant_id=candidate.tenant_id FOR UPDATE;
        SELECT * INTO request FROM public.gui_certificate_requests WHERE device_id=device.id AND tenant_id=device.tenant_id;
        IF NOT FOUND OR device.revoked OR device.gui_public_key IS DISTINCT FROM request.gui_public_key
          OR request.assigned_host<>device.subdomain||'.'||p_domain OR p_excluded ? request.assigned_host THEN CONTINUE; END IF;
        SELECT * INTO current_generation FROM public.gui_certificate_generations
          WHERE device_id=device.id AND tenant_id=device.tenant_id ORDER BY generation DESC LIMIT 1;
        IF NOT FOUND OR current_generation.request_id<>request.id OR current_generation.renew_after>clock_timestamp()
          OR current_generation.generation>=2147483647 THEN CONTINUE; END IF;
        -- Expired material may still be renewed. A failed/cancelled newer job
        -- requires operator review rather than automatically creating CA work.
        IF EXISTS (SELECT FROM public.gui_certificate_jobs WHERE device_id=device.id
          AND (generation>current_generation.generation OR state IN ('queued','leased','retry_wait'))) THEN CONTINUE; END IF;
        INSERT INTO public.gui_certificate_jobs(tenant_id,device_id,request_id,generation)
          VALUES(device.tenant_id,device.id,request.id,current_generation.generation+1) RETURNING id INTO job_id;
        PERFORM set_config('app.tenant_id',device.tenant_id::text,true);
        PERFORM public.append_audit('system',NULL,'device.certificate_renewal_queued',device.id,
          jsonb_build_object('request_id',request.id,'job_id',job_id,'generation',current_generation.generation+1,
            'previous_generation_id',current_generation.id));
        queued:=queued+1;
        -- The host advances one job per invocation; do not admit a batch whose
        -- immutable two-hour deadlines can expire behind our own queue.
        EXIT;
    END LOOP;
    RETURN queued;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION enqueue_due_gui_certificate_renewals(text,jsonb) FROM PUBLIC;

-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname='nethub_issuer') THEN
        GRANT EXECUTE ON FUNCTION enqueue_due_gui_certificate_renewals(text,jsonb) TO nethub_issuer;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Renewal history must be retained; restore a verified backup instead'; END $$;
