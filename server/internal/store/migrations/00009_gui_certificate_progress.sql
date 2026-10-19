-- +goose Up
CREATE TABLE gui_certificate_progress (
    job_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    phase text NOT NULL CHECK (phase IN ('order_intent','order_saved','proof_saved','proof_live','validating','finalizing')),
    checkpoint jsonb NOT NULL CHECK (jsonb_typeof(checkpoint)='object' AND octet_length(checkpoint::text)<=32768),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    FOREIGN KEY (tenant_id,job_id) REFERENCES gui_certificate_jobs(tenant_id,id)
);
ALTER TABLE gui_certificate_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE gui_certificate_progress FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON gui_certificate_progress
 USING (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid)
 WITH CHECK (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);

-- +goose StatementBegin
CREATE FUNCTION guard_gui_certificate_progress_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF (NEW.job_id,NEW.tenant_id,NEW.created_at) IS DISTINCT FROM (OLD.job_id,OLD.tenant_id,OLD.created_at) THEN
        RAISE EXCEPTION 'Certificate checkpoint identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_gui_certificate_progress_identity() FROM PUBLIC;
CREATE TRIGGER gui_certificate_progress_identity BEFORE UPDATE ON gui_certificate_progress
 FOR EACH ROW EXECUTE FUNCTION guard_gui_certificate_progress_identity();

-- +goose StatementBegin
CREATE FUNCTION read_gui_certificate_progress(p_job uuid,p_lease uuid,p_version bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE result jsonb;
BEGIN
    IF NOT public.lock_gui_certificate_lease(p_job,p_lease,p_version) THEN RETURN NULL; END IF;
    SELECT jsonb_build_object('phase',phase,'checkpoint',checkpoint) INTO result
      FROM public.gui_certificate_progress WHERE job_id=p_job;
    RETURN coalesce(result,jsonb_build_object('phase','new','checkpoint',NULL));
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION read_gui_certificate_progress(uuid,uuid,bigint) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION save_gui_certificate_progress(p_job uuid,p_lease uuid,p_version bigint,p_phase text,p_checkpoint jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE previous public.gui_certificate_progress%ROWTYPE; before_phase text;
        binding record; field text; allowed boolean;
BEGIN
    IF NOT public.lock_gui_certificate_lease(p_job,p_lease,p_version) THEN RETURN NULL; END IF;
    SELECT j.tenant_id,r.assigned_host,r.csr_fingerprint INTO binding
      FROM public.gui_certificate_jobs j JOIN public.gui_certificate_requests r
      ON (r.tenant_id,r.device_id,r.id)=(j.tenant_id,j.device_id,j.request_id) WHERE j.id=p_job;
    IF p_checkpoint IS NULL OR jsonb_typeof(p_checkpoint)<>'object' OR octet_length(p_checkpoint::text)>32768
       OR NOT p_checkpoint ?& ARRAY['version','host','request_fingerprint','order','proof']
       OR p_checkpoint-ARRAY['version','host','request_fingerprint','order','proof']<>'{}'::jsonb
       OR p_checkpoint->'version'<>'1'::jsonb OR p_checkpoint->>'host' IS DISTINCT FROM binding.assigned_host
       OR p_checkpoint->>'request_fingerprint' IS DISTINCT FROM binding.csr_fingerprint THEN
        RAISE EXCEPTION 'Invalid certificate checkpoint binding' USING ERRCODE='23514';
    END IF;
    SELECT * INTO previous FROM public.gui_certificate_progress WHERE job_id=p_job FOR UPDATE;
    before_phase:=CASE WHEN FOUND THEN previous.phase ELSE 'new' END;
    allowed:=CASE before_phase
      WHEN 'new' THEN p_phase='order_intent'
      WHEN 'order_intent' THEN p_phase IN ('order_intent','order_saved')
      WHEN 'order_saved' THEN p_phase IN ('order_saved','proof_saved','finalizing')
      WHEN 'proof_saved' THEN p_phase IN ('proof_saved','proof_live','finalizing')
      WHEN 'proof_live' THEN p_phase IN ('proof_saved','proof_live','validating','finalizing')
      WHEN 'validating' THEN p_phase IN ('proof_saved','validating','finalizing')
      WHEN 'finalizing' THEN p_phase='finalizing' ELSE false END;
    IF NOT coalesce(allowed,false) THEN
        RAISE EXCEPTION 'Invalid certificate checkpoint transition' USING ERRCODE='23514';
    END IF;
    IF (p_phase='order_intent' AND (p_checkpoint->'order'<>'null'::jsonb OR p_checkpoint->'proof'<>'null'::jsonb))
       OR (p_phase<>'order_intent' AND jsonb_typeof(p_checkpoint->'order')<>'object')
       OR (p_phase='order_saved' AND p_checkpoint->'proof'<>'null'::jsonb)
       OR (p_phase IN ('proof_saved','proof_live','validating') AND
           (jsonb_typeof(p_checkpoint->'proof')<>'object' OR p_checkpoint#>'{proof,retired}' IS DISTINCT FROM 'false'::jsonb))
       OR (p_phase='finalizing' AND jsonb_typeof(p_checkpoint->'proof')='object'
           AND p_checkpoint#>'{proof,retired}' IS DISTINCT FROM 'true'::jsonb) THEN
        RAISE EXCEPTION 'Invalid certificate proof checkpoint' USING ERRCODE='23514';
    END IF;
    IF p_phase<>'order_intent' AND
       (p_checkpoint#>>'{order,host}' IS DISTINCT FROM binding.assigned_host OR
        p_checkpoint#>>'{order,request_fingerprint}' IS DISTINCT FROM binding.csr_fingerprint) THEN
        RAISE EXCEPTION 'Invalid certificate order binding' USING ERRCODE='23514';
    END IF;
    IF jsonb_typeof(previous.checkpoint->'order')='object' THEN
        FOREACH field IN ARRAY ARRAY['uri','host','request_fingerprint','profile','authorization_url','finalize_url'] LOOP
            IF previous.checkpoint#>ARRAY['order',field] IS DISTINCT FROM p_checkpoint#>ARRAY['order',field] THEN
                RAISE EXCEPTION 'Certificate order identity cannot change' USING ERRCODE='23514';
            END IF;
        END LOOP;
        IF coalesce(previous.checkpoint#>>'{order,certificate_url}','')<>''
           AND previous.checkpoint#>'{order,certificate_url}' IS DISTINCT FROM p_checkpoint#>'{order,certificate_url}' THEN
            RAISE EXCEPTION 'Certificate download identity cannot change' USING ERRCODE='23514';
        END IF;
    END IF;
    IF jsonb_typeof(previous.checkpoint->'proof')='object' AND jsonb_typeof(p_checkpoint->'proof')<>'object' THEN
        RAISE EXCEPTION 'Publication recovery history must be retained' USING ERRCODE='23514';
    END IF;
    IF jsonb_typeof(previous.checkpoint->'proof')='object' AND jsonb_typeof(p_checkpoint->'proof')='object' THEN
        IF previous.checkpoint#>'{proof,generation}' IS DISTINCT FROM p_checkpoint#>'{proof,generation}' THEN
            IF p_phase<>'proof_saved' THEN
                RAISE EXCEPTION 'Publication replacement requires prepared intent' USING ERRCODE='23514';
            END IF;
        ELSE
            FOREACH field IN ARRAY ARRAY['uri','token','key_authorization','expires'] LOOP
                IF previous.checkpoint#>ARRAY['proof',field] IS DISTINCT FROM p_checkpoint#>ARRAY['proof',field] THEN
                    RAISE EXCEPTION 'Publication identity cannot change within a generation' USING ERRCODE='23514';
                END IF;
            END LOOP;
        END IF;
    END IF;
    INSERT INTO public.gui_certificate_progress(job_id,tenant_id,phase,checkpoint)
      VALUES(p_job,binding.tenant_id,p_phase,p_checkpoint)
      ON CONFLICT(job_id) DO UPDATE SET phase=EXCLUDED.phase,checkpoint=EXCLUDED.checkpoint,updated_at=clock_timestamp();
    UPDATE public.gui_certificate_jobs SET version=version+1,
      lease_expires_at=least(clock_timestamp()+interval '120 seconds',deadline),updated_at=clock_timestamp() WHERE id=p_job;
    RETURN public.private_gui_job_snapshot(p_job);
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION save_gui_certificate_progress(uuid,uuid,bigint,text,jsonb) FROM PUBLIC;

-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname='nethub_issuer') THEN
        GRANT EXECUTE ON FUNCTION read_gui_certificate_progress(uuid,uuid,bigint),
          save_gui_certificate_progress(uuid,uuid,bigint,text,jsonb) TO nethub_issuer;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Order recovery checkpoints must be retained; restore a verified backup instead'; END $$;
