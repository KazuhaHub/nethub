-- +goose Up
ALTER TABLE gui_certificate_jobs DROP CONSTRAINT gui_certificate_jobs_state_check;
ALTER TABLE gui_certificate_jobs ADD CHECK (state IN ('queued','leased','retry_wait','failed','cancelled','issued'));
CREATE TABLE gui_certificate_generations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    device_id uuid NOT NULL,
    request_id uuid NOT NULL,
    job_id uuid NOT NULL UNIQUE,
    generation integer NOT NULL CHECK (generation>0),
    chain_pem bytea NOT NULL CHECK (octet_length(chain_pem) BETWEEN 1 AND 32768),
    leaf_fingerprint text NOT NULL CHECK (leaf_fingerprint ~ '^[a-f0-9]{64}$'),
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    renew_after timestamptz NOT NULL,
    completed_lease uuid NOT NULL,
    completed_version bigint NOT NULL CHECK (completed_version>0),
    issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_id,job_id) REFERENCES gui_certificate_jobs(tenant_id,id),
    FOREIGN KEY (tenant_id,device_id,request_id) REFERENCES gui_certificate_requests(tenant_id,device_id,id),
    UNIQUE (device_id,generation), UNIQUE (tenant_id,id),
    CHECK (not_before<not_after AND valid_until<=not_after AND renew_after<valid_until AND issued_at<renew_after)
);
ALTER TABLE gui_certificate_generations ENABLE ROW LEVEL SECURITY;
ALTER TABLE gui_certificate_generations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON gui_certificate_generations
 USING (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid)
 WITH CHECK (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);

-- +goose StatementBegin
CREATE FUNCTION retain_gui_certificate_generation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'Issued certificate material is immutable';
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION retain_gui_certificate_generation() FROM PUBLIC;
CREATE TRIGGER gui_certificate_generation_immutable BEFORE UPDATE OR DELETE ON gui_certificate_generations
 FOR EACH ROW EXECUTE FUNCTION retain_gui_certificate_generation();

-- +goose StatementBegin
CREATE FUNCTION finish_gui_certificate_job(p_job uuid,p_lease uuid,p_version bigint,p_chain bytea,p_fingerprint text,
 p_not_before timestamptz,p_not_after timestamptz,p_valid_until timestamptz,p_renew_after timestamptz) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE identity record; job public.gui_certificate_jobs%ROWTYPE; existing public.gui_certificate_generations%ROWTYPE;
        progress public.gui_certificate_progress%ROWTYPE; generation_id uuid;
BEGIN
    IF session_user<>'nethub_issuer' THEN
        RAISE EXCEPTION 'Certificate issuer identity denied' USING ERRCODE='42501';
    END IF;
    SELECT device_id,tenant_id INTO identity FROM public.gui_certificate_jobs WHERE id=p_job;
    IF NOT FOUND THEN RETURN NULL; END IF;
    PERFORM 1 FROM public.devices WHERE id=identity.device_id AND tenant_id=identity.tenant_id FOR UPDATE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT * INTO job FROM public.gui_certificate_jobs WHERE id=p_job FOR UPDATE;
    IF NOT FOUND OR public.private_gui_job_snapshot(p_job) IS NULL THEN RETURN NULL; END IF;
    IF job.state='issued' THEN
        SELECT * INTO existing FROM public.gui_certificate_generations WHERE job_id=p_job;
        IF FOUND AND existing.completed_lease=p_lease AND existing.completed_version=p_version
          AND existing.chain_pem=p_chain AND existing.leaf_fingerprint=p_fingerprint
          AND existing.not_before=p_not_before AND existing.not_after=p_not_after
          AND existing.valid_until=p_valid_until AND existing.renew_after=p_renew_after THEN RETURN existing.id; END IF;
        RETURN NULL;
    END IF;
    IF NOT public.lock_gui_certificate_lease(p_job,p_lease,p_version) THEN RETURN NULL; END IF;
    SELECT * INTO progress FROM public.gui_certificate_progress WHERE job_id=p_job FOR UPDATE;
    IF NOT FOUND OR progress.phase<>'finalizing' OR progress.checkpoint#>>'{order,status}' IS DISTINCT FROM 'valid'
      OR coalesce(progress.checkpoint#>>'{order,certificate_url}','')='' THEN
        RAISE EXCEPTION 'Certificate issuance has no durable completed order' USING ERRCODE='23514';
    END IF;
    IF p_chain IS NULL OR octet_length(p_chain) NOT BETWEEN 1 AND 32768 OR p_fingerprint IS NULL OR p_fingerprint!~'^[a-f0-9]{64}$'
      OR p_not_before IS NULL OR p_not_after IS NULL OR p_valid_until IS NULL OR p_renew_after IS NULL
      OR p_not_before>clock_timestamp() OR p_valid_until<=clock_timestamp() OR p_not_before>=p_valid_until
      OR p_valid_until>p_not_after OR p_renew_after<=clock_timestamp() OR p_renew_after>=p_valid_until THEN
        RAISE EXCEPTION 'Invalid issued certificate lifetime or material' USING ERRCODE='23514';
    END IF;
    INSERT INTO public.gui_certificate_generations(tenant_id,device_id,request_id,job_id,generation,chain_pem,
      leaf_fingerprint,not_before,not_after,valid_until,renew_after,completed_lease,completed_version)
    VALUES(job.tenant_id,job.device_id,job.request_id,job.id,job.generation,p_chain,p_fingerprint,
      p_not_before,p_not_after,p_valid_until,p_renew_after,p_lease,p_version) RETURNING id INTO generation_id;
    UPDATE public.gui_certificate_jobs SET state='issued',lease_token=NULL,lease_expires_at=NULL,
      version=version+1,updated_at=clock_timestamp() WHERE id=p_job;
    PERFORM set_config('app.tenant_id',job.tenant_id::text,true);
    PERFORM public.append_audit('system',NULL,'device.certificate_issued',job.device_id,
      jsonb_build_object('job_id',job.id,'generation_id',generation_id,'leaf_fingerprint',p_fingerprint));
    RETURN generation_id;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION finish_gui_certificate_job(uuid,uuid,bigint,bytea,text,timestamptz,timestamptz,timestamptz,timestamptz) FROM PUBLIC;

-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname='nethub_issuer') THEN
        GRANT EXECUTE ON FUNCTION finish_gui_certificate_job(uuid,uuid,bigint,bytea,text,timestamptz,timestamptz,timestamptz,timestamptz) TO nethub_issuer;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Issued generations must be retained; restore a verified backup instead'; END $$;
