-- +goose Up
ALTER TABLE gui_certificate_requests ADD UNIQUE (tenant_id,device_id,id);

CREATE TABLE gui_certificate_jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    device_id uuid NOT NULL,
    request_id uuid NOT NULL,
    generation integer NOT NULL DEFAULT 1 CHECK (generation > 0),
    state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','leased','retry_wait','failed','cancelled')),
    failures integer NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 5),
    recoveries integer NOT NULL DEFAULT 0 CHECK (recoveries BETWEEN 0 AND 3),
    polls integer NOT NULL DEFAULT 0 CHECK (polls BETWEEN 0 AND 60),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    lease_token uuid,
    lease_expires_at timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    failure_code text NOT NULL DEFAULT 'none'
      CHECK (failure_code IN ('none','transient','policy','indeterminate_order','job_expired',
                             'lease_exhausted','attempts_exhausted','polls_exhausted','assignment_changed')),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    deadline timestamptz NOT NULL DEFAULT statement_timestamp()+interval '2 hours',
    FOREIGN KEY (tenant_id,device_id,request_id) REFERENCES gui_certificate_requests(tenant_id,device_id,id),
    UNIQUE (request_id,generation), UNIQUE (tenant_id,id),
    CHECK ((state='leased' AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR (state<>'leased' AND lease_token IS NULL AND lease_expires_at IS NULL)),
    CHECK (deadline > created_at AND deadline <= created_at+interval '2 hours')
);
CREATE UNIQUE INDEX gui_certificate_jobs_active ON gui_certificate_jobs(device_id)
 WHERE state IN ('queued','leased','retry_wait');
CREATE INDEX gui_certificate_jobs_due ON gui_certificate_jobs(next_attempt_at,id)
 WHERE state IN ('queued','leased','retry_wait');
ALTER TABLE gui_certificate_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE gui_certificate_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON gui_certificate_jobs
 USING (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid)
 WITH CHECK (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);

-- +goose StatementBegin
CREATE FUNCTION guard_gui_certificate_job_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF (NEW.id,NEW.tenant_id,NEW.device_id,NEW.request_id,NEW.generation,NEW.created_at,NEW.deadline)
       IS DISTINCT FROM
       (OLD.id,OLD.tenant_id,OLD.device_id,OLD.request_id,OLD.generation,OLD.created_at,OLD.deadline) THEN
        RAISE EXCEPTION 'Certificate job identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_gui_certificate_job_identity() FROM PUBLIC;
CREATE TRIGGER gui_certificate_job_identity BEFORE UPDATE ON gui_certificate_jobs
 FOR EACH ROW EXECUTE FUNCTION guard_gui_certificate_job_identity();

-- +goose StatementBegin
CREATE FUNCTION cancel_changed_gui_certificate_jobs() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    -- The caller already owns the parent device lock; jobs always come second.
    UPDATE public.gui_certificate_jobs SET state='cancelled',failure_code='assignment_changed',
      lease_token=NULL,lease_expires_at=NULL,version=version+1,updated_at=clock_timestamp()
    WHERE device_id=NEW.id AND tenant_id=NEW.tenant_id AND state IN ('queued','leased','retry_wait');
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION cancel_changed_gui_certificate_jobs() FROM PUBLIC;
CREATE TRIGGER devices_cancel_gui_jobs AFTER UPDATE ON devices
 FOR EACH ROW WHEN ((NEW.revoked AND NOT OLD.revoked) OR NEW.subdomain IS DISTINCT FROM OLD.subdomain)
 EXECUTE FUNCTION cancel_changed_gui_certificate_jobs();

-- +goose StatementBegin
CREATE FUNCTION enqueue_gui_certificate_request(p_request uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE request public.gui_certificate_requests%ROWTYPE; device public.devices%ROWTYPE;
        job_id uuid; inserted boolean;
BEGIN
    IF session_user NOT IN ('nethub_authz','nethub_issuer') THEN
        RAISE EXCEPTION 'Certificate queue identity denied' USING ERRCODE='42501';
    END IF;
    SELECT * INTO request FROM public.gui_certificate_requests WHERE id=p_request;
    IF NOT FOUND OR (session_user='nethub_authz' AND request.tenant_id IS DISTINCT FROM
       nullif(current_setting('app.tenant_id',true),'')::uuid) THEN RETURN NULL; END IF;
    SELECT * INTO device FROM public.devices WHERE id=request.device_id AND tenant_id=request.tenant_id FOR UPDATE;
    IF NOT FOUND OR device.revoked OR device.gui_public_key IS DISTINCT FROM request.gui_public_key
       OR device.subdomain<>split_part(request.assigned_host,'.',1) THEN RETURN NULL; END IF;
    INSERT INTO public.gui_certificate_jobs(tenant_id,device_id,request_id)
      VALUES(request.tenant_id,request.device_id,request.id)
      ON CONFLICT (request_id,generation) DO NOTHING RETURNING id INTO job_id;
    inserted:=FOUND;
    IF NOT inserted THEN
        SELECT id INTO job_id FROM public.gui_certificate_jobs WHERE request_id=request.id AND generation=1;
    ELSE
        PERFORM set_config('app.tenant_id',request.tenant_id::text,true);
        PERFORM public.append_audit(CASE WHEN session_user='nethub_authz' THEN 'device' ELSE 'system' END,
          CASE WHEN session_user='nethub_authz' THEN device.id ELSE NULL END,'device.certificate_queued',device.id,
          jsonb_build_object('request_id',request.id,'job_id',job_id));
    END IF;
    RETURN job_id;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION enqueue_gui_certificate_request(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION enqueue_gui_certificate_request(uuid) TO nethub_authz;

-- +goose StatementBegin
CREATE FUNCTION private_gui_job_snapshot(p_job uuid) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
    SELECT jsonb_build_object('job',to_jsonb(j),'assigned_host',r.assigned_host,
      'subdomain',d.subdomain,'public_key',d.gui_public_key,
      'csr_der_hex',encode(r.csr_der,'hex'),'csr_fingerprint',r.csr_fingerprint)
    FROM public.gui_certificate_jobs j
    JOIN public.gui_certificate_requests r ON (r.tenant_id,r.device_id,r.id)=(j.tenant_id,j.device_id,j.request_id)
    JOIN public.devices d ON (d.tenant_id,d.id)=(j.tenant_id,j.device_id)
    WHERE j.id=p_job AND NOT d.revoked AND d.gui_public_key=r.gui_public_key
      AND d.subdomain=split_part(r.assigned_host,'.',1);
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION private_gui_job_snapshot(uuid) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION claim_gui_certificate_job() RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE candidate record; job public.gui_certificate_jobs%ROWTYPE;
BEGIN
    IF session_user<>'nethub_issuer' THEN
        RAISE EXCEPTION 'Certificate issuer identity denied' USING ERRCODE='42501';
    END IF;
    FOR candidate IN SELECT j.id,j.device_id,j.tenant_id FROM public.gui_certificate_jobs j
      JOIN public.devices d ON (d.tenant_id,d.id)=(j.tenant_id,j.device_id)
      WHERE (j.state IN ('queued','retry_wait') AND j.next_attempt_at<=clock_timestamp())
         OR (j.state='leased' AND j.lease_expires_at<=clock_timestamp())
      ORDER BY j.next_attempt_at,j.id LIMIT 32 FOR UPDATE OF d SKIP LOCKED
    LOOP
        -- Do not lock a candidate job before its parent: enqueue/revoke lock the
        -- device first. Parent-only locking also skips blocked rows before LIMIT,
        -- so a locked prefix cannot starve unrelated eligible devices.
        -- Recheck every predicate after both nonblocking locks.
        PERFORM 1 FROM public.devices WHERE id=candidate.device_id AND tenant_id=candidate.tenant_id FOR UPDATE SKIP LOCKED;
        IF NOT FOUND THEN CONTINUE; END IF;
        SELECT * INTO job FROM public.gui_certificate_jobs WHERE id=candidate.id FOR UPDATE SKIP LOCKED;
        IF NOT FOUND OR NOT ((job.state IN ('queued','retry_wait') AND job.next_attempt_at<=clock_timestamp())
          OR (job.state='leased' AND job.lease_expires_at<=clock_timestamp())) THEN CONTINUE; END IF;
        IF public.private_gui_job_snapshot(job.id) IS NULL THEN
            UPDATE public.gui_certificate_jobs SET state='cancelled',failure_code='assignment_changed',
              lease_token=NULL,lease_expires_at=NULL,version=version+1,updated_at=clock_timestamp() WHERE id=job.id;
            CONTINUE;
        END IF;
        IF job.deadline<=clock_timestamp() OR (job.state='leased' AND job.recoveries>=3) THEN
            UPDATE public.gui_certificate_jobs SET state='failed',failure_code=CASE WHEN job.deadline<=clock_timestamp()
              THEN 'job_expired' ELSE 'lease_exhausted' END,lease_token=NULL,lease_expires_at=NULL,
              version=version+1,updated_at=clock_timestamp() WHERE id=job.id;
            CONTINUE;
        END IF;
        UPDATE public.gui_certificate_jobs SET state='leased',failure_code='none',lease_token=gen_random_uuid(),
          lease_expires_at=least(clock_timestamp()+interval '120 seconds',deadline),
          recoveries=recoveries+CASE WHEN state='leased' THEN 1 ELSE 0 END,
          version=version+1,updated_at=clock_timestamp() WHERE id=job.id;
        RETURN public.private_gui_job_snapshot(job.id);
    END LOOP;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION claim_gui_certificate_job() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION lock_gui_certificate_lease(p_job uuid,p_lease uuid,p_version bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE identity record; job public.gui_certificate_jobs%ROWTYPE;
BEGIN
    IF session_user<>'nethub_issuer' THEN
        RAISE EXCEPTION 'Certificate issuer identity denied' USING ERRCODE='42501';
    END IF;
    SELECT device_id,tenant_id INTO identity FROM public.gui_certificate_jobs WHERE id=p_job;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM 1 FROM public.devices WHERE id=identity.device_id AND tenant_id=identity.tenant_id FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    SELECT * INTO job FROM public.gui_certificate_jobs WHERE id=p_job FOR UPDATE;
    IF NOT FOUND OR job.state<>'leased' OR job.lease_token IS DISTINCT FROM p_lease
      OR job.version IS DISTINCT FROM p_version OR job.lease_expires_at<=clock_timestamp()
      OR job.deadline<=clock_timestamp() THEN RETURN false; END IF;
    IF public.private_gui_job_snapshot(job.id) IS NULL THEN RETURN false; END IF;
    RETURN true;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION lock_gui_certificate_lease(uuid,uuid,bigint) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION renew_gui_certificate_lease(p_job uuid,p_lease uuid,p_version bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF NOT public.lock_gui_certificate_lease(p_job,p_lease,p_version) THEN RETURN NULL; END IF;
    UPDATE public.gui_certificate_jobs SET lease_expires_at=least(clock_timestamp()+interval '120 seconds',deadline),
      version=version+1,updated_at=clock_timestamp() WHERE id=p_job;
    RETURN public.private_gui_job_snapshot(p_job);
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION renew_gui_certificate_lease(uuid,uuid,bigint) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION release_gui_certificate_lease(p_job uuid,p_lease uuid,p_version bigint,p_reason text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE job public.gui_certificate_jobs%ROWTYPE; terminal boolean;
BEGIN
    IF NOT public.lock_gui_certificate_lease(p_job,p_lease,p_version) THEN RETURN false; END IF;
    IF p_reason NOT IN ('transient','policy','indeterminate_order','waiting') OR p_reason IS NULL THEN
        RAISE EXCEPTION 'Invalid certificate failure classification' USING ERRCODE='23514';
    END IF;
    SELECT * INTO job FROM public.gui_certificate_jobs WHERE id=p_job;
    terminal:=p_reason IN ('policy','indeterminate_order')
      OR (p_reason='transient' AND job.failures>=4) OR (p_reason='waiting' AND job.polls>=59);
    UPDATE public.gui_certificate_jobs SET state=CASE WHEN terminal THEN 'failed' ELSE 'retry_wait' END,
      failure_code=CASE WHEN p_reason='waiting' AND terminal THEN 'polls_exhausted'
                       WHEN p_reason='transient' AND terminal THEN 'attempts_exhausted'
                       WHEN p_reason='waiting' THEN 'none' ELSE p_reason END,
      failures=failures+CASE WHEN p_reason='transient' THEN 1 ELSE 0 END,
      polls=polls+CASE WHEN p_reason='waiting' THEN 1 ELSE 0 END,
      next_attempt_at=least(deadline,clock_timestamp()+CASE WHEN p_reason='waiting' THEN interval '30 seconds'
        ELSE interval '60 seconds'*(1<<job.failures) END),
      lease_token=NULL,lease_expires_at=NULL,version=version+1,updated_at=clock_timestamp() WHERE id=p_job;
    RETURN true;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION release_gui_certificate_lease(uuid,uuid,bigint,text) FROM PUBLIC;

-- Old volumes may not yet have the reserved role. Disabled device APIs still
-- migrate; an issuer requires an explicit reviewed role/grant upgrade first.
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname='nethub_issuer') THEN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='nethub_issuer' AND NOT rolcanlogin
          AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication
          AND NOT rolinherit AND NOT rolbypassrls)
          OR EXISTS (SELECT FROM pg_auth_members WHERE roleid='nethub_issuer'::regrole OR member='nethub_issuer'::regrole) THEN
            RAISE EXCEPTION 'Issuer role flags or memberships need operator review';
        END IF;
        GRANT EXECUTE ON FUNCTION enqueue_gui_certificate_request(uuid),claim_gui_certificate_job(),
          renew_gui_certificate_lease(uuid,uuid,bigint),release_gui_certificate_lease(uuid,uuid,bigint,text) TO nethub_issuer;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Certificate jobs must be retained; restore a verified backup instead'; END $$;
