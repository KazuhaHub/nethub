-- +goose Up
-- Immutable authenticated reports; delivery and issuance never create them.
CREATE TABLE gui_certificate_applications (
    generation_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    device_id uuid NOT NULL,
    request_id uuid NOT NULL,
    generation integer NOT NULL CHECK (generation>0),
    csr_fingerprint text NOT NULL CHECK (csr_fingerprint ~ '^[a-f0-9]{64}$'),
    leaf_fingerprint text NOT NULL CHECK (leaf_fingerprint ~ '^[a-f0-9]{64}$'),
    accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_id,generation_id) REFERENCES gui_certificate_generations(tenant_id,id),
    FOREIGN KEY (tenant_id,device_id,request_id) REFERENCES gui_certificate_requests(tenant_id,device_id,id),
    UNIQUE (tenant_id,device_id,generation)
);
ALTER TABLE gui_certificate_applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE gui_certificate_applications FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON gui_certificate_applications
 USING (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid)
 WITH CHECK (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);
REVOKE ALL ON gui_certificate_applications FROM PUBLIC,nethub_web,nethub_authz;

-- +goose StatementBegin
CREATE FUNCTION retain_gui_certificate_application() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'Certificate application reports are immutable';
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION retain_gui_certificate_application() FROM PUBLIC;
CREATE TRIGGER gui_certificate_application_immutable BEFORE UPDATE OR DELETE ON gui_certificate_applications
 FOR EACH ROW EXECUTE FUNCTION retain_gui_certificate_application();

-- +goose StatementBegin
CREATE FUNCTION record_gui_certificate_application(p_device uuid,p_request uuid,p_csr text,p_host text,
 p_generation_id uuid,p_generation integer,p_leaf text) RETURNS TABLE(accepted_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE binding record; existing public.gui_certificate_applications%ROWTYPE; received timestamptz;
BEGIN
    IF session_user<>'nethub_authz' THEN
        RAISE EXCEPTION 'Certificate application identity denied' USING ERRCODE='42501';
    END IF;
    SELECT d.id,d.tenant_id,d.gui_public_key,d.subdomain,d.revoked INTO binding
      FROM public.devices d WHERE d.id=p_device
       AND d.tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid FOR UPDATE;
    IF NOT FOUND OR binding.revoked OR binding.gui_public_key IS NULL THEN RETURN; END IF;
    received:=clock_timestamp();
    PERFORM 1 FROM public.gui_certificate_generations g
      JOIN public.gui_certificate_requests r ON (r.tenant_id,r.device_id,r.id)=(g.tenant_id,g.device_id,g.request_id)
      JOIN public.gui_certificate_jobs j ON (j.tenant_id,j.device_id,j.request_id,j.id,j.generation)=
       (g.tenant_id,g.device_id,g.request_id,g.job_id,g.generation)
      WHERE g.id=p_generation_id AND g.device_id=binding.id AND g.tenant_id=binding.tenant_id
       AND g.generation=p_generation AND g.leaf_fingerprint=p_leaf AND j.state='issued'
       AND r.id=p_request AND r.csr_fingerprint=p_csr AND r.gui_public_key=binding.gui_public_key
       AND r.assigned_host=p_host AND split_part(p_host,'.',1)=binding.subdomain
       AND g.not_before<=received AND g.valid_until>received;
    IF NOT FOUND THEN RETURN; END IF;
    -- All writers hold the parent device lock, including revocation and issuance.
    -- A newer issuance alone does not invalidate an older valid installed leaf.
    PERFORM 1 FROM public.gui_certificate_applications a WHERE a.tenant_id=binding.tenant_id
      AND a.device_id=binding.id AND a.generation>p_generation;
    IF FOUND THEN RETURN; END IF;
    SELECT * INTO existing FROM public.gui_certificate_applications a
      WHERE a.generation_id=p_generation_id AND a.tenant_id=binding.tenant_id AND a.device_id=binding.id;
    IF FOUND THEN
        RETURN QUERY SELECT existing.accepted_at;
        RETURN;
    END IF;
    INSERT INTO public.gui_certificate_applications(generation_id,tenant_id,device_id,request_id,generation,
      csr_fingerprint,leaf_fingerprint,accepted_at)
    VALUES(p_generation_id,binding.tenant_id,binding.id,p_request,p_generation,p_csr,p_leaf,received);
    PERFORM public.append_audit('device',binding.id,'device.certificate_applied',binding.id,
      jsonb_build_object('request_id',p_request,'generation_id',p_generation_id,'generation',p_generation,'leaf_fingerprint',p_leaf));
    RETURN QUERY SELECT received;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION record_gui_certificate_application(uuid,uuid,text,text,uuid,integer,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION record_gui_certificate_application(uuid,uuid,text,text,uuid,integer,text) TO nethub_authz;

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Restore a verified backup instead of removing application reports'; END $$;
