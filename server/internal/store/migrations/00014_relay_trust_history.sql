-- +goose Up
-- Deployment-public history is visible only through narrow host/device functions.
CREATE TABLE relay_trust_generations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    generation integer NOT NULL UNIQUE CHECK (generation>0),
    server_name text NOT NULL CHECK (octet_length(server_name) BETWEEN 1 AND 253),
    ca_pem bytea NOT NULL CHECK (octet_length(ca_pem) BETWEEN 64 AND 32768),
    bundle_fingerprint text NOT NULL CHECK (bundle_fingerprint ~ '^[a-f0-9]{64}$'),
    root_fingerprints jsonb NOT NULL CHECK (jsonb_typeof(root_fingerprints)='array'),
    not_before timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    published_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(id,generation),
    CHECK (not_before<=published_at AND published_at<valid_until)
);
CREATE TABLE relay_trust_head (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    generation_id uuid,
    generation integer NOT NULL DEFAULT 0,
    FOREIGN KEY(generation_id,generation) REFERENCES relay_trust_generations(id,generation),
    CHECK ((generation_id IS NULL AND generation=0) OR (generation_id IS NOT NULL AND generation>0))
);
INSERT INTO relay_trust_head(singleton) VALUES(true);
CREATE TABLE relay_trust_applications (
    tenant_id uuid NOT NULL,
    device_id uuid NOT NULL,
    generation_id uuid NOT NULL,
    generation integer NOT NULL,
    bundle_fingerprint text NOT NULL CHECK (bundle_fingerprint ~ '^[a-f0-9]{64}$'),
    accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(device_id,generation_id),
    UNIQUE(tenant_id,device_id,generation),
    FOREIGN KEY(tenant_id,device_id) REFERENCES devices(tenant_id,id),
    FOREIGN KEY(generation_id,generation) REFERENCES relay_trust_generations(id,generation)
);
ALTER TABLE relay_trust_generations ENABLE ROW LEVEL SECURITY;
ALTER TABLE relay_trust_generations FORCE ROW LEVEL SECURITY;
ALTER TABLE relay_trust_head ENABLE ROW LEVEL SECURITY;
ALTER TABLE relay_trust_head FORCE ROW LEVEL SECURITY;
ALTER TABLE relay_trust_applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE relay_trust_applications FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON relay_trust_applications
 USING (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid)
 WITH CHECK (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);
REVOKE ALL ON relay_trust_generations,relay_trust_head,relay_trust_applications FROM PUBLIC,nethub_web,nethub_authz;

-- +goose StatementBegin
CREATE FUNCTION retain_relay_trust_history() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN RAISE EXCEPTION 'Relay trust history is immutable'; END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION retain_relay_trust_history() FROM PUBLIC;
CREATE TRIGGER relay_trust_generation_immutable BEFORE UPDATE OR DELETE ON relay_trust_generations
 FOR EACH ROW EXECUTE FUNCTION retain_relay_trust_history();
CREATE TRIGGER relay_trust_application_immutable BEFORE UPDATE OR DELETE ON relay_trust_applications
 FOR EACH ROW EXECUTE FUNCTION retain_relay_trust_history();

-- +goose StatementBegin
CREATE FUNCTION lock_relay_trust_head() RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF session_user<>'nethub_authz' THEN
        RAISE EXCEPTION 'Relay trust reader identity denied' USING ERRCODE='42501';
    END IF;
    PERFORM 1 FROM public.relay_trust_head WHERE singleton FOR SHARE;
    RETURN FOUND;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION lock_relay_trust_head() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lock_relay_trust_head() TO nethub_authz;

-- +goose StatementBegin
CREATE FUNCTION guard_enrollment_relay_trust() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    -- Also fence raw inserts; a publisher must not miss an uncommitted device.
    PERFORM 1 FROM public.relay_trust_head WHERE singleton FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Relay trust head missing'; END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_enrollment_relay_trust() FROM PUBLIC;
CREATE TRIGGER devices_relay_trust_enrollment BEFORE INSERT ON devices
 FOR EACH ROW EXECUTE FUNCTION guard_enrollment_relay_trust();

-- +goose StatementBegin
CREATE FUNCTION private_relay_trust_snapshot(p_id uuid) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
    SELECT jsonb_build_object('id',id,'generation',generation,'server_name',server_name,
      'ca_pem',convert_from(ca_pem,'UTF8'),'bundle_fingerprint',bundle_fingerprint,
      'root_fingerprints',root_fingerprints,'not_before',not_before,'valid_until',valid_until,
      'published_at',published_at) FROM public.relay_trust_generations WHERE id=p_id;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION private_relay_trust_snapshot(uuid) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION read_current_relay_trust(p_name text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE selected uuid; current_generation public.relay_trust_generations%ROWTYPE;
BEGIN
    IF session_user NOT IN ('nethub_authz','nethub_issuer') THEN
        RAISE EXCEPTION 'Relay trust reader identity denied' USING ERRCODE='42501';
    END IF;
    SELECT generation_id INTO selected FROM public.relay_trust_head WHERE singleton FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Relay trust head missing'; END IF;
    IF selected IS NULL THEN RETURN NULL; END IF;
    SELECT * INTO current_generation FROM public.relay_trust_generations WHERE id=selected;
    IF NOT FOUND OR current_generation.server_name IS DISTINCT FROM lower(p_name)
      OR current_generation.not_before>clock_timestamp() OR current_generation.valid_until<=clock_timestamp() THEN
        RAISE EXCEPTION 'Relay trust identity or validity differs' USING ERRCODE='23514';
    END IF;
    RETURN public.private_relay_trust_snapshot(selected);
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION read_current_relay_trust(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION read_current_relay_trust(text) TO nethub_authz;

-- +goose StatementBegin
CREATE FUNCTION publish_relay_trust(p_expected uuid,p_name text,p_ca bytea,p_fingerprint text,
 p_roots jsonb,p_not_before timestamptz,p_valid_until timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE head public.relay_trust_head%ROWTYPE; previous public.relay_trust_generations%ROWTYPE;
        selected uuid; distinct_roots integer;
BEGIN
    IF session_user<>'nethub_issuer' THEN
        RAISE EXCEPTION 'Relay trust publisher identity denied' USING ERRCODE='42501';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_trigger WHERE tgrelid='public.devices'::regclass
      AND tgname='devices_relay_trust_enrollment' AND NOT tgisinternal AND tgenabled IN ('O','A')
      AND tgfoid='public.guard_enrollment_relay_trust()'::regprocedure) THEN
        RAISE EXCEPTION 'Enrollment trust fence is unavailable';
    END IF;
    IF p_name IS NULL OR octet_length(p_name) NOT BETWEEN 1 AND 253 OR p_name !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
      OR p_ca IS NULL OR octet_length(p_ca) NOT BETWEEN 64 AND 32768
      OR p_fingerprint IS NULL OR p_fingerprint IS DISTINCT FROM encode(public.digest(convert_to('nethub-relay-trust-v1:','UTF8')||p_ca,'sha256'),'hex')
      OR p_roots IS NULL OR jsonb_typeof(p_roots)<>'array' OR p_not_before IS NULL OR p_valid_until IS NULL THEN
        RAISE EXCEPTION 'Invalid public relay trust metadata' USING ERRCODE='23514';
    END IF;
    IF jsonb_array_length(p_roots) NOT BETWEEN 1 AND 2 OR EXISTS (SELECT FROM jsonb_array_elements(p_roots) e
      WHERE jsonb_typeof(e)<>'string' OR (e#>>'{}') !~ '^[a-f0-9]{64}$')
      OR convert_from(p_ca,'UTF8') !~ '^(-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n){1,2}$' THEN
        RAISE EXCEPTION 'Invalid public relay trust encoding' USING ERRCODE='23514';
    END IF;
    SELECT count(DISTINCT value) INTO distinct_roots FROM jsonb_array_elements_text(p_roots);
    IF distinct_roots<>jsonb_array_length(p_roots) OR p_roots<>(SELECT jsonb_agg(value ORDER BY value) FROM jsonb_array_elements_text(p_roots)) THEN
        RAISE EXCEPTION 'Root identities must be distinct and canonical' USING ERRCODE='23514';
    END IF;
    SELECT * INTO head FROM public.relay_trust_head WHERE singleton FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Relay trust head missing'; END IF;
    IF p_not_before>clock_timestamp() OR p_valid_until<=clock_timestamp() OR p_not_before>=p_valid_until THEN
        RAISE EXCEPTION 'Relay trust validity elapsed' USING ERRCODE='23514';
    END IF;
    IF head.generation_id IS NOT NULL THEN
        SELECT * INTO previous FROM public.relay_trust_generations WHERE id=head.generation_id;
        IF previous.server_name=p_name AND previous.ca_pem=p_ca AND previous.bundle_fingerprint=p_fingerprint
          AND previous.root_fingerprints=p_roots AND previous.not_before=p_not_before AND previous.valid_until=p_valid_until THEN
            RETURN public.private_relay_trust_snapshot(previous.id);
        END IF;
    END IF;
    IF head.generation_id IS DISTINCT FROM p_expected THEN RETURN NULL; END IF;
    IF head.generation>=2147483647 THEN RAISE EXCEPTION 'Relay trust generation limit' USING ERRCODE='23514'; END IF;
    IF head.generation_id IS NOT NULL THEN
        IF previous.server_name<>p_name OR NOT EXISTS (SELECT FROM jsonb_array_elements_text(previous.root_fingerprints) r WHERE p_roots ? r.value) THEN
            RAISE EXCEPTION 'Planned trust replacement needs a shared authority' USING ERRCODE='23514';
        END IF;
        IF EXISTS (SELECT FROM jsonb_array_elements_text(previous.root_fingerprints) r WHERE NOT p_roots ? r.value) THEN
            -- Head first, then parent devices. The insertion trigger fences new
            -- enrollments; do not skip a busy device or treat delivery as applied.
            PERFORM 1 FROM public.devices WHERE NOT revoked ORDER BY id FOR UPDATE;
            IF EXISTS (SELECT FROM public.devices d WHERE NOT d.revoked AND NOT EXISTS (
              SELECT FROM public.relay_trust_applications a WHERE a.device_id=d.id AND a.tenant_id=d.tenant_id
                AND a.generation_id=previous.id AND a.bundle_fingerprint=previous.bundle_fingerprint)) THEN RETURN NULL; END IF;
        END IF;
    END IF;
    INSERT INTO public.relay_trust_generations(generation,server_name,ca_pem,bundle_fingerprint,root_fingerprints,not_before,valid_until)
      VALUES(head.generation+1,p_name,p_ca,p_fingerprint,p_roots,p_not_before,p_valid_until) RETURNING id INTO selected;
    UPDATE public.relay_trust_head SET generation_id=selected,generation=head.generation+1 WHERE singleton;
    RETURN public.private_relay_trust_snapshot(selected);
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION publish_relay_trust(uuid,text,bytea,text,jsonb,timestamptz,timestamptz) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION record_relay_trust_application(p_device uuid,p_id uuid,p_generation integer,p_fingerprint text) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE selected uuid; binding public.devices%ROWTYPE; trust public.relay_trust_generations%ROWTYPE; received timestamptz; existing_received timestamptz;
BEGIN
    IF session_user<>'nethub_authz' THEN
        RAISE EXCEPTION 'Relay trust report identity denied' USING ERRCODE='42501';
    END IF;
    SELECT generation_id INTO selected FROM public.relay_trust_head WHERE singleton FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Relay trust head missing'; END IF;
    SELECT * INTO binding FROM public.devices WHERE id=p_device
      AND tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid FOR UPDATE;
    IF NOT FOUND OR binding.revoked OR selected IS DISTINCT FROM p_id THEN RETURN NULL; END IF;
    SELECT * INTO trust FROM public.relay_trust_generations WHERE id=selected;
    received:=clock_timestamp();
    IF NOT FOUND OR trust.generation IS DISTINCT FROM p_generation OR trust.bundle_fingerprint IS DISTINCT FROM p_fingerprint
      OR trust.not_before>received OR trust.valid_until<=received THEN RETURN NULL; END IF;
    SELECT accepted_at INTO existing_received FROM public.relay_trust_applications WHERE device_id=binding.id AND generation_id=selected;
    IF FOUND THEN RETURN existing_received; END IF;
    INSERT INTO public.relay_trust_applications(tenant_id,device_id,generation_id,generation,bundle_fingerprint,accepted_at)
      VALUES(binding.tenant_id,binding.id,selected,p_generation,p_fingerprint,received);
    PERFORM public.append_audit('device',binding.id,'device.relay_trust_applied',binding.id,
      jsonb_build_object('generation_id',selected,'generation',p_generation,'bundle_fingerprint',p_fingerprint));
    RETURN received;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION record_relay_trust_application(uuid,uuid,integer,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION record_relay_trust_application(uuid,uuid,integer,text) TO nethub_authz;

-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname='nethub_issuer') THEN
        GRANT EXECUTE ON FUNCTION read_current_relay_trust(text),publish_relay_trust(uuid,text,bytea,text,jsonb,timestamptz,timestamptz) TO nethub_issuer;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Relay trust history must be retained; restore a verified backup instead'; END $$;
