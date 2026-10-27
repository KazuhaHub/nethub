-- +goose Up
CREATE TABLE relay_traffic_samples (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id uuid NOT NULL,
    sample_day date NOT NULL,
    in_bytes bigint NOT NULL CHECK (in_bytes>=0),
    out_bytes bigint NOT NULL CHECK (out_bytes>=0),
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id,device_id),
    FOREIGN KEY (tenant_id,device_id) REFERENCES devices(tenant_id,id) ON DELETE CASCADE,
    CHECK (sample_day=(observed_at AT TIME ZONE 'UTC')::date)
);

-- Monthly facts survive device removal; their UUID remains a historical label.
CREATE TABLE relay_traffic_months (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id uuid NOT NULL,
    month_start date NOT NULL,
    in_bytes numeric(30,0) NOT NULL CHECK (in_bytes>=0),
    out_bytes numeric(30,0) NOT NULL CHECK (out_bytes>=0),
    first_observed_at timestamptz NOT NULL,
    last_observed_at timestamptz NOT NULL,
    reset_events bigint NOT NULL DEFAULT 0 CHECK (reset_events>=0),
    PRIMARY KEY (tenant_id,month_start,device_id),
    CHECK (month_start=date_trunc('month',month_start::timestamp)::date),
    CHECK (last_observed_at>=first_observed_at)
);

ALTER TABLE relay_traffic_samples ENABLE ROW LEVEL SECURITY;
ALTER TABLE relay_traffic_samples FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON relay_traffic_samples
    USING (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);
ALTER TABLE relay_traffic_months ENABLE ROW LEVEL SECURITY;
ALTER TABLE relay_traffic_months FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON relay_traffic_months
    USING (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);
REVOKE ALL ON relay_traffic_samples,relay_traffic_months FROM PUBLIC,nethub_web;
GRANT SELECT,INSERT ON relay_traffic_samples,relay_traffic_months TO nethub_authz;
GRANT UPDATE(sample_day,in_bytes,out_bytes,observed_at) ON relay_traffic_samples TO nethub_authz;
GRANT UPDATE(in_bytes,out_bytes,last_observed_at,reset_events) ON relay_traffic_months TO nethub_authz;
GRANT SELECT ON relay_traffic_months TO nethub_web;
GRANT SELECT ON relay_traffic_samples,relay_traffic_months TO nethub_backup;

-- Invoker privileges and forced RLS apply; this function grants no new authority.
-- +goose StatementBegin
CREATE FUNCTION record_relay_traffic(p_samples jsonb,p_observed_at timestamptz) RETURNS integer
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE tenant uuid := nullif(current_setting('app.tenant_id',true),'')::uuid;
    entry jsonb; sample record; previous public.relay_traffic_samples%ROWTYPE;
    day date; month date; incoming numeric; outgoing numeric; resets bigint;
    had_previous boolean; accepted integer := 0;
BEGIN
    IF tenant IS NULL OR NOT EXISTS(SELECT 1 FROM public.tenants WHERE id=tenant) THEN
        RAISE EXCEPTION 'Tenant context is required' USING ERRCODE='42501';
    END IF;
    IF p_observed_at IS NULL OR p_observed_at>clock_timestamp()+interval '5 seconds'
       OR p_observed_at<clock_timestamp()-interval '1 minute'
       OR p_samples IS NULL OR jsonb_typeof(p_samples)<>'array'
       OR jsonb_array_length(p_samples)>1024 THEN
        RAISE EXCEPTION 'Bounded current traffic samples are required' USING ERRCODE='22023';
    END IF;
    FOR entry IN SELECT value FROM jsonb_array_elements(p_samples) LOOP
        IF jsonb_typeof(entry)<>'object' THEN
            RAISE EXCEPTION 'Invalid traffic sample' USING ERRCODE='22023';
        END IF;
        IF (SELECT count(*) FROM jsonb_object_keys(entry))<>4
           OR jsonb_typeof(entry->'device_id') IS DISTINCT FROM 'string'
           OR coalesce(entry->>'device_id','') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
           OR jsonb_typeof(entry->'subdomain') IS DISTINCT FROM 'string'
           OR coalesce(entry->>'subdomain','') !~ '^([a-z0-9]{8})?$'
           OR jsonb_typeof(entry->'in_bytes') IS DISTINCT FROM 'number'
           OR jsonb_typeof(entry->'out_bytes') IS DISTINCT FROM 'number'
           OR coalesce(entry->>'in_bytes','') !~ '^(0|[1-9][0-9]{0,18})$'
           OR coalesce(entry->>'out_bytes','') !~ '^(0|[1-9][0-9]{0,18})$' THEN
            RAISE EXCEPTION 'Invalid traffic sample' USING ERRCODE='22023';
        END IF;
    END LOOP;
    IF (SELECT count(DISTINCT value->>'device_id') FROM jsonb_array_elements(p_samples))<>jsonb_array_length(p_samples) THEN
        RAISE EXCEPTION 'Repeated traffic identity' USING ERRCODE='22023';
    END IF;
    -- A busy telemetry writer skips this tenant rather than delaying other work.
    IF NOT pg_try_advisory_xact_lock(hashtextextended('nethub:traffic:'||tenant::text,0)) THEN RETURN 0; END IF;
    day := (p_observed_at AT TIME ZONE 'UTC')::date;
    month := date_trunc('month',day::timestamp)::date;
    FOR sample IN
        SELECT x.* FROM jsonb_to_recordset(p_samples) AS x(device_id uuid,subdomain text,in_bytes bigint,out_bytes bigint)
        JOIN public.devices d ON d.tenant_id=tenant AND d.id=x.device_id
        WHERE x.subdomain='' OR x.subdomain=d.subdomain ORDER BY x.device_id
    LOOP
        SELECT * INTO previous FROM public.relay_traffic_samples
        WHERE tenant_id=tenant AND device_id=sample.device_id FOR UPDATE SKIP LOCKED;
        had_previous := FOUND;
        IF NOT had_previous AND (sample.subdomain='' OR EXISTS(SELECT 1 FROM public.relay_traffic_samples
            WHERE tenant_id=tenant AND device_id=sample.device_id)) THEN CONTINUE; END IF;
        IF had_previous AND p_observed_at<=previous.observed_at THEN CONTINUE; END IF;
        incoming := sample.in_bytes; outgoing := sample.out_bytes; resets := 0;
        IF had_previous AND previous.sample_day=day THEN
            IF sample.in_bytes>=previous.in_bytes THEN incoming := sample.in_bytes-previous.in_bytes;
            ELSE resets := 1; END IF;
            IF sample.out_bytes>=previous.out_bytes THEN outgoing := sample.out_bytes-previous.out_bytes;
            ELSE resets := 1; END IF;
        END IF;
        INSERT INTO public.relay_traffic_months(tenant_id,device_id,month_start,in_bytes,out_bytes,first_observed_at,last_observed_at,reset_events)
        VALUES(tenant,sample.device_id,month,incoming,outgoing,p_observed_at,p_observed_at,resets)
        ON CONFLICT(tenant_id,month_start,device_id) DO UPDATE
        SET in_bytes=public.relay_traffic_months.in_bytes+EXCLUDED.in_bytes,
            out_bytes=public.relay_traffic_months.out_bytes+EXCLUDED.out_bytes,
            last_observed_at=EXCLUDED.last_observed_at,
            reset_events=public.relay_traffic_months.reset_events+EXCLUDED.reset_events;
        INSERT INTO public.relay_traffic_samples(tenant_id,device_id,sample_day,in_bytes,out_bytes,observed_at)
        VALUES(tenant,sample.device_id,day,sample.in_bytes,sample.out_bytes,p_observed_at)
        ON CONFLICT(tenant_id,device_id) DO UPDATE SET sample_day=EXCLUDED.sample_day,
            in_bytes=EXCLUDED.in_bytes,out_bytes=EXCLUDED.out_bytes,observed_at=EXCLUDED.observed_at;
        accepted := accepted+1;
    END LOOP;
    RETURN accepted;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION record_relay_traffic(jsonb,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION record_relay_traffic(jsonb,timestamptz) TO nethub_authz;

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Traffic history requires an explicit retention or restore procedure'; END $$;
