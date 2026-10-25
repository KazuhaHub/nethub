-- +goose Up
CREATE TABLE relay_anomaly_incidents (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    device_id uuid,
    kind text NOT NULL CHECK (kind IN ('unknown_proxy','revoked_online','domain_mismatch')),
    proxy_key text NOT NULL CHECK (proxy_key ~ '^[0-9a-f]{64}$'),
    response text NOT NULL CHECK (response IN ('alarm_only','revoked','already_revoked')),
    confirmed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    resolved_at timestamptz,
    FOREIGN KEY (tenant_id,device_id) REFERENCES devices(tenant_id,id),
    CHECK ((kind='unknown_proxy')=(device_id IS NULL)),
    CHECK (response<>'revoked' OR kind='domain_mismatch'),
    CHECK (response<>'already_revoked' OR kind='revoked_online'),
    CHECK (last_observed_at>=confirmed_at),
    CHECK (resolved_at IS NULL OR resolved_at>=confirmed_at)
);
CREATE UNIQUE INDEX relay_anomaly_active_identity ON relay_anomaly_incidents
    (tenant_id,kind,proxy_key,coalesce(device_id::text,'')) WHERE resolved_at IS NULL;
CREATE INDEX relay_anomaly_admin_alerts ON relay_anomaly_incidents(tenant_id,confirmed_at DESC,id)
    WHERE resolved_at IS NULL;
ALTER TABLE relay_anomaly_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE relay_anomaly_incidents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON relay_anomaly_incidents
    USING (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);
REVOKE ALL ON relay_anomaly_incidents FROM PUBLIC,nethub_web;
GRANT SELECT,INSERT ON relay_anomaly_incidents TO nethub_authz;
GRANT UPDATE(last_observed_at,resolved_at) ON relay_anomaly_incidents TO nethub_authz;
GRANT SELECT ON relay_anomaly_incidents TO nethub_backup;

-- A persisted alarm never becomes an automatic revocation on a retry/restart.
-- +goose StatementBegin
CREATE FUNCTION retain_relay_anomaly_receipt() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF (NEW.id,NEW.tenant_id,NEW.device_id,NEW.kind,NEW.proxy_key,NEW.response,NEW.confirmed_at)
       IS DISTINCT FROM (OLD.id,OLD.tenant_id,OLD.device_id,OLD.kind,OLD.proxy_key,OLD.response,OLD.confirmed_at)
       OR NEW.last_observed_at<OLD.last_observed_at
       OR (OLD.resolved_at IS NOT NULL AND NEW.resolved_at IS DISTINCT FROM OLD.resolved_at) THEN
        RAISE EXCEPTION 'Relay anomaly receipts are immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION retain_relay_anomaly_receipt() FROM PUBLIC;
CREATE TRIGGER retain_relay_anomaly_receipt BEFORE UPDATE ON relay_anomaly_incidents
    FOR EACH ROW EXECUTE FUNCTION retain_relay_anomaly_receipt();

-- Unknown proxies are deployment-wide summaries, never guessed device ownership.
-- The projection exposes neither their raw names nor the internal digest keys.
-- +goose StatementBegin
CREATE FUNCTION console_relay_alerts(p_actor uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
    SELECT coalesce(jsonb_agg(jsonb_build_object('id',a.id,'device_id',a.device_id,
        'kind',a.kind,'response',a.response,'confirmed_at',a.confirmed_at)
        ORDER BY a.confirmed_at DESC,a.id),'[]'::jsonb)
    FROM (
        SELECT i.id,i.device_id,i.kind,i.response,i.confirmed_at
        FROM public.relay_anomaly_incidents i
        WHERE i.tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid
          AND i.resolved_at IS NULL AND EXISTS (
            SELECT FROM public.users u WHERE u.tenant_id=i.tenant_id AND u.id=p_actor
              AND u.role='admin' AND u.disabled_at IS NULL)
        ORDER BY i.confirmed_at DESC,i.id LIMIT 100
    ) a;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION console_relay_alerts(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION console_relay_alerts(uuid) TO nethub_web;

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Restore a verified backup before reverting relay anomaly receipts'; END $$;
