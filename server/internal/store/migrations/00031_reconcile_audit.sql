-- +goose Up
CREATE TABLE device_reconcile_events (
 tenant_id uuid NOT NULL,
 device_id uuid NOT NULL,
 event_id uuid NOT NULL,
 kind text NOT NULL CHECK (kind IN ('reconcile_failed','reconcile_failure_overflow')),
 failure_count bigint NOT NULL CHECK (failure_count > 0),
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 first_at timestamptz NOT NULL CHECK (isfinite(first_at)),
 last_at timestamptz NOT NULL CHECK (isfinite(last_at) AND last_at >= first_at),
 PRIMARY KEY (tenant_id,device_id,event_id),
 FOREIGN KEY (tenant_id,device_id) REFERENCES devices(tenant_id,id),
 CHECK (kind <> 'reconcile_failed' OR (failure_count=1 AND first_at=last_at))
);
ALTER TABLE device_reconcile_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_reconcile_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_reconcile_events
 USING (tenant_id = nullif(current_setting('app.tenant_id',true),'')::uuid)
 WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id',true),'')::uuid);
GRANT SELECT ON device_reconcile_events TO nethub_authz;
GRANT INSERT (tenant_id,device_id,event_id,kind,failure_count,first_at,last_at) ON device_reconcile_events TO nethub_authz;
GRANT SELECT ON device_reconcile_events TO nethub_backup;

CREATE INDEX device_reconcile_daily_budget ON device_reconcile_events(tenant_id,device_id,received_at);

-- +goose StatementBegin
CREATE FUNCTION bound_device_reconcile_events() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog,pg_temp AS $$
DECLARE day_start timestamptz;
BEGIN
 PERFORM 1 FROM public.devices WHERE tenant_id=NEW.tenant_id AND id=NEW.device_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Device event identity unavailable'; END IF;
 -- Exact retries do not spend another slot, including after budget exhaustion.
 IF EXISTS (SELECT 1 FROM public.device_reconcile_events WHERE tenant_id=NEW.tenant_id AND device_id=NEW.device_id AND event_id=NEW.event_id) THEN RETURN NEW; END IF;
 day_start := date_trunc('day',clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
 IF (SELECT count(*) FROM public.device_reconcile_events WHERE tenant_id=NEW.tenant_id AND device_id=NEW.device_id AND received_at>=day_start) >= 2048 THEN
   RAISE EXCEPTION 'Device reconcile event budget exhausted' USING ERRCODE='54000';
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION bound_device_reconcile_events() FROM PUBLIC;
CREATE TRIGGER device_reconcile_events_budget BEFORE INSERT ON device_reconcile_events
 FOR EACH ROW EXECUTE FUNCTION bound_device_reconcile_events();

-- +goose StatementBegin
CREATE FUNCTION append_device_reconcile_audit() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog,pg_temp AS $$
BEGIN
 PERFORM public.append_audit('device',NEW.device_id,
   CASE WHEN NEW.kind='reconcile_failed' THEN 'device.reconcile_failed' ELSE 'device.reconcile_overflow' END,
   NEW.device_id,jsonb_build_object('event_id',NEW.event_id,'failure_count',NEW.failure_count,
      'first_reported_at',NEW.first_at,'last_reported_at',NEW.last_at,'device_reported',true));
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION append_device_reconcile_audit() FROM PUBLIC;
CREATE TRIGGER device_reconcile_audit AFTER INSERT ON device_reconcile_events
 FOR EACH ROW EXECUTE FUNCTION append_device_reconcile_audit();

-- +goose StatementBegin
CREATE FUNCTION keep_device_reconcile_events() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog,pg_temp AS $$
BEGIN
 RAISE EXCEPTION 'Device reconcile events are immutable';
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION keep_device_reconcile_events() FROM PUBLIC;
CREATE TRIGGER device_reconcile_events_immutable BEFORE UPDATE OR DELETE ON device_reconcile_events
 FOR EACH ROW EXECUTE FUNCTION keep_device_reconcile_events();

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Device reconcile event history must be retained; restore a verified backup instead'; END $$;
