-- +goose Up
CREATE TABLE relay_authority_switches (
 id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
 trust_generation_id uuid NOT NULL REFERENCES relay_trust_generations(id),
 server_name text NOT NULL,
 previous_root text NOT NULL CHECK(previous_root~'^[a-f0-9]{64}$'),
 next_root text NOT NULL CHECK(next_root~'^[a-f0-9]{64}$' AND next_root<>previous_root),
 previous_leaf text NOT NULL CHECK(previous_leaf~'^[a-f0-9]{64}$'),
 next_leaf text NOT NULL CHECK(next_leaf~'^[a-f0-9]{64}$' AND next_leaf<>previous_leaf),
 phase text NOT NULL DEFAULT 'pending' CHECK(phase IN ('pending','committed','rolled_back')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 finished_at timestamptz,
 observed_leaf text,
 CHECK ((phase='pending' AND finished_at IS NULL AND observed_leaf IS NULL) OR
  (phase<>'pending' AND finished_at IS NOT NULL AND observed_leaf IS NOT NULL AND finished_at>=created_at AND observed_leaf=
   (CASE WHEN phase='committed' THEN next_leaf ELSE previous_leaf END)))
);
CREATE UNIQUE INDEX relay_authority_one_pending ON relay_authority_switches(phase) WHERE phase='pending';
ALTER TABLE relay_authority_switches ENABLE ROW LEVEL SECURITY;
ALTER TABLE relay_authority_switches FORCE ROW LEVEL SECURITY;
REVOKE ALL ON relay_authority_switches FROM PUBLIC,nethub_web,nethub_authz;

-- +goose StatementBegin
CREATE FUNCTION retain_relay_authority_switch() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Authority switch history must be retained'; END IF;
 IF OLD.phase<>'pending' OR NEW.phase='pending' OR
  (to_jsonb(NEW)-ARRAY['phase','finished_at','observed_leaf']) IS DISTINCT FROM
  (to_jsonb(OLD)-ARRAY['phase','finished_at','observed_leaf']) THEN
  RAISE EXCEPTION 'Authority switch identity and terminal history are immutable';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION retain_relay_authority_switch() FROM PUBLIC;
CREATE TRIGGER relay_authority_switch_immutable BEFORE UPDATE OR DELETE ON relay_authority_switches
 FOR EACH ROW EXECUTE FUNCTION retain_relay_authority_switch();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_enrollment_relay_trust() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 PERFORM 1 FROM public.relay_trust_head WHERE singleton FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Relay trust head missing'; END IF;
 IF EXISTS(SELECT FROM public.relay_authority_switches WHERE phase='pending') THEN
  RAISE EXCEPTION 'Relay authority switch requires host recovery' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION guard_relay_trust_authority_switch() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 PERFORM 1 FROM public.relay_trust_head WHERE singleton FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Relay trust head missing'; END IF;
 IF EXISTS(SELECT FROM public.relay_authority_switches WHERE phase='pending') THEN
  RAISE EXCEPTION 'Relay authority switch requires host recovery' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_relay_trust_authority_switch() FROM PUBLIC;
CREATE TRIGGER relay_trust_authority_switch_fence BEFORE INSERT ON relay_trust_generations
 FOR EACH ROW EXECUTE FUNCTION guard_relay_trust_authority_switch();

-- +goose StatementBegin
CREATE FUNCTION relay_authority_switch_fence_ready() RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT session_user IN ('nethub_authz','nethub_issuer')
 AND NOT EXISTS(SELECT FROM (VALUES
  ('public.guard_enrollment_relay_trust()'),('public.guard_relay_trust_authority_switch()'),
  ('public.private_relay_authority_switch(uuid)'),
  ('public.begin_relay_authority_switch(uuid,uuid,text,text,text,text,text)'),
  ('public.read_relay_authority_switch(uuid,text)'),('public.finish_relay_authority_switch(uuid,text,text)')) f(signature)
  LEFT JOIN pg_proc p ON p.oid=to_regprocedure(f.signature)
  WHERE p.oid IS NULL OR NOT p.prosecdef OR p.proowner<>'nethub_owner'::regrole
   OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']::text[])
 AND EXISTS(SELECT FROM pg_class WHERE oid='public.relay_authority_switches'::regclass AND relrowsecurity AND relforcerowsecurity AND relowner='nethub_owner'::regrole)
 AND EXISTS(SELECT FROM pg_proc WHERE oid='public.retain_relay_authority_switch()'::regprocedure
  AND proowner='nethub_owner'::regrole AND proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[])
 AND NOT EXISTS(SELECT FROM (VALUES
  ('public.private_relay_authority_switch(uuid)'),
  ('public.begin_relay_authority_switch(uuid,uuid,text,text,text,text,text)'),
  ('public.read_relay_authority_switch(uuid,text)'),('public.finish_relay_authority_switch(uuid,text,text)')) f(signature)
  JOIN pg_proc p ON p.oid=to_regprocedure(f.signature),
  LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE a.privilege_type='EXECUTE' AND (a.grantee=0 OR a.grantee IN ('nethub_web'::regrole,'nethub_authz'::regrole)))
 AND NOT EXISTS(SELECT FROM pg_roles r WHERE rolname IN ('nethub_authz','nethub_web','nethub_issuer')
  AND (has_table_privilege(r.oid,'public.relay_authority_switches','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
   OR has_any_column_privilege(r.oid,'public.relay_authority_switches','SELECT,INSERT,UPDATE,REFERENCES')))
 AND (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled IN ('O','A') AND
  ((tgrelid='public.devices'::regclass AND tgname='devices_relay_trust_enrollment' AND tgfoid='public.guard_enrollment_relay_trust()'::regprocedure)
   OR (tgrelid='public.relay_trust_generations'::regclass AND tgname='relay_trust_authority_switch_fence' AND tgfoid='public.guard_relay_trust_authority_switch()'::regprocedure)
   OR (tgrelid='public.relay_authority_switches'::regclass AND tgname='relay_authority_switch_immutable' AND tgfoid='public.retain_relay_authority_switch()'::regprocedure)))=3;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION relay_authority_switch_fence_ready() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION relay_authority_switch_fence_ready() TO nethub_authz;

-- +goose StatementBegin
CREATE FUNCTION private_relay_authority_switch(p_id uuid) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT to_jsonb(s) FROM public.relay_authority_switches s WHERE id=p_id;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION private_relay_authority_switch(uuid) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION begin_relay_authority_switch(p_id uuid,p_expected uuid,p_name text,p_old text,p_new text,p_before text,p_after text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE selected uuid; trust public.relay_trust_generations%ROWTYPE; existing public.relay_authority_switches%ROWTYPE;
BEGIN
 IF session_user<>'nethub_issuer' THEN RAISE EXCEPTION 'Host issuer identity denied' USING ERRCODE='42501'; END IF;
 IF NOT public.relay_authority_switch_fence_ready() THEN RAISE EXCEPTION 'Authority switch fence unavailable'; END IF;
 IF p_id IS NULL OR p_id='00000000-0000-0000-0000-000000000000'::uuid OR p_expected IS NULL
  OR p_old IS NULL OR p_old!~'^[a-f0-9]{64}$' OR p_new IS NULL OR p_new!~'^[a-f0-9]{64}$' OR p_old=p_new
  OR p_before IS NULL OR p_before!~'^[a-f0-9]{64}$' OR p_after IS NULL OR p_after!~'^[a-f0-9]{64}$' OR p_before=p_after THEN
  RAISE EXCEPTION 'Invalid authority switch identity' USING ERRCODE='23514';
 END IF;
 SELECT generation_id INTO selected FROM public.relay_trust_head WHERE singleton FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Relay trust head missing'; END IF;
 SELECT * INTO existing FROM public.relay_authority_switches WHERE id=p_id;
 IF FOUND THEN
  IF existing.trust_generation_id=p_expected AND existing.server_name=p_name AND existing.previous_root=p_old AND existing.next_root=p_new
   AND existing.previous_leaf=p_before AND existing.next_leaf=p_after THEN RETURN public.private_relay_authority_switch(p_id); END IF;
  RETURN NULL;
 END IF;
 IF selected IS DISTINCT FROM p_expected OR EXISTS(SELECT FROM public.relay_authority_switches WHERE phase='pending') THEN RETURN NULL; END IF;
 SELECT * INTO trust FROM public.relay_trust_generations WHERE id=selected;
 IF NOT FOUND OR trust.server_name IS DISTINCT FROM p_name OR trust.not_before>clock_timestamp() OR trust.valid_until<=clock_timestamp()
  OR NOT (trust.root_fingerprints ? p_old) OR NOT (trust.root_fingerprints ? p_new) THEN RETURN NULL; END IF;
 PERFORM 1 FROM public.devices WHERE NOT revoked ORDER BY id FOR UPDATE;
 IF EXISTS(SELECT FROM public.devices d WHERE NOT revoked AND NOT EXISTS(
  SELECT FROM public.relay_trust_applications a WHERE a.device_id=d.id AND a.tenant_id=d.tenant_id
   AND a.generation_id=trust.id AND a.bundle_fingerprint=trust.bundle_fingerprint)) THEN RETURN NULL; END IF;
 INSERT INTO public.relay_authority_switches(id,trust_generation_id,server_name,previous_root,next_root,previous_leaf,next_leaf)
 VALUES(p_id,p_expected,p_name,p_old,p_new,p_before,p_after);
 RETURN public.private_relay_authority_switch(p_id);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION begin_relay_authority_switch(uuid,uuid,text,text,text,text,text) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION read_relay_authority_switch(p_id uuid,p_name text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF session_user<>'nethub_issuer' THEN RAISE EXCEPTION 'Host issuer identity denied' USING ERRCODE='42501'; END IF;
 IF NOT public.relay_authority_switch_fence_ready() THEN RAISE EXCEPTION 'Authority switch fence unavailable'; END IF;
 IF NOT EXISTS(SELECT FROM public.relay_authority_switches WHERE id=p_id AND server_name=p_name) THEN RETURN NULL; END IF;
 RETURN public.private_relay_authority_switch(p_id);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION read_relay_authority_switch(uuid,text) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION finish_relay_authority_switch(p_id uuid,p_phase text,p_observed text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE selected uuid; existing public.relay_authority_switches%ROWTYPE;
BEGIN
 IF session_user<>'nethub_issuer' THEN RAISE EXCEPTION 'Host issuer identity denied' USING ERRCODE='42501'; END IF;
 IF NOT public.relay_authority_switch_fence_ready() THEN RAISE EXCEPTION 'Authority switch fence unavailable'; END IF;
 IF p_phase IS NULL OR p_phase NOT IN ('committed','rolled_back') OR p_observed IS NULL OR p_observed!~'^[a-f0-9]{64}$' THEN RETURN NULL; END IF;
 SELECT generation_id INTO selected FROM public.relay_trust_head WHERE singleton FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Relay trust head missing'; END IF;
 SELECT * INTO existing FROM public.relay_authority_switches WHERE id=p_id FOR UPDATE;
 IF NOT FOUND OR p_observed IS DISTINCT FROM (CASE WHEN p_phase='committed' THEN existing.next_leaf ELSE existing.previous_leaf END) THEN RETURN NULL; END IF;
 IF existing.phase<>'pending' THEN
  IF existing.phase=p_phase AND existing.observed_leaf=p_observed THEN RETURN public.private_relay_authority_switch(p_id); END IF;
  RETURN NULL;
 END IF;
 IF selected IS DISTINCT FROM existing.trust_generation_id THEN RETURN NULL; END IF;
 UPDATE public.relay_authority_switches SET phase=p_phase,observed_leaf=p_observed,finished_at=clock_timestamp() WHERE id=p_id;
 RETURN public.private_relay_authority_switch(p_id);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION finish_relay_authority_switch(uuid,text,text) FROM PUBLIC;

-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='nethub_issuer') THEN
  GRANT EXECUTE ON FUNCTION relay_authority_switch_fence_ready(),begin_relay_authority_switch(uuid,uuid,text,text,text,text,text),
   read_relay_authority_switch(uuid,text),finish_relay_authority_switch(uuid,text,text) TO nethub_issuer;
 END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Authority switch history must be retained; restore a verified backup instead'; END $$;
