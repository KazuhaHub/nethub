-- +goose Up
CREATE TABLE relay_authority_cancellations (
 id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
 trust_generation_id uuid NOT NULL CHECK(trust_generation_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 server_name text NOT NULL CHECK(octet_length(server_name) BETWEEN 1 AND 253),
 previous_root text NOT NULL CHECK(previous_root~'^[a-f0-9]{64}$'),
 next_root text NOT NULL CHECK(next_root~'^[a-f0-9]{64}$' AND next_root<>previous_root),
 previous_leaf text NOT NULL CHECK(previous_leaf~'^[a-f0-9]{64}$'),
 next_leaf text NOT NULL CHECK(next_leaf~'^[a-f0-9]{64}$' AND next_leaf<>previous_leaf),
 intent_sha256 text NOT NULL CHECK(intent_sha256~'^[a-f0-9]{64}$'),
 cancelled_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE relay_authority_cancellations ENABLE ROW LEVEL SECURITY;
ALTER TABLE relay_authority_cancellations FORCE ROW LEVEL SECURITY;
REVOKE ALL ON relay_authority_cancellations FROM PUBLIC,nethub_web,nethub_authz;

-- +goose StatementBegin
CREATE FUNCTION retain_relay_authority_cancellation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN RAISE EXCEPTION 'Authority cancellation history must be retained'; END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION retain_relay_authority_cancellation() FROM PUBLIC;
CREATE TRIGGER relay_authority_cancellation_immutable BEFORE UPDATE OR DELETE ON relay_authority_cancellations
 FOR EACH ROW EXECUTE FUNCTION retain_relay_authority_cancellation();

-- +goose StatementBegin
CREATE FUNCTION guard_relay_authority_cancellation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 PERFORM 1 FROM public.relay_trust_head WHERE singleton FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Relay trust head missing'; END IF;
 IF (TG_TABLE_NAME='relay_authority_switches' AND EXISTS(SELECT FROM public.relay_authority_cancellations WHERE id=NEW.id)) OR
    (TG_TABLE_NAME='relay_authority_cancellations' AND EXISTS(SELECT FROM public.relay_authority_switches WHERE id=NEW.id)) THEN
  RAISE EXCEPTION 'Authority operation already has another durable decision' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_relay_authority_cancellation() FROM PUBLIC;
CREATE TRIGGER relay_authority_cancelled_switch_guard BEFORE INSERT ON relay_authority_switches
 FOR EACH ROW EXECUTE FUNCTION guard_relay_authority_cancellation();
CREATE TRIGGER relay_authority_cancellation_switch_guard BEFORE INSERT ON relay_authority_cancellations
 FOR EACH ROW EXECUTE FUNCTION guard_relay_authority_cancellation();

-- Preserve the reviewed admission logic behind a non-callable private boundary.
ALTER FUNCTION relay_authority_switch_fence_ready() RENAME TO private_relay_authority_switch_fence_v15;
ALTER FUNCTION begin_relay_authority_switch(uuid,uuid,text,text,text,text,text) RENAME TO private_begin_relay_authority_switch_v15;
REVOKE ALL ON FUNCTION private_relay_authority_switch_fence_v15(),private_begin_relay_authority_switch_v15(uuid,uuid,text,text,text,text,text) FROM PUBLIC,nethub_web,nethub_authz;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='nethub_issuer') THEN
  REVOKE ALL ON FUNCTION private_relay_authority_switch_fence_v15(),private_begin_relay_authority_switch_v15(uuid,uuid,text,text,text,text,text) FROM nethub_issuer;
 END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION relay_authority_cancellation_fence_ready() RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT session_user IN ('nethub_authz','nethub_issuer')
 AND EXISTS(SELECT FROM pg_class WHERE oid='public.relay_authority_cancellations'::regclass AND relrowsecurity AND relforcerowsecurity AND relowner='nethub_owner'::regrole)
 AND NOT EXISTS(SELECT FROM (VALUES
  ('public.relay_authority_switch_fence_ready()'),('public.private_relay_authority_switch_fence_v15()'),
  ('public.private_begin_relay_authority_switch_v15(uuid,uuid,text,text,text,text,text)'),
  ('public.begin_relay_authority_switch(uuid,uuid,text,text,text,text,text)'),
  ('public.cancel_relay_authority_switch(uuid,uuid,text,text,text,text,text,text)'),
  ('public.read_relay_authority_cancellation(uuid,text)'),('public.guard_relay_authority_cancellation()')) f(signature)
  LEFT JOIN pg_proc p ON p.oid=to_regprocedure(f.signature)
  WHERE p.oid IS NULL OR NOT p.prosecdef OR p.proowner<>'nethub_owner'::regrole
   OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']::text[])
 AND EXISTS(SELECT FROM pg_proc WHERE oid='public.retain_relay_authority_cancellation()'::regprocedure
  AND proowner='nethub_owner'::regrole AND proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[])
 AND NOT EXISTS(SELECT FROM pg_roles r WHERE rolname IN ('nethub_web','nethub_authz','nethub_issuer')
  AND (has_table_privilege(r.oid,'public.relay_authority_cancellations','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
   OR has_any_column_privilege(r.oid,'public.relay_authority_cancellations','SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT FROM (VALUES
  ('public.private_relay_authority_switch_fence_v15()'),
  ('public.private_begin_relay_authority_switch_v15(uuid,uuid,text,text,text,text,text)'),
  ('public.cancel_relay_authority_switch(uuid,uuid,text,text,text,text,text,text)'),
  ('public.read_relay_authority_cancellation(uuid,text)')) f(signature)
  JOIN pg_proc p ON p.oid=to_regprocedure(f.signature),
  LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE a.privilege_type='EXECUTE' AND (a.grantee=0 OR a.grantee IN ('nethub_web'::regrole,'nethub_authz'::regrole)))
 AND NOT EXISTS(SELECT FROM pg_roles r WHERE rolname='nethub_issuer' AND
  (has_function_privilege(r.oid,'public.private_relay_authority_switch_fence_v15()','EXECUTE') OR
   has_function_privilege(r.oid,'public.private_begin_relay_authority_switch_v15(uuid,uuid,text,text,text,text,text)','EXECUTE')))
 AND (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled IN ('O','A') AND
  ((tgrelid='public.relay_authority_cancellations'::regclass AND tgname='relay_authority_cancellation_immutable' AND tgfoid='public.retain_relay_authority_cancellation()'::regprocedure)
   OR (tgrelid='public.relay_authority_cancellations'::regclass AND tgname='relay_authority_cancellation_switch_guard' AND tgfoid='public.guard_relay_authority_cancellation()'::regprocedure)
   OR (tgrelid='public.relay_authority_switches'::regclass AND tgname='relay_authority_cancelled_switch_guard' AND tgfoid='public.guard_relay_authority_cancellation()'::regprocedure)))=3;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION relay_authority_cancellation_fence_ready() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION relay_authority_switch_fence_ready() RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT public.private_relay_authority_switch_fence_v15() AND public.relay_authority_cancellation_fence_ready();
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION relay_authority_switch_fence_ready() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION relay_authority_switch_fence_ready() TO nethub_authz;

-- +goose StatementBegin
CREATE FUNCTION begin_relay_authority_switch(p_id uuid,p_expected uuid,p_name text,p_old text,p_new text,p_before text,p_after text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF session_user<>'nethub_issuer' THEN RAISE EXCEPTION 'Host issuer identity denied' USING ERRCODE='42501'; END IF;
 IF NOT public.relay_authority_switch_fence_ready() THEN RAISE EXCEPTION 'Authority switch fence unavailable'; END IF;
 PERFORM 1 FROM public.relay_trust_head WHERE singleton FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Relay trust head missing'; END IF;
 IF EXISTS(SELECT FROM public.relay_authority_cancellations WHERE id=p_id) THEN RETURN NULL; END IF;
 RETURN public.private_begin_relay_authority_switch_v15(p_id,p_expected,p_name,p_old,p_new,p_before,p_after);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION begin_relay_authority_switch(uuid,uuid,text,text,text,text,text) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION cancel_relay_authority_switch(p_id uuid,p_expected uuid,p_name text,p_old text,p_new text,p_before text,p_after text,p_intent text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE existing public.relay_authority_cancellations%ROWTYPE;
BEGIN
 IF session_user<>'nethub_issuer' THEN RAISE EXCEPTION 'Host issuer identity denied' USING ERRCODE='42501'; END IF;
 IF NOT public.relay_authority_switch_fence_ready() THEN RAISE EXCEPTION 'Authority switch fence unavailable'; END IF;
 IF p_id IS NULL OR p_id='00000000-0000-0000-0000-000000000000'::uuid OR p_expected IS NULL OR p_expected='00000000-0000-0000-0000-000000000000'::uuid
  OR p_name IS NULL OR octet_length(p_name) NOT BETWEEN 1 AND 253
  OR p_old IS NULL OR p_old!~'^[a-f0-9]{64}$' OR p_new IS NULL OR p_new!~'^[a-f0-9]{64}$' OR p_old=p_new
  OR p_before IS NULL OR p_before!~'^[a-f0-9]{64}$' OR p_after IS NULL OR p_after!~'^[a-f0-9]{64}$' OR p_before=p_after
  OR p_intent IS NULL OR p_intent!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'Invalid cancellation identity' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.relay_trust_head WHERE singleton FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Relay trust head missing'; END IF;
 IF EXISTS(SELECT FROM public.relay_authority_switches WHERE id=p_id) THEN RETURN NULL; END IF;
 SELECT * INTO existing FROM public.relay_authority_cancellations WHERE id=p_id;
 IF FOUND THEN
  IF existing.trust_generation_id=p_expected AND existing.server_name=p_name AND existing.previous_root=p_old AND existing.next_root=p_new
   AND existing.previous_leaf=p_before AND existing.next_leaf=p_after AND existing.intent_sha256=p_intent THEN RETURN to_jsonb(existing); END IF;
  RETURN NULL;
 END IF;
 INSERT INTO public.relay_authority_cancellations(id,trust_generation_id,server_name,previous_root,next_root,previous_leaf,next_leaf,intent_sha256)
 VALUES(p_id,p_expected,p_name,p_old,p_new,p_before,p_after,p_intent) RETURNING * INTO existing;
 RETURN to_jsonb(existing);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION cancel_relay_authority_switch(uuid,uuid,text,text,text,text,text,text) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION read_relay_authority_cancellation(p_id uuid,p_name text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE existing public.relay_authority_cancellations%ROWTYPE;
BEGIN
 IF session_user<>'nethub_issuer' THEN RAISE EXCEPTION 'Host issuer identity denied' USING ERRCODE='42501'; END IF;
 IF NOT public.relay_authority_switch_fence_ready() THEN RAISE EXCEPTION 'Authority switch fence unavailable'; END IF;
 SELECT * INTO existing FROM public.relay_authority_cancellations WHERE id=p_id;
 IF NOT FOUND THEN RETURN NULL; END IF;
 IF existing.server_name IS DISTINCT FROM p_name THEN RAISE EXCEPTION 'Cancellation identity mismatch' USING ERRCODE='42501'; END IF;
 RETURN to_jsonb(existing);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION read_relay_authority_cancellation(uuid,text) FROM PUBLIC;

-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='nethub_issuer') THEN
  GRANT EXECUTE ON FUNCTION relay_authority_switch_fence_ready(),begin_relay_authority_switch(uuid,uuid,text,text,text,text,text),
   cancel_relay_authority_switch(uuid,uuid,text,text,text,text,text,text),read_relay_authority_cancellation(uuid,text) TO nethub_issuer;
 END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Authority cancellation history must be retained; restore a verified backup instead'; END $$;
