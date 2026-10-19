-- +goose Up
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION consume_enroll_token(p_hash bytea)
RETURNS TABLE (tenant_id uuid, created_by_user_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE actor uuid; scope uuid;
BEGIN
    SELECT u.id, u.tenant_id INTO actor, scope
    FROM public.enroll_tokens t JOIN public.users u
      ON u.id = t.created_by_user_id AND u.tenant_id = t.tenant_id
    WHERE t.token_hash = p_hash
    FOR SHARE OF u;
    IF NOT FOUND THEN RETURN; END IF;

    -- Lock in user/token order, then check expiry using the post-wait clock.
    PERFORM 1 FROM public.enroll_tokens t WHERE t.token_hash = p_hash FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    RETURN QUERY
    UPDATE public.enroll_tokens t SET used_at = clock_timestamp()
    WHERE t.token_hash = p_hash AND t.tenant_id = scope AND t.created_by_user_id = actor
      AND t.used_at IS NULL AND t.created_at <= clock_timestamp()
      AND t.expires_at > clock_timestamp()
      AND t.expires_at <= t.created_at + interval '15 minutes'
      AND EXISTS (SELECT FROM public.users u
                  WHERE u.id = actor AND u.tenant_id = scope AND u.disabled_at IS NULL)
    RETURNING t.tenant_id, t.created_by_user_id;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION consume_enroll_token(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consume_enroll_token(bytea) TO nethub_authz;

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Enrollment locking must not be weakened; restore a verified backup instead'; END $$;
