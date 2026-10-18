-- +goose Up
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO nethub_web, nethub_authz, nethub_backup;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE tenants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    local_admin_count integer NOT NULL DEFAULT 0 CHECK (local_admin_count >= 0),
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO tenants (name) VALUES ('NetHub');

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    email text NOT NULL CHECK (length(email) BETWEEN 3 AND 320),
    password_hash text,
    role text NOT NULL CHECK (role IN ('admin', 'member')),
    created_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX users_tenant_email ON users(tenant_id, lower(email));

CREATE TABLE identity_providers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    kind text NOT NULL CHECK (kind IN ('oidc', 'saml')),
    slug text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    display_name text NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id), UNIQUE (tenant_id, id, kind), UNIQUE (tenant_id, slug)
);
CREATE TABLE oidc_providers (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    kind text GENERATED ALWAYS AS ('oidc'::text) STORED,
    issuer_url text NOT NULL,
    client_id text NOT NULL,
    client_secret_enc bytea,
    scopes text[] NOT NULL DEFAULT ARRAY['openid', 'email', 'profile'],
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, id, kind) REFERENCES identity_providers(tenant_id, id, kind)
);
CREATE TABLE saml_providers (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    kind text GENERATED ALWAYS AS ('saml'::text) STORED,
    entity_id text NOT NULL,
    metadata_xml text NOT NULL,
    email_attribute text NOT NULL,
    sp_key_enc bytea,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, id, kind) REFERENCES identity_providers(tenant_id, id, kind)
);
CREATE TABLE user_identities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    protocol text NOT NULL CHECK (protocol IN ('oidc', 'saml')),
    issuer text NOT NULL,
    subject text NOT NULL CHECK (length(subject) > 0),
    email_at_link text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id),
    FOREIGN KEY (tenant_id, provider_id, protocol) REFERENCES identity_providers(tenant_id, id, kind),
    UNIQUE (tenant_id, protocol, issuer, subject)
);
CREATE TABLE invites (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    email text NOT NULL,
    role text NOT NULL CHECK (role IN ('admin', 'member')),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_by_user_id uuid NOT NULL,
    provider_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT now() + interval '72 hours',
    used_at timestamptz,
    cancelled_at timestamptz,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '72 hours'),
    FOREIGN KEY (tenant_id, created_by_user_id) REFERENCES users(tenant_id, id),
    FOREIGN KEY (tenant_id, provider_id) REFERENCES identity_providers(tenant_id, id)
);
CREATE TABLE sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    csrf_hash bytea NOT NULL CHECK (octet_length(csrf_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    ip inet NOT NULL,
    user_agent text NOT NULL,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id)
);
CREATE TABLE devices (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    hostname text NOT NULL DEFAULT '',
    label text NOT NULL DEFAULT '' CHECK (length(label) <= 64),
    platform text NOT NULL CHECK (platform = 'opnsense'),
    capabilities text[] NOT NULL DEFAULT ARRAY['remote.web'],
    device_secret_hash text NOT NULL,
    subdomain text NOT NULL UNIQUE CHECK (subdomain ~ '^[a-z0-9-]{1,63}$'),
    domain_claim_issued_at timestamptz NOT NULL DEFAULT now(),
    cluster_hint text,
    agent_protocol_version text NOT NULL,
    enrolled_at timestamptz NOT NULL DEFAULT now(),
    revoked boolean NOT NULL DEFAULT false,
    revoked_at timestamptz,
    revoked_by_user_id uuid,
    last_seen_at timestamptz,
    platform_version text NOT NULL DEFAULT '',
    agent_version text NOT NULL DEFAULT '',
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, owner_user_id) REFERENCES users(tenant_id, id),
    FOREIGN KEY (tenant_id, revoked_by_user_id) REFERENCES users(tenant_id, id),
    CHECK (NOT revoked OR revoked_at IS NOT NULL)
);
CREATE TABLE enroll_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT now() + interval '15 minutes',
    used_at timestamptz,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes'),
    FOREIGN KEY (tenant_id, created_by_user_id) REFERENCES users(tenant_id, id)
);
CREATE TABLE device_access_grants (
    tenant_id uuid NOT NULL,
    device_id uuid NOT NULL,
    user_id uuid NOT NULL,
    source_ip inet NOT NULL CHECK (masklen(source_ip) = CASE family(source_ip) WHEN 4 THEN 32 ELSE 128 END),
    granted_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, device_id, user_id, source_ip),
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id),
    CHECK (expires_at = granted_at + interval '30 minutes')
);
CREATE TABLE device_disconnect_requests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    device_id uuid NOT NULL,
    requested_by_user_id uuid NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT now(),
    processed_at timestamptz,
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, id),
    FOREIGN KEY (tenant_id, requested_by_user_id) REFERENCES users(tenant_id, id)
);
CREATE TABLE audit_log (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    sequence bigint NOT NULL,
    actor_type text NOT NULL CHECK (actor_type IN ('user', 'system', 'device')),
    actor_id uuid,
    action text NOT NULL,
    target_device_id uuid,
    payload jsonb NOT NULL,
    prev_hash bytea NOT NULL,
    entry_hash bytea NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, sequence)
);

-- +goose StatementBegin
DO $policies$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['users','identity_providers','oidc_providers','saml_providers',
        'user_identities','invites','sessions','devices','enroll_tokens','device_access_grants',
        'device_disconnect_requests','audit_log'] LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)', table_name);
    END LOOP;
END
$policies$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION guard_local_admin() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE before_count integer := 0; after_count integer := 0; tenant uuid;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        tenant := OLD.tenant_id;
        before_count := CASE WHEN OLD.role = 'admin' AND OLD.disabled_at IS NULL AND OLD.password_hash IS NOT NULL THEN 1 ELSE 0 END;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        tenant := NEW.tenant_id;
        after_count := CASE WHEN NEW.role = 'admin' AND NEW.disabled_at IS NULL AND NEW.password_hash IS NOT NULL THEN 1 ELSE 0 END;
        IF TG_OP = 'UPDATE' AND NEW.tenant_id <> OLD.tenant_id THEN
            RAISE EXCEPTION 'User tenant cannot be changed' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF after_count <> before_count THEN
        UPDATE public.tenants SET local_admin_count = local_admin_count + after_count - before_count
        WHERE id = tenant AND (after_count > before_count OR local_admin_count > 1);
        IF NOT FOUND THEN
            RAISE EXCEPTION 'At least one enabled local-password admin must remain' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER users_local_admin BEFORE INSERT OR UPDATE OR DELETE ON users FOR EACH ROW EXECUTE FUNCTION guard_local_admin();

-- +goose StatementBegin
CREATE FUNCTION guard_revocation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.revoked AND NOT NEW.revoked THEN
        RAISE EXCEPTION 'Device revocation cannot be reversed' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER devices_revocation BEFORE UPDATE ON devices FOR EACH ROW EXECUTE FUNCTION guard_revocation();

-- +goose StatementBegin
CREATE FUNCTION consume_enroll_token(p_hash bytea)
RETURNS TABLE (tenant_id uuid, created_by_user_id uuid)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    UPDATE public.enroll_tokens AS token SET used_at = clock_timestamp()
    WHERE token.token_hash = p_hash AND token.used_at IS NULL
      AND token.created_at <= clock_timestamp() AND token.expires_at > clock_timestamp()
      AND token.expires_at <= token.created_at + interval '15 minutes'
      AND EXISTS (SELECT FROM public.users u WHERE u.id = token.created_by_user_id
                  AND u.tenant_id = token.tenant_id AND u.disabled_at IS NULL)
    RETURNING token.tenant_id, token.created_by_user_id;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION consume_enroll_token(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consume_enroll_token(bytea) TO nethub_authz;

GRANT SELECT (id, name, created_at) ON tenants TO nethub_web, nethub_authz;
GRANT SELECT, INSERT, UPDATE, DELETE ON users, identity_providers, oidc_providers,
    saml_providers, user_identities, invites, sessions TO nethub_web;
GRANT SELECT (id, tenant_id, owner_user_id, hostname, label, platform, capabilities,
    subdomain, cluster_hint, enrolled_at, revoked, revoked_at, revoked_by_user_id,
    last_seen_at, platform_version, agent_version) ON devices TO nethub_web;
GRANT UPDATE (label, revoked, revoked_at, revoked_by_user_id) ON devices TO nethub_web;
GRANT SELECT, INSERT, UPDATE ON devices TO nethub_authz;
GRANT INSERT (tenant_id, token_hash, created_by_user_id) ON enroll_tokens TO nethub_web;
GRANT SELECT (id, tenant_id, created_by_user_id, created_at, expires_at, used_at) ON enroll_tokens TO nethub_web;
GRANT SELECT ON audit_log TO nethub_web;
GRANT SELECT ON device_access_grants, device_disconnect_requests TO nethub_authz;
GRANT UPDATE (processed_at) ON device_disconnect_requests TO nethub_authz;

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'Core identity migration is irreversible; restore a verified backup instead'; END $$;
