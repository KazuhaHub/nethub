import type { OIDCProvider, OIDCProviderInput, OIDCProviderPatch } from "./api";

export type ProviderDraft = {
  original: OIDCProvider | null;
  slug: string;
  name: string;
  issuer: string;
  client: string;
  scopes: string;
  enabled: boolean;
  secret: string;
  removeSecret: boolean;
};

export function providerDraft(provider: OIDCProvider | null): ProviderDraft {
  return {
    original: provider,
    slug: provider?.slug ?? "",
    name: provider?.display_name ?? "",
    issuer: provider?.issuer_url ?? "",
    client: provider?.client_id ?? "",
    scopes: provider?.scopes.join(" ") ?? "openid email profile",
    enabled: provider?.enabled ?? false,
    secret: "",
    removeSecret: false,
  };
}

export function providerChanges(
  draft: ProviderDraft,
): OIDCProviderInput | OIDCProviderPatch {
  const scopes = draft.scopes.trim().split(/\s+/);
  if (
    scopes.length > 32 ||
    !scopes.includes("openid") ||
    new Set(scopes).size !== scopes.length ||
    scopes.some(
      (value) =>
        !value ||
        value.length > 128 ||
        !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(value),
    )
  )
    throw new Error("Enter distinct space-separated scopes including openid.");
  if (draft.removeSecret && draft.secret)
    throw new Error("Choose either a replacement secret or removal.");
  const values = {
    display_name: draft.name,
    issuer_url: draft.issuer,
    client_id: draft.client,
    scopes,
    enabled: draft.enabled,
  };
  if (!draft.original)
    return {
      ...values,
      slug: draft.slug,
      ...(draft.secret ? { client_secret: draft.secret } : {}),
    };
  const patch: OIDCProviderPatch = {};
  if (values.display_name !== draft.original.display_name)
    patch.display_name = values.display_name;
  if (values.issuer_url !== draft.original.issuer_url)
    patch.issuer_url = values.issuer_url;
  if (values.client_id !== draft.original.client_id)
    patch.client_id = values.client_id;
  if (JSON.stringify(values.scopes) !== JSON.stringify(draft.original.scopes))
    patch.scopes = values.scopes;
  if (values.enabled !== draft.original.enabled) patch.enabled = values.enabled;
  if (draft.removeSecret) patch.client_secret = "";
  else if (draft.secret) patch.client_secret = draft.secret;
  return patch;
}

export function providerProjection(value: unknown): value is OIDCProvider {
  if (!value || typeof value !== "object") return false;
  const p = value as Record<string, unknown>;
  return (
    !Object.keys(p).some((key) =>
      ["client_secret", "client_secret_enc"].includes(key),
    ) &&
    typeof p.id === "string" &&
    /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(p.id) &&
    typeof p.slug === "string" &&
    /^[a-z0-9][a-z0-9-]{0,62}$/.test(p.slug) &&
    typeof p.display_name === "string" &&
    typeof p.issuer_url === "string" &&
    typeof p.client_id === "string" &&
    typeof p.has_client_secret === "boolean" &&
    typeof p.enabled === "boolean" &&
    Array.isArray(p.scopes) &&
    p.scopes.every((s) => typeof s === "string") &&
    typeof p.redirect_uri === "string" &&
    typeof p.created_at === "string" &&
    Number.isFinite(Date.parse(p.created_at))
  );
}
