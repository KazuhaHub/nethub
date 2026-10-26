import type { SAMLProvider, SAMLProviderInput, SAMLProviderPatch } from "./api";

export type SAMLDraft = {
  original: SAMLProvider | null;
  slug: string;
  name: string;
  entity: string;
  email: string;
  metadata: string;
  enabled: boolean;
};
export function samlDraft(provider: SAMLProvider | null): SAMLDraft {
  return {
    original: provider,
    slug: provider?.slug ?? "",
    name: provider?.display_name ?? "",
    entity: provider?.entity_id ?? "",
    email: provider?.email_attribute ?? "mail",
    metadata: "",
    enabled: provider?.enabled ?? false,
  };
}
export function samlChanges(
  draft: SAMLDraft,
): SAMLProviderInput | SAMLProviderPatch {
  if (new TextEncoder().encode(draft.metadata).length > 1 << 20)
    throw new Error("IdP metadata must be no larger than 1 MiB.");
  if (!draft.original && !draft.metadata.trim())
    throw new Error("Paste trusted IdP metadata XML.");
  if (
    draft.original &&
    draft.entity !== draft.original.entity_id &&
    !draft.metadata.trim()
  )
    throw new Error("Paste matching metadata when changing the IdP entity ID.");
  const values = {
    display_name: draft.name,
    entity_id: draft.entity,
    email_attribute: draft.email,
    enabled: draft.enabled,
  };
  if (!draft.original)
    return { ...values, slug: draft.slug, metadata_xml: draft.metadata };
  const patch: SAMLProviderPatch = {};
  for (const key of [
    "display_name",
    "entity_id",
    "email_attribute",
    "enabled",
  ] as const) {
    if (values[key] !== draft.original[key])
      Object.assign(patch, { [key]: values[key] });
  }
  if (draft.metadata.trim()) patch.metadata_xml = draft.metadata;
  return patch;
}
export function samlProjection(value: unknown): value is SAMLProvider {
  if (!value || typeof value !== "object") return false;
  const p = value as Record<string, unknown>;
  return (
    !["sp_key_enc", "signing_key", "private_key", "metadata_xml"].some(
      (key) => key in p,
    ) &&
    typeof p.id === "string" &&
    /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(p.id) &&
    typeof p.slug === "string" &&
    /^[a-z0-9][a-z0-9-]{0,62}$/.test(p.slug) &&
    typeof p.display_name === "string" &&
    p.display_name.length > 0 &&
    p.display_name.length <= 200 &&
    typeof p.entity_id === "string" &&
    p.entity_id.length > 0 &&
    p.entity_id.length <= 2048 &&
    typeof p.email_attribute === "string" &&
    p.email_attribute.length > 0 &&
    p.email_attribute.length <= 512 &&
    typeof p.enabled === "boolean" &&
    typeof p.has_signing_key === "boolean" &&
    typeof p.metadata_uri === "string" &&
    typeof p.acs_uri === "string" &&
    typeof p.created_at === "string" &&
    Number.isFinite(Date.parse(p.created_at))
  );
}
export function verifiedSAMLAddresses(provider: SAMLProvider, origin: string) {
  const metadata = `${origin}/api/v1/console/saml/${provider.slug}/metadata`;
  const acs = `${origin}/api/v1/console/saml/${provider.slug}/callback`;
  return provider.metadata_uri === metadata && provider.acs_uri === acs
    ? { metadata, acs }
    : null;
}
