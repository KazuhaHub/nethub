export type User = { id: string; email: string; role: "admin" | "member" };
export type TrafficDevice = {
  device_id: string;
  label: string;
  hostname: string;
  removed: boolean;
  in_bytes: string;
  out_bytes: string;
  total_bytes: string;
  reset_events: string;
  first_observed_at: string;
  last_observed_at: string;
};
export type TrafficPage = {
  month: string;
  in_bytes: string;
  out_bytes: string;
  total_bytes: string;
  reset_events: string;
  first_observed_at: string | null;
  last_observed_at: string | null;
  warning_bytes: string | null;
  warning: boolean;
  warning_revision: number;
  items: TrafficDevice[];
  next_cursor: string | null;
};
export type ManagedUser = User & {
  disabled: boolean;
  has_password: boolean;
  identities: { provider_slug: string; linked_at: string }[];
  created_at: string;
};
export type UserPage = { items: ManagedUser[]; next_cursor: string | null };
export type OIDCProvider = {
  id: string;
  slug: string;
  display_name: string;
  issuer_url: string;
  client_id: string;
  has_client_secret: boolean;
  scopes: string[];
  enabled: boolean;
  redirect_uri: string;
  created_at: string;
};
export type OIDCProviderPage = {
  items: OIDCProvider[];
  next_cursor: string | null;
};
export type OIDCProviderInput = Pick<
  OIDCProvider,
  "slug" | "display_name" | "issuer_url" | "client_id" | "scopes" | "enabled"
> & { client_secret?: string };
export type OIDCProviderPatch = Partial<Omit<OIDCProviderInput, "slug">>;
export type LoginProvider = {
  slug: string;
  display_name: string;
  protocol?: "oidc" | "saml";
};
export type SAMLProvider = {
  id: string;
  slug: string;
  display_name: string;
  entity_id: string;
  email_attribute: string;
  enabled: boolean;
  has_signing_key: boolean;
  created_at: string;
  metadata_uri: string;
  acs_uri: string;
};
export type SAMLProviderPage = {
  items: SAMLProvider[];
  next_cursor: string | null;
};
export type SAMLProviderInput = Pick<
  SAMLProvider,
  "slug" | "display_name" | "entity_id" | "email_attribute" | "enabled"
> & { metadata_xml: string };
export type SAMLProviderPatch = Partial<Omit<SAMLProviderInput, "slug">>;
export type UserPatch = { role?: User["role"]; disabled?: boolean };
export type Invitation = {
  id: string;
  email: string;
  role: User["role"];
  provider_id: string | null;
  created_at: string;
  expires_at: string;
  created_by: { id: string; email: string };
};
export type InvitationPage = {
  items: Invitation[];
  next_cursor: string | null;
};
export type IssuedInvitation = {
  id: string;
  invite_url: string;
  expires_at: string;
};
export type InvitationInfo = {
  email: string;
  role: User["role"];
  expires_at: string;
  password_allowed: boolean;
  providers: { slug: string; display_name: string; kind: "oidc" | "saml" }[];
};
export type Session = {
  user: User;
  csrf_token: string;
  session_expires_at: string;
};
export type Device = {
  disconnect?: Disconnect | null;
  id: string;
  label: string;
  hostname: string;
  subdomain: string;
  url: string;
  platform: string;
  platform_version: string;
  agent_version: string;
  capabilities: string[];
  cluster_hint: string | null;
  online: boolean;
  last_seen_at: string | null;
  enrolled_at: string;
  revoked: boolean;
  revoked_at: string | null;
  owner: { id: string; email: string };
  gui_certificate?: {
    state:
      | "unsupported"
      | "pending"
      | "failed"
      | "applied"
      | "renewing"
      | "renewal_failed"
      | "expired"
      | "revoked";
    assigned_host: string | null;
    valid_until: string | null;
    confirmed_at: string | null;
  };
};
export type RelayAlert = {
  id: string;
  device_id: string | null;
  kind: "unknown_proxy" | "domain_mismatch" | "revoked_online";
  response: "alarm_only" | "revoked" | "already_revoked";
  confirmed_at: string;
};
export type DevicePage = {
  items: Device[];
  next_cursor: string | null;
  relay_alerts?: RelayAlert[];
};

export function validRelayAlerts(value: unknown): value is RelayAlert[] {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  if (!Array.isArray(value) || value.length > 100) return false;
  const seen = new Set<string>();
  return value.every((item) => {
    if (
      !item ||
      typeof item !== "object" ||
      typeof item.id !== "string" ||
      !uuid.test(item.id) ||
      seen.has(item.id) ||
      typeof item.confirmed_at !== "string" ||
      !Number.isFinite(Date.parse(item.confirmed_at))
    )
      return false;
    seen.add(item.id);
    if (item.kind === "unknown_proxy")
      return item.device_id === null && item.response === "alarm_only";
    if (typeof item.device_id !== "string" || !uuid.test(item.device_id))
      return false;
    return (
      (item.kind === "domain_mismatch" &&
        ["alarm_only", "revoked"].includes(item.response)) ||
      (item.kind === "revoked_online" &&
        ["alarm_only", "already_revoked"].includes(item.response))
    );
  });
}
export type Enrollment = { token: string; expires_at: string };
export type Revocation = { revoked: true; revoked_at: string };
export type Disconnect = {
  request_id: string;
  requested_at: string;
  armed_at: string | null;
  state: "pending" | "armed";
};

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

let csrf = "";
let unauthorized = () => {};
export function onUnauthorized(callback: () => void) {
  unauthorized = callback;
  return () => {
    unauthorized = () => {};
  };
}
export function clearSession() {
  csrf = "";
}

async function request<T>(
  path: string,
  body?: object,
  signal?: AbortSignal,
  background = false,
  method = body === undefined ? "GET" : "POST",
): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (background) headers["X-NetHub-Background"] = "1";
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (method !== "GET" && method !== "HEAD" && csrf)
    headers["X-CSRF-Token"] = csrf;
  let response: Response;
  try {
    response = await fetch(`/api/v1/console${path}`, {
      method,
      credentials: "same-origin",
      cache: "no-store",
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new ApiError(
      0,
      "connection_failed",
      "Could not reach the console. Check your connection and try again.",
    );
  }
  if (response.status === 401) {
    clearSession();
    unauthorized();
  }
  if (!response.ok) {
    if (response.status === 429) {
      const seconds = Math.min(
        3600,
        Math.max(1, Number(response.headers.get("Retry-After")) || 1),
      );
      throw new ApiError(
        429,
        "rate_limited",
        `Too many attempts. Try again in ${seconds} seconds.`,
      );
    }
    const data = await response.json().catch(() => null);
    const code =
      typeof data?.error?.code === "string"
        ? data.error.code
        : "request_failed";
    const message =
      typeof data?.error?.message === "string" &&
      data.error.message.length <= 300
        ? data.error.message
        : "The request could not be completed. Try again.";
    throw new ApiError(response.status, code, message);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export const api = {
  traffic(
    month: string,
    cursor: string | null,
    signal?: AbortSignal,
    background = false,
  ) {
    const query = new URLSearchParams({ month, limit: "50" });
    if (cursor) query.set("cursor", cursor);
    return request<TrafficPage>(
      `/traffic?${query}`,
      undefined,
      signal,
      background,
    );
  },
  setTrafficWarning(warning_bytes: string, expected_revision: number) {
    return request<{ warning_bytes: string | null; revision: number }>(
      "/traffic/settings",
      { warning_bytes, expected_revision },
      AbortSignal.timeout(15000),
      false,
      "PATCH",
    );
  },
  samlProviders(
    cursor: string | null,
    signal?: AbortSignal,
    background = false,
  ) {
    const query = new URLSearchParams({ limit: "50" });
    if (cursor) query.set("cursor", cursor);
    return request<SAMLProviderPage>(
      `/saml-providers?${query}`,
      undefined,
      signal,
      background,
    );
  },
  createSAMLProvider(input: SAMLProviderInput) {
    return providerMutation<SAMLProvider>("/saml-providers", input);
  },
  updateSAMLProvider(id: string, patch: SAMLProviderPatch) {
    return providerMutation<SAMLProvider>(
      `/saml-providers/${encodeURIComponent(id)}`,
      patch,
      "PATCH",
    );
  },
  deleteSAMLProvider(id: string) {
    return providerMutation<void>(
      `/saml-providers/${encodeURIComponent(id)}`,
      undefined,
      "DELETE",
    );
  },
  async ssoProviders(
    signal?: AbortSignal,
  ): Promise<{ items: LoginProvider[]; partial: boolean }> {
    const results = await Promise.allSettled([
      api.loginProviders(signal),
      request<{ items: LoginProvider[] }>(
        "/saml/providers",
        undefined,
        signal,
      ).then((value) => {
        if (
          !Array.isArray(value.items) ||
          !value.items.every(
            (p) =>
              p &&
              p.protocol === "saml" &&
              typeof p.slug === "string" &&
              /^[a-z0-9][a-z0-9-]{0,62}$/.test(p.slug) &&
              typeof p.display_name === "string" &&
              p.display_name.length > 0 &&
              p.display_name.length <= 200,
          )
        )
          throw new Error("SSO choices could not be verified.");
        return value;
      }),
    ]);
    if (results.every((result) => result.status === "rejected"))
      throw new Error("SSO choices are unavailable.");
    const items = results.flatMap((result, index) =>
      result.status === "fulfilled"
        ? result.value.items.map((p) => ({
            ...p,
            protocol: index === 0 ? ("oidc" as const) : ("saml" as const),
          }))
        : [],
    );
    const partial = results.some((result) => result.status === "rejected");
    if (partial && items.length === 0)
      throw new Error("SSO choices are unavailable.");
    return { items, partial };
  },
  async startSAML(slug: string, invite?: string) {
    const result = await request<{ redirect_url: string }>(
      `/saml/${encodeURIComponent(slug)}/start`,
      invite ? { invite_token: invite } : {},
      AbortSignal.timeout(15000),
    );
    if (!validSSODestination(result.redirect_url))
      throw new Error(
        "The sign-in destination could not be verified. Try starting again.",
      );
    return result.redirect_url;
  },
  oidcProviders(
    cursor: string | null,
    signal?: AbortSignal,
    background = false,
  ) {
    const query = new URLSearchParams({ limit: "50" });
    if (cursor) query.set("cursor", cursor);
    return request<OIDCProviderPage>(
      `/oidc-providers?${query}`,
      undefined,
      signal,
      background,
    );
  },
  createOIDCProvider(input: OIDCProviderInput) {
    return providerMutation<OIDCProvider>("/oidc-providers", input);
  },
  updateOIDCProvider(id: string, patch: OIDCProviderPatch) {
    return providerMutation<OIDCProvider>(
      `/oidc-providers/${encodeURIComponent(id)}`,
      patch,
      "PATCH",
    );
  },
  deleteOIDCProvider(id: string) {
    return providerMutation<void>(
      `/oidc-providers/${encodeURIComponent(id)}`,
      undefined,
      "DELETE",
    );
  },
  async loginProviders(signal?: AbortSignal) {
    const value = await request<{ items: LoginProvider[] }>(
      "/oidc/providers",
      undefined,
      signal,
    );
    if (
      !Array.isArray(value.items) ||
      !value.items.every(
        (p) =>
          p &&
          typeof p.slug === "string" &&
          /^[a-z0-9][a-z0-9-]{0,62}$/.test(p.slug) &&
          typeof p.display_name === "string" &&
          p.display_name.length > 0 &&
          p.display_name.length <= 200,
      )
    )
      throw new Error("SSO choices could not be verified.");
    return value;
  },
  async startOIDC(slug: string, invite?: string) {
    const result = await request<{ redirect_url: string }>(
      `/oidc/${encodeURIComponent(slug)}/start`,
      invite ? { invite_token: invite } : {},
      AbortSignal.timeout(15000),
    );
    if (!validSSODestination(result.redirect_url))
      throw new Error(
        "The sign-in destination could not be verified. Try starting again.",
      );
    return result.redirect_url;
  },
  invitations(cursor: string | null, signal?: AbortSignal) {
    const query = new URLSearchParams({ limit: "50" });
    if (cursor) query.set("cursor", cursor);
    return request<InvitationPage>(`/invites?${query}`, undefined, signal);
  },
  issueInvitation(email: string, role: User["role"], providerId?: string) {
    return invitationMutation<IssuedInvitation>("/invites", {
      email,
      role,
      ...(providerId ? { provider_id: providerId } : {}),
    });
  },
  withdrawInvitation(id: string) {
    return invitationMutation<void>(
      `/invites/${encodeURIComponent(id)}`,
      undefined,
      "DELETE",
    );
  },
  inspectInvitation(token: string, signal?: AbortSignal) {
    return request<InvitationInfo>("/invites/inspect", { token }, signal);
  },
  async acceptInvitation(token: string, password: string) {
    const result = await invitationMutation<Session>("/invites/accept", {
      token,
      password,
    });
    csrf = result.csrf_token;
    return result;
  },
  users(cursor: string | null, signal?: AbortSignal, background = false) {
    const query = new URLSearchParams({ limit: "50" });
    if (cursor) query.set("cursor", cursor);
    return request<UserPage>(`/users?${query}`, undefined, signal, background);
  },
  async updateUser(id: string, patch: UserPatch) {
    const deadline = AbortSignal.timeout(15000);
    try {
      return await request<ManagedUser>(
        `/users/${encodeURIComponent(id)}`,
        patch,
        deadline,
        false,
        "PATCH",
      );
    } catch (error) {
      if (deadline.aborted)
        throw new ApiError(
          0,
          "change_unconfirmed",
          "Could not confirm the change. Refresh before trying again.",
        );
      throw error;
    }
  },
  async session(signal?: AbortSignal, background = false) {
    const data = await request<
      ({ signed_in: true } & Session) | { signed_in: false }
    >("/session", undefined, signal, background);
    csrf = data.signed_in ? data.csrf_token : "";
    return data.signed_in ? data : null;
  },
  async login(email: string, password: string) {
    const data = await request<Session>("/login", { email, password });
    csrf = data.csrf_token;
    return data;
  },
  async logout() {
    await request<void>("/logout", {});
    clearSession();
  },
  async devices(
    cursor: string | null,
    status: string,
    signal?: AbortSignal,
    background = false,
  ) {
    const query = new URLSearchParams({ limit: "50" });
    if (cursor) query.set("cursor", cursor);
    if (status === "online" || status === "offline")
      query.set("online", String(status === "online"));
    if (status === "revoked") query.set("revoked", "true");
    const page = await request<DevicePage>(
      `/devices?${query}`,
      undefined,
      signal,
      background,
    );
    if (page.relay_alerts !== undefined && !validRelayAlerts(page.relay_alerts))
      throw new Error("Relay alert data is unavailable. Try refreshing.");
    return page;
  },
  enroll(signal?: AbortSignal) {
    return request<Enrollment>("/enroll-tokens", {}, signal);
  },
  openDevice(id: string) {
    return request<{ url: string; gate_expires_at: string }>(
      `/devices/${encodeURIComponent(id)}/open`,
      {},
    );
  },
  revokeDevice(id: string) {
    return request<Revocation>(`/devices/${encodeURIComponent(id)}/revoke`, {});
  },
  requestDisconnect(id: string) {
    return request<Disconnect>(
      `/devices/${encodeURIComponent(id)}/disconnect`,
      {},
    );
  },
};

export function validSSODestination(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 8192) return false;
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.hostname !== "" &&
      !url.username &&
      !url.password &&
      !url.hash
    );
  } catch {
    return false;
  }
}

async function providerMutation<T>(
  path: string,
  body?: object,
  method = "POST",
): Promise<T> {
  const deadline = AbortSignal.timeout(15000);
  try {
    return await request<T>(path, body, deadline, false, method);
  } catch (error) {
    if (
      deadline.aborted ||
      !(error instanceof ApiError) ||
      error.status === 0 ||
      error.status >= 500
    )
      throw new ApiError(
        0,
        "provider_unconfirmed",
        "The change could not be confirmed. Close this dialog and refresh providers before trying again.",
      );
    throw error;
  }
}

async function invitationMutation<T>(
  path: string,
  body?: object,
  method = "POST",
): Promise<T> {
  const deadline = AbortSignal.timeout(15000);
  try {
    return await request<T>(path, body, deadline, false, method);
  } catch (error) {
    if (
      deadline.aborted ||
      !(error instanceof ApiError) ||
      error.status === 0 ||
      error.status >= 500
    )
      throw new ApiError(
        0,
        "invitation_unconfirmed",
        "The result could not be confirmed. Do not repeat this request automatically.",
      );
    throw error;
  }
}
