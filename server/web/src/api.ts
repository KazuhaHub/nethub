export type User = { id: string; email: string; role: "admin" | "member" };
export type ManagedUser = User & {
  disabled: boolean;
  has_password: boolean;
  identities: { provider_slug: string; linked_at: string }[];
  created_at: string;
};
export type UserPage = { items: ManagedUser[]; next_cursor: string | null };
export type UserPatch = { role?: User["role"]; disabled?: boolean };
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
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }
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
