export type User = { id: string; email: string; role: "admin" | "member" };
export type Session = {
  user: User;
  csrf_token: string;
  session_expires_at: string;
};
export type Device = {
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
export type DevicePage = { items: Device[]; next_cursor: string | null };
export type Enrollment = { token: string; expires_at: string };
export type Revocation = { revoked: true; revoked_at: string };

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
      method: body === undefined ? "GET" : "POST",
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
  async session(signal?: AbortSignal) {
    const data = await request<
      ({ signed_in: true } & Session) | { signed_in: false }
    >("/session", undefined, signal);
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
  devices(
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
    return request<DevicePage>(
      `/devices?${query}`,
      undefined,
      signal,
      background,
    );
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
};
