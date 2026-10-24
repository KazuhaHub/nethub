import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  ArrowRight,
  Check,
  ChevronLeft,
  ChevronRight,
  Copy,
  KeyRound,
  LogOut,
  Moon,
  Network,
  Plus,
  RefreshCw,
  Router,
  Search,
  ShieldCheck,
  Sun,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  api,
  clearSession,
  onUnauthorized,
  type DevicePage,
  type Device,
  type Enrollment,
  type Session,
} from "./api";
import { NativeDialog } from "./dialog";
import {
  canOpenDevice,
  certificateLabel,
  deviceDestination,
} from "./device-access";

function DeviceAccess({ device }: { device: Device }) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const [grant, setGrant] = useState<{ url: string; expires: string } | null>(
    null,
  );
  async function openDevice() {
    if (pending || !canOpenDevice(device)) return;
    // Reserve the tab during the gesture; sever access before any navigation.
    const tab = window.open("about:blank", "_blank");
    if (tab) tab.opener = null;
    setPending(true);
    setError("");
    setGrant(null);
    try {
      const access = await api.openDevice(device.id);
      const destination = deviceDestination(device);
      if (
        !destination ||
        new URL(access.url).href !== destination.href ||
        !(Date.parse(access.gate_expires_at) > Date.now())
      ) {
        throw new Error("The console returned an invalid device destination.");
      }
      setGrant({ url: destination.href, expires: access.gate_expires_at });
      if (tab && !tab.closed) tab.location.replace(destination.href);
    } catch (error) {
      tab?.close();
      setError(message(error));
    } finally {
      setPending(false);
    }
  }
  const validGrant =
    grant && Date.parse(grant.expires) > Date.now() && canOpenDevice(device);
  return (
    <div className="device-access">
      <Button
        variant="outline"
        size="sm"
        disabled={pending || !canOpenDevice(device)}
        onClick={() => void openDevice()}
      >
        {pending ? "Opening…" : "Open"}
      </Button>
      {validGrant && (
        <p className="muted">
          <a href={grant.url} target="_blank" rel="noopener noreferrer">
            Continue to router
          </a>
          <br />
          Allowed until {new Date(grant.expires).toLocaleTimeString()}
        </p>
      )}
      {error && (
        <p className="error-message" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}

const message = (error: unknown) =>
  error instanceof Error
    ? error.message
    : "The request could not be completed.";
function Brand() {
  return (
    <span className="brand">
      <span className="brand-symbol">
        <Network aria-hidden="true" />
      </span>
      NetHub
    </span>
  );
}

function ThemeButton() {
  const [dark, setDark] = useState(() => {
    try {
      const saved = localStorage.getItem("nethub-theme");
      return saved
        ? saved === "dark"
        : matchMedia("(prefers-color-scheme: dark)").matches;
    } catch {
      return false;
    }
  });
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    try {
      localStorage.setItem("nethub-theme", dark ? "dark" : "light");
    } catch {
      /* Theme persistence is optional. */
    }
  }, [dark]);
  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={() => setDark(!dark)}
      aria-label={dark ? "Use light theme" : "Use dark theme"}
    >
      {dark ? <Sun /> : <Moon />}
    </Button>
  );
}

function SignIn({ onLogin }: { onLogin: (session: Session) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    const supplied = password;
    setPassword("");
    setBusy(true);
    setError("");
    try {
      onLogin(await api.login(email, supplied));
    } catch (error) {
      setError(message(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="signin-shell">
      <aside className="signin-story">
        <Brand />
        <div className="story-content">
          <span className="eyebrow">YOUR NETWORK. WITHIN REACH.</span>
          <h1>
            A familiar way
            <br />
            back to your network.
          </h1>
          <p>
            One console for your OPNsense firewalls.
            <br />
            Hosted by you. Connected on your terms.
          </p>
          <div className="network-art" aria-hidden="true">
            <span className="art-console">
              <Network />
            </span>
            <span className="art-line" />
            <span className="art-router">
              <Router />
            </span>
            <span className="art-dot" />
          </div>
        </div>
        <span className="story-footer">
          <ShieldCheck size={16} /> Self-hosted remote management
        </span>
      </aside>
      <main className="signin-main">
        <div className="signin-top">
          <span className="mobile-brand">
            <Brand />
          </span>
          <ThemeButton />
        </div>
        <section className="signin-form-wrap">
          <span className="form-icon">
            <KeyRound />
          </span>
          <h2>Sign in to NetHub</h2>
          <p className="muted">Use your console account to continue.</p>
          <form onSubmit={submit} aria-busy={busy}>
            <div className="field">
              <Label htmlFor="email">Email address</Label>
              <Input
                id="email"
                type="email"
                autoComplete="username"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                required
                maxLength={320}
                placeholder="you@example.com"
                autoFocus
              />
            </div>
            <div className="field">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
                maxLength={1024}
              />
            </div>
            {error && (
              <p role="alert" className="error-message">
                {error}
              </p>
            )}
            <Button className="signin-submit" disabled={busy} type="submit">
              {busy ? "Signing in…" : "Sign in"}
              <ArrowRight />
            </Button>
          </form>
          <p className="signin-note">
            Access is managed by your instance administrator.
          </p>
        </section>
        <footer className="signin-footer">
          NetHub console<span>Private by deployment</span>
        </footer>
      </main>
    </div>
  );
}

function EnrollmentDialog({
  open,
  close,
}: {
  open: boolean;
  close: () => void;
}) {
  const [issued, setIssued] = useState<Enrollment | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [expired, setExpired] = useState(false);
  const [seconds, setSeconds] = useState(0);
  const [copied, setCopied] = useState(false);
  const [originCopied, setOriginCopied] = useState(false);
  const pending = useRef<AbortController | null>(null);
  function reset() {
    pending.current?.abort();
    pending.current = null;
    setIssued(null);
    setBusy(false);
    setError("");
    setExpired(false);
    setCopied(false);
    setOriginCopied(false);
  }
  function dismiss() {
    reset();
    close();
  }
  useEffect(() => {
    if (!open) reset();
    return () => {
      pending.current?.abort();
    };
  }, [open]);
  useEffect(() => {
    if (!issued) return;
    function tick() {
      const remaining = Math.max(
        0,
        Math.ceil((Date.parse(issued!.expires_at) - Date.now()) / 1000),
      );
      setSeconds(remaining);
      if (!remaining) {
        setIssued(null);
        setExpired(true);
        setCopied(false);
        setOriginCopied(false);
      }
    }
    tick();
    const timer = setInterval(tick, 1000);
    return () => clearInterval(timer);
  }, [issued]);
  async function generate() {
    if (busy) return;
    const controller = new AbortController();
    pending.current = controller;
    setBusy(true);
    setError("");
    setExpired(false);
    try {
      const result = await api.enroll(controller.signal);
      if (!controller.signal.aborted) {
        setIssued(result);
        setCopied(false);
        setOriginCopied(false);
      }
    } catch (error) {
      if (!controller.signal.aborted) setError(message(error));
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }
  async function copy(kind: "token" | "origin") {
    if (!issued) return;
    try {
      await navigator.clipboard.writeText(
        kind === "token" ? issued.token : window.location.origin,
      );
      if (kind === "token") setCopied(true);
      else setOriginCopied(true);
    } catch {
      setError(
        "Clipboard access is unavailable. Select the value and copy it manually.",
      );
    }
  }
  return (
    <NativeDialog open={open} title="Add a device" onClose={dismiss}>
      <p className="muted dialog-description">
        Generate an enrollment token for your OPNsense NetHub plugin. It belongs
        to your account and can be used once.
      </p>
      {expired && (
        <p role="status" className="notice">
          This token expired. Generate a new one when you are ready.
        </p>
      )}
      {issued ? (
        <>
          <div className="token-heading">
            <Label htmlFor="enrollment-console-url">
              Console HTTPS address
            </Label>
            <Button variant="outline" size="sm" onClick={() => copy("origin")}>
              {originCopied ? <Check /> : <Copy />}
              {originCopied ? "Copied address" : "Copy console address"}
            </Button>
          </div>
          <Input
            id="enrollment-console-url"
            type="url"
            readOnly
            value={window.location.origin}
            onFocus={(event) => event.target.select()}
          />
          <div className="token-heading">
            <Label htmlFor="enrollment-token">Enrollment token</Label>
            <span className="expiry" aria-label="Time remaining">
              Expires in {Math.floor(seconds / 60)}:
              {String(seconds % 60).padStart(2, "0")}
            </span>
          </div>
          <textarea
            id="enrollment-token"
            className="token-value"
            readOnly
            value={issued.token}
            spellCheck={false}
            onFocus={(event) => event.target.select()}
          />
          <p className="token-warning">
            <ShieldCheck size={16} />
            Shown only once. Closing this dialog clears it.
          </p>
          <div className="dialog-actions">
            <Button variant="outline" onClick={() => copy("token")}>
              {copied ? <Check /> : <Copy />}
              {copied ? "Copied" : "Copy token"}
            </Button>
            <Button onClick={dismiss}>Done</Button>
          </div>
        </>
      ) : (
        <div className="token-placeholder">
          <span className="form-icon">
            <KeyRound />
          </span>
          <strong>Ready when your firewall is.</strong>
          <p className="muted">
            The token expires after 15 minutes.
            <br />
            Generate it just before enrolling.
          </p>
          <Button onClick={generate} disabled={busy}>
            {busy ? "Generating…" : "Generate token"}
          </Button>
        </div>
      )}
      {error && (
        <p role="alert" className="error-message">
          {error}
        </p>
      )}
    </NativeDialog>
  );
}

function Devices() {
  const [page, setPage] = useState<DevicePage>({
    items: [],
    next_cursor: null,
  });
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const [status, setStatus] = useState("all");
  const [search, setSearch] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [updated, setUpdated] = useState("");
  const [open, setOpen] = useState(false);
  const cursor = cursors[cursors.length - 1];
  useEffect(() => {
    const controller = new AbortController();
    let pending = false;
    async function load(background = false) {
      if (pending || controller.signal.aborted) return;
      pending = true;
      setLoading(true);
      setError("");
      try {
        const result = await api.devices(
          cursor,
          status,
          controller.signal,
          background,
        );
        if (!controller.signal.aborted) {
          setPage(result);
          setUpdated(
            new Date().toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
            }),
          );
        }
      } catch (error) {
        if (!controller.signal.aborted) setError(message(error));
      } finally {
        pending = false;
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    function refreshVisible() {
      if (document.visibilityState === "visible") void load(true);
    }
    void load();
    const timer = setInterval(refreshVisible, 5000);
    document.addEventListener("visibilitychange", refreshVisible);
    return () => {
      controller.abort();
      clearInterval(timer);
      document.removeEventListener("visibilitychange", refreshVisible);
    };
  }, [cursor, status, refresh]);
  const visible = page.items.filter((device) =>
    [device.label, device.hostname, device.subdomain, device.owner.email].some(
      (value) => value.toLowerCase().includes(search.toLowerCase()),
    ),
  );
  return (
    <>
      <header className="page-heading">
        <div>
          <span className="eyebrow">NETWORK INVENTORY</span>
          <h1>Devices</h1>
          <p className="muted">Your firewalls, wherever you need them.</p>
        </div>
        <Button onClick={() => setOpen(true)}>
          <Plus />
          Add device
        </Button>
      </header>
      <section
        className="device-panel"
        aria-label="Device inventory"
        aria-busy={loading}
      >
        <div className="inventory-toolbar">
          <div className="search-box">
            <Search size={17} aria-hidden="true" />
            <Input
              aria-label="Search this page"
              placeholder="Search this page…"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </div>
          <div className="toolbar-actions">
            <Label className="sr-only" htmlFor="device-status">
              Filter devices
            </Label>
            <select
              id="device-status"
              value={status}
              onChange={(event) => {
                setStatus(event.target.value);
                setCursors([null]);
                setSearch("");
                setPage({ items: [], next_cursor: null });
              }}
            >
              <option value="all">All statuses</option>
              <option value="online">Recently online</option>
              <option value="offline">Offline</option>
              <option value="revoked">Revoked</option>
            </select>
            <Button
              variant="outline"
              size="icon"
              aria-label="Refresh devices"
              disabled={loading}
              onClick={() => setRefresh(refresh + 1)}
            >
              <RefreshCw className={loading ? "spinning" : ""} />
            </Button>
          </div>
        </div>
        {error && (
          <p className="error-message inventory-error" role="alert">
            {error}
          </p>
        )}
        {loading && !page.items.length ? (
          <div className="empty-state" role="status">
            <RefreshCw className="spinning" />
            <p>Loading devices…</p>
          </div>
        ) : !visible.length ? (
          <div className="empty-state">
            <span className="empty-icon">
              <Router />
            </span>
            <h2>
              {search || status !== "all"
                ? "No matching devices"
                : "Your network starts here"}
            </h2>
            <p className="muted">
              {search || status !== "all"
                ? "Try another filter or search on this page."
                : "Add your first OPNsense firewall with a one-time enrollment token."}
            </p>
            {!search && status === "all" && !error && (
              <Button variant="outline" onClick={() => setOpen(true)}>
                <Plus />
                Add your first device
              </Button>
            )}
          </div>
        ) : (
          <div className="table-region" tabIndex={0} aria-label="Device table">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Device</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Owner</TableHead>
                  <TableHead>Last seen</TableHead>
                  <TableHead>GUI certificate</TableHead>
                  <TableHead>Access</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {visible.map((device) => (
                  <TableRow key={device.id}>
                    <TableCell>
                      <div className="device-name">
                        <span className="device-icon">
                          <Router size={20} />
                        </span>
                        <span>
                          <strong>
                            {device.label ||
                              device.hostname ||
                              device.subdomain}
                          </strong>
                          <span className="device-domain">
                            {deviceDestination(device)?.host ||
                              device.subdomain}{" "}
                            · {device.platform}
                          </span>
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <span
                        className={`status-badge ${device.revoked ? "revoked" : device.online ? "online" : "offline"}`}
                      >
                        <span />
                        {device.revoked
                          ? "Revoked"
                          : device.online
                            ? "Recently online"
                            : "Offline"}
                      </span>
                    </TableCell>
                    <TableCell className="owner-cell">
                      {device.owner.email}
                    </TableCell>
                    <TableCell>
                      {device.last_seen_at
                        ? new Date(device.last_seen_at).toLocaleString()
                        : "Not observed"}
                    </TableCell>
                    <TableCell>
                      {certificateLabel(device)}
                      {device.gui_certificate?.valid_until && (
                        <p className="muted">
                          Valid until{" "}
                          {new Date(
                            device.gui_certificate.valid_until,
                          ).toLocaleString()}
                        </p>
                      )}
                    </TableCell>
                    <TableCell>
                      <DeviceAccess device={device} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        <footer className="inventory-footer">
          <span>
            {visible.length} shown{updated ? ` · Refreshed ${updated}` : ""}
          </span>
          <div>
            <Button
              variant="ghost"
              size="sm"
              disabled={loading || cursors.length === 1}
              onClick={() => setCursors(cursors.slice(0, -1))}
            >
              <ChevronLeft />
              Previous
            </Button>
            <Button
              variant="ghost"
              size="sm"
              disabled={loading || !page.next_cursor}
              onClick={() => {
                if (page.next_cursor) {
                  setCursors([...cursors, page.next_cursor]);
                  setSearch("");
                }
              }}
            >
              Next
              <ChevronRight />
            </Button>
          </div>
        </footer>
      </section>
      <p className="observation-note">
        Online reflects a recent tunnel observation. This list updates
        automatically while visible. Certificate status is reported by the
        device; your browser verifies the connection. Open allows your current
        network for 30 minutes. Click again to renew, or after changing
        networks. The router still requires its own login. Others may share your
        public IP (CGNAT); IPv4 and IPv6 routes may use different addresses.
      </p>
      <EnrollmentDialog
        open={open}
        close={() => {
          setOpen(false);
          setRefresh((value) => value + 1);
        }}
      />
    </>
  );
}

export function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [booting, setBooting] = useState(true);
  const [failure, setFailure] = useState("");
  const [retry, setRetry] = useState(0);
  const [leaving, setLeaving] = useState(false);
  useEffect(
    () =>
      onUnauthorized(() => {
        setSession(null);
        setFailure("");
      }),
    [],
  );
  useEffect(() => {
    const controller = new AbortController();
    setBooting(true);
    setFailure("");
    api
      .session(controller.signal)
      .then((value) => {
        if (!controller.signal.aborted) setSession(value);
      })
      .catch((error) => {
        if (!controller.signal.aborted) setFailure(message(error));
      })
      .finally(() => {
        if (!controller.signal.aborted) setBooting(false);
      });
    return () => controller.abort();
  }, [retry]);
  async function logout() {
    setLeaving(true);
    setFailure("");
    try {
      await api.logout();
      clearSession();
      setSession(null);
    } catch (error) {
      setFailure(message(error));
    } finally {
      setLeaving(false);
    }
  }
  if (booting)
    return (
      <main className="boot-screen" role="status">
        <Brand />
        <p className="muted">Connecting to your console…</p>
      </main>
    );
  if (!session && failure)
    return (
      <main className="boot-screen">
        <Brand />
        <p className="error-message" role="alert">
          {failure}
        </p>
        <Button onClick={() => setRetry(retry + 1)}>Try again</Button>
      </main>
    );
  if (!session) return <SignIn onLogin={setSession} />;
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Brand />
        <div className="workspace-label">WORKSPACE</div>
        <nav aria-label="Main navigation">
          <a href="/" aria-current="page">
            <Router size={18} />
            Devices
          </a>
        </nav>
        <div className="sidebar-footer">
          <span className="sidebar-dot" />
          Self-hosted instance
          <a
            href="/third-party-licenses.txt"
            target="_blank"
            rel="noopener noreferrer"
          >
            Third-party licenses
          </a>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <span className="breadcrumb">
            Workspace<span>/</span>
            <strong>Devices</strong>
          </span>
          <div className="account-actions">
            <span className="account-email">{session.user.email}</span>
            <span className="role-badge">{session.user.role}</span>
            <ThemeButton />
            <Button
              variant="ghost"
              size="icon"
              aria-label="Sign out"
              disabled={leaving}
              onClick={logout}
            >
              <LogOut />
            </Button>
          </div>
        </header>
        <main className="page-content">
          {failure && (
            <p role="alert" className="error-message">
              {failure}
            </p>
          )}
          <Devices />
        </main>
        <footer className="workspace-footer">
          NetHub<span>Self-hosted remote management</span>
        </footer>
      </div>
    </div>
  );
}
