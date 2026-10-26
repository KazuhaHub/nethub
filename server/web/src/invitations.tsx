import { useEffect, useRef, useState, type FormEvent } from "react";
import { ChevronLeft, ChevronRight, Copy, Plus, RefreshCw } from "lucide-react";
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
  ApiError,
  type Invitation,
  type InvitationPage,
  type IssuedInvitation,
  type User,
  type OIDCProvider,
  type SAMLProvider,
} from "./api";
import { providerProjection } from "./provider-form";
import { samlProjection } from "./saml-provider-form";
import { NativeDialog } from "./dialog";
import { validInvitationLink } from "./invitation-safety";

const emptyPage: InvitationPage = { items: [], next_cursor: null };
const message = (error: unknown) =>
  error instanceof Error
    ? error.message
    : "The request could not be completed.";

export function Invitations({
  onAuthorityChanged,
}: {
  onAuthorityChanged: () => Promise<void>;
}) {
  const [page, setPage] = useState<InvitationPage>(emptyPage);
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [creating, setCreating] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<User["role"]>("member");
  const [providerId, setProviderId] = useState("");
  const [providers, setProviders] = useState<(OIDCProvider | SAMLProvider)[]>(
    [],
  );
  const [providerError, setProviderError] = useState("");
  const [providersLoading, setProvidersLoading] = useState(false);
  const [issued, setIssued] = useState<IssuedInvitation | null>(null);
  const [withdrawing, setWithdrawing] = useState<Invitation | null>(null);
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);
  const [operationError, setOperationError] = useState("");
  const [uncertain, setUncertain] = useState(false);
  const [copied, setCopied] = useState(false);
  const alive = useRef(true);
  const cursor = cursors.at(-1)!;
  useEffect(() => {
    if (!creating || issued) return;
    const controller = new AbortController();
    setProvidersLoading(true);
    setProviderError("");
    setProviders([]);
    async function load() {
      const result: (OIDCProvider | SAMLProvider)[] = [];
      let after: string | null = null;
      const seen = new Set<string>();
      try {
        const signal = AbortSignal.any([
          controller.signal,
          AbortSignal.timeout(15000),
        ]);
        do {
          const page = await api.oidcProviders(after, signal);
          if (!page.items.every(providerProjection))
            throw new Error("Provider data unavailable.");
          result.push(...page.items.filter((p) => p.enabled));
          after = page.next_cursor;
          if (after && seen.has(after))
            throw new Error("Provider pagination unavailable.");
          if (after) seen.add(after);
        } while (after);
        after = null;
        seen.clear();
        do {
          const page = await api.samlProviders(after, signal);
          if (!page.items.every(samlProjection))
            throw new Error("Provider data unavailable.");
          result.push(...page.items.filter((p) => p.enabled));
          after = page.next_cursor;
          if (after && seen.has(after))
            throw new Error("Provider pagination unavailable.");
          if (after) seen.add(after);
        } while (after);
        if (!controller.signal.aborted) setProviders(result);
      } catch {
        if (!controller.signal.aborted)
          setProviderError(
            "Provider choices are unavailable. Retry opening this dialog to restrict sign-in.",
          );
      } finally {
        if (!controller.signal.aborted) setProvidersLoading(false);
      }
    }
    void load();
    return () => controller.abort();
  }, [creating, issued]);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setPage(emptyPage);
    setError("");
    api
      .invitations(
        cursor,
        AbortSignal.any([controller.signal, AbortSignal.timeout(15000)]),
      )
      .then((value) => {
        if (!controller.signal.aborted) setPage(value);
      })
      .catch(async (failure) => {
        if (controller.signal.aborted) return;
        setError(message(failure));
        if (failure instanceof ApiError && failure.status === 403) {
          setPage(emptyPage);
          await onAuthorityChanged();
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [cursor, refresh, onAuthorityChanged]);
  useEffect(() => {
    if (!issued) return;
    const expire = () => {
      if (Date.parse(issued.expires_at) <= Date.now()) {
        setIssued(null);
        setOperationError(
          "This invitation expired. Close this dialog and refresh pending invitations.",
        );
        setUncertain(true);
        setCopied(false);
      }
    };
    expire();
    const timer = setInterval(expire, 1000);
    return () => clearInterval(timer);
  }, [issued]);

  function close() {
    if (pending.current) return;
    setCreating(false);
    setWithdrawing(null);
    setIssued(null);
    setEmail("");
    setRole("member");
    setProviderId("");
    setOperationError("");
    setUncertain(false);
    setCopied(false);
    setRefresh((value) => value + 1);
  }
  async function failure(error: unknown) {
    if (!alive.current) return;
    setOperationError(message(error));
    if (error instanceof ApiError && error.code === "invitation_unconfirmed")
      setUncertain(true);
    if (error instanceof ApiError && error.status === 403) {
      setCreating(false);
      setWithdrawing(null);
      setIssued(null);
      setPage(emptyPage);
      await onAuthorityChanged();
    }
  }
  async function create(event: FormEvent) {
    event.preventDefault();
    if (pending.current || issued || uncertain) return;
    pending.current = true;
    setBusy(true);
    setOperationError("");
    try {
      const value = await api.issueInvitation(
        email,
        role,
        providerId || undefined,
      );
      if (!alive.current) return;
      if (
        !validInvitationLink(
          value.invite_url,
          window.location.origin,
          value.expires_at,
        )
      ) {
        setUncertain(true);
        throw new Error(
          "The invitation link could not be verified. Close this dialog and review pending invitations before creating another.",
        );
      }
      setIssued(value);
    } catch (error) {
      await failure(error);
    } finally {
      pending.current = false;
      if (alive.current) setBusy(false);
    }
  }
  async function withdraw() {
    if (!withdrawing || pending.current || uncertain) return;
    pending.current = true;
    setBusy(true);
    setOperationError("");
    try {
      await api.withdrawInvitation(withdrawing.id);
      if (alive.current) {
        setWithdrawing(null);
        setRefresh((value) => value + 1);
      }
    } catch (error) {
      await failure(error);
    } finally {
      pending.current = false;
      if (alive.current) setBusy(false);
    }
  }
  async function copy() {
    if (
      !issued ||
      !validInvitationLink(
        issued.invite_url,
        window.location.origin,
        issued.expires_at,
      )
    )
      return;
    try {
      await navigator.clipboard.writeText(issued.invite_url);
      if (alive.current) setCopied(true);
    } catch {
      if (alive.current)
        setOperationError(
          "Clipboard access is unavailable. Select and copy the link below.",
        );
    }
  }
  return (
    <>
      <header className="page-heading">
        <div>
          <span className="eyebrow">WORKSPACE ACCESS</span>
          <h1>Invitations</h1>
          <p className="muted">Invite people to your console.</p>
        </div>
        <Button
          disabled={loading || busy}
          onClick={() => {
            setOperationError("");
            setUncertain(false);
            setCreating(true);
          }}
        >
          <Plus />
          Invite user
        </Button>
      </header>
      {error && (
        <p className="error-message" role="alert">
          {error}
        </p>
      )}
      <section
        className="device-panel"
        aria-label="Pending invitations"
        aria-busy={loading}
      >
        <div className="inventory-toolbar">
          <p className="muted">
            Links expire after 72 hours. No email is sent.
          </p>
          <Button
            variant="outline"
            disabled={loading || busy}
            onClick={() => setRefresh((value) => value + 1)}
          >
            <RefreshCw />
            Refresh invitations
          </Button>
        </div>
        <div className="table-scroll">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Email</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Sign-in method</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead>Invited by</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {page.items.map((invite) => (
                <TableRow key={invite.id}>
                  <TableCell>{invite.email}</TableCell>
                  <TableCell>{invite.role}</TableCell>
                  <TableCell>
                    {invite.provider_id
                      ? "Restricted SSO provider"
                      : "Local password allowed"}
                  </TableCell>
                  <TableCell>
                    {new Date(invite.expires_at).toLocaleString()}
                  </TableCell>
                  <TableCell>{invite.created_by.email}</TableCell>
                  <TableCell>
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={loading || busy}
                      onClick={() => {
                        setOperationError("");
                        setUncertain(false);
                        setWithdrawing(invite);
                      }}
                    >
                      Withdraw
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        {!page.items.length && (
          <p className="muted user-empty" role="status">
            {loading
              ? "Loading invitations…"
              : error
                ? "Invitations are unavailable."
                : "No pending invitations on this page."}
          </p>
        )}
        <footer className="inventory-footer">
          <span>{page.items.length} pending on this page</span>
          <div>
            <Button
              variant="ghost"
              size="sm"
              aria-label="Previous invitation page"
              disabled={loading || busy || cursors.length === 1}
              onClick={() => setCursors((values) => values.slice(0, -1))}
            >
              <ChevronLeft />
              Previous
            </Button>
            <Button
              variant="ghost"
              size="sm"
              aria-label="Next invitation page"
              disabled={loading || busy || !page.next_cursor}
              onClick={() =>
                setCursors((values) => [...values, page.next_cursor])
              }
            >
              Next
              <ChevronRight />
            </Button>
          </div>
        </footer>
      </section>
      <NativeDialog
        open={creating}
        title={issued ? "Invitation ready" : "Invite user"}
        dismissible={!busy}
        onClose={close}
      >
        {issued ? (
          <div className="user-form">
            <p>
              Copy this link and send it to {email}. It is shown only in this
              dialog; pending invitations cannot reveal it again.
            </p>
            <p className="muted">
              Expires {new Date(issued.expires_at).toLocaleString()}. Anyone
              with this link can claim the invited role.
            </p>
            <Label htmlFor="invitation-link">Invitation link</Label>
            <textarea
              id="invitation-link"
              className="token-value invitation-link"
              readOnly
              value={issued.invite_url}
              rows={3}
              spellCheck={false}
            />
            <Button onClick={() => void copy()}>
              <Copy />
              {copied ? "Copied" : "Copy invitation link"}
            </Button>
            <Button variant="outline" onClick={close}>
              Done
            </Button>
          </div>
        ) : (
          <form className="user-form" onSubmit={(event) => void create(event)}>
            <p className="muted">
              Create a single-use link, then copy and share it yourself.
            </p>
            <Label htmlFor="invitation-email">Email address</Label>
            <Input
              id="invitation-email"
              type="email"
              autoComplete="off"
              maxLength={320}
              required
              value={email}
              disabled={busy || uncertain}
              onChange={(event) => setEmail(event.target.value)}
            />
            <Label htmlFor="invitation-role">Role</Label>
            <select
              id="invitation-role"
              value={role}
              disabled={busy || uncertain}
              onChange={(event) => setRole(event.target.value as User["role"])}
            >
              <option value="member">Member</option>
              <option value="admin">Admin</option>
            </select>
            <Label htmlFor="invitation-provider">Sign-in restriction</Label>
            <select
              id="invitation-provider"
              value={providerId}
              disabled={busy || uncertain || providersLoading}
              onChange={(e) => setProviderId(e.target.value)}
            >
              <option value="">Local password or any available SSO</option>
              {providers.map((provider) => (
                <option key={provider.id} value={provider.id}>
                  {provider.display_name} only
                </option>
              ))}
            </select>
            {providerError && (
              <p className="muted" role="status">
                {providerError}
              </p>
            )}
            <p className="muted">
              Admins can manage all devices, users and invitations. Members
              manage their own devices.
            </p>
            <div className="dialog-actions">
              <Button
                type="button"
                variant="outline"
                disabled={busy}
                onClick={close}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={busy || uncertain}>
                {busy ? "Creating…" : "Create invitation"}
              </Button>
            </div>
          </form>
        )}
        {operationError && (
          <p className="error-message" role="alert">
            {operationError}
            {uncertain &&
              " Close this dialog and refresh pending invitations before trying again."}
          </p>
        )}
      </NativeDialog>
      <NativeDialog
        open={withdrawing !== null}
        title="Withdraw invitation?"
        dismissible={!busy}
        onClose={close}
      >
        <div className="user-form">
          <p>
            Withdraw the pending invitation for {withdrawing?.email}? Its link
            will no longer create an account.
          </p>
          {operationError && (
            <p className="error-message" role="alert">
              {operationError}
              {uncertain &&
                " Close this dialog and refresh pending invitations before trying again."}
            </p>
          )}
          <div className="dialog-actions">
            <Button variant="outline" disabled={busy} onClick={close}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={busy || uncertain}
              onClick={() => void withdraw()}
            >
              {busy ? "Withdrawing…" : "Withdraw invitation"}
            </Button>
          </div>
        </div>
      </NativeDialog>
    </>
  );
}
