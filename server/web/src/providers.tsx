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
  type OIDCProvider,
  type OIDCProviderPage,
  type OIDCProviderInput,
} from "./api";
import { NativeDialog } from "./dialog";
import {
  providerChanges,
  providerDraft,
  providerProjection,
  type ProviderDraft,
} from "./provider-form";

const emptyPage: OIDCProviderPage = { items: [], next_cursor: null };
const message = (error: unknown) =>
  error instanceof Error
    ? error.message
    : "The request could not be completed.";

export function Providers({
  onAuthorityChanged,
}: {
  onAuthorityChanged: (active?: boolean) => Promise<void>;
}) {
  const [page, setPage] = useState<OIDCProviderPage>(emptyPage);
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [draft, setDraft] = useState<ProviderDraft | null>(null);
  const [deleting, setDeleting] = useState<OIDCProvider | null>(null);
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);
  const [operationError, setOperationError] = useState("");
  const [uncertain, setUncertain] = useState(false);
  const [copied, setCopied] = useState("");
  const alive = useRef(true);
  const cursor = cursors.at(-1)!;
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    let inFlight = false;
    async function load(background = false) {
      if (inFlight || controller.signal.aborted || pending.current) return;
      inFlight = true;
      setLoading(true);
      try {
        const value = await api.oidcProviders(
          cursor,
          AbortSignal.any([controller.signal, AbortSignal.timeout(15000)]),
          background,
        );
        if (
          !Array.isArray(value.items) ||
          !value.items.every(providerProjection)
        )
          throw new Error(
            "Provider data could not be verified. Try refreshing.",
          );
        if (!controller.signal.aborted && !pending.current) {
          setPage(value);
          setError("");
        }
      } catch (failure) {
        if (!controller.signal.aborted && !pending.current) {
          setError(message(failure));
          if (failure instanceof ApiError && failure.status === 403) {
            setPage(emptyPage);
            setDraft(null);
            setDeleting(null);
            await onAuthorityChanged(!background);
          }
        }
      } finally {
        inFlight = false;
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    const visible = () => {
      if (!document.hidden) void load(true);
    };
    setPage(emptyPage);
    void load();
    const timer = setInterval(visible, 15000);
    document.addEventListener("visibilitychange", visible);
    return () => {
      controller.abort();
      clearInterval(timer);
      document.removeEventListener("visibilitychange", visible);
    };
  }, [cursor, refresh, onAuthorityChanged]);
  function close() {
    if (pending.current) return;
    setDraft(null);
    setDeleting(null);
    setOperationError("");
    setUncertain(false);
    setCopied("");
    setRefresh((v) => v + 1);
  }
  function edit(provider: OIDCProvider | null) {
    setOperationError("");
    setUncertain(false);
    setCopied("");
    setDraft(providerDraft(provider));
  }
  async function failure(value: unknown) {
    if (!alive.current) return;
    setOperationError(message(value));
    if (
      value instanceof ApiError &&
      ["provider_unconfirmed", "provider_changed"].includes(value.code)
    )
      setUncertain(true);
    if (value instanceof ApiError && value.status === 403) {
      setDraft(null);
      setDeleting(null);
      setPage(emptyPage);
      await onAuthorityChanged();
    }
  }
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!draft || pending.current || uncertain) return;
    let changes;
    try {
      changes = providerChanges(draft);
    } catch (value) {
      setOperationError(message(value));
      return;
    }
    if (draft.original && Object.keys(changes).length === 0) return;
    const original = draft.original;
    const slug = draft.slug;
    pending.current = true;
    setBusy(true);
    setOperationError("");
    setDraft({ ...draft, secret: "" });
    try {
      const result = original
        ? await api.updateOIDCProvider(original.id, changes)
        : await api.createOIDCProvider(changes as OIDCProviderInput);
      if (!alive.current) return;
      if (
        !providerProjection(result) ||
        result.slug !== slug ||
        (original && result.id !== original.id)
      )
        throw new ApiError(
          0,
          "provider_unconfirmed",
          "The change was not confirmed. Close and refresh providers.",
        );
      setDraft(null);
      setRefresh((v) => v + 1);
    } catch (value) {
      await failure(value);
    } finally {
      pending.current = false;
      if (alive.current) setBusy(false);
    }
  }
  async function remove() {
    if (!deleting || pending.current || uncertain) return;
    pending.current = true;
    setBusy(true);
    setOperationError("");
    try {
      await api.deleteOIDCProvider(deleting.id);
      if (alive.current) {
        setDeleting(null);
        setRefresh((v) => v + 1);
      }
    } catch (value) {
      await failure(value);
    } finally {
      pending.current = false;
      if (alive.current) setBusy(false);
    }
  }
  async function copy(provider: OIDCProvider) {
    const expected = `${window.location.origin}/api/v1/console/oidc/${provider.slug}/callback`;
    if (provider.redirect_uri !== expected) {
      setError(
        "The callback address could not be verified. Refresh providers.",
      );
      return;
    }
    try {
      await navigator.clipboard.writeText(expected);
      if (alive.current) setCopied(provider.id);
    } catch {
      if (alive.current)
        setError(
          "Clipboard access is unavailable. Select and copy the callback address.",
        );
    }
  }
  let changed = false;
  if (draft) {
    try {
      changed =
        !draft.original || Object.keys(providerChanges(draft)).length > 0;
    } catch {
      changed = true;
    }
  }
  return (
    <>
      <header className="page-heading">
        <div>
          <span className="eyebrow">WORKSPACE ACCESS</span>
          <h1>Identity providers</h1>
          <p className="muted">
            Connect an OpenID Connect provider for console sign-in.
          </p>
        </div>
        <div className="provider-heading-actions">
          <Button
            variant="outline"
            aria-label="Refresh providers"
            disabled={loading || busy}
            onClick={() => setRefresh((v) => v + 1)}
          >
            <RefreshCw />
            Refresh
          </Button>
          <Button disabled={busy} onClick={() => edit(null)}>
            <Plus />
            Add provider
          </Button>
        </div>
      </header>
      {error && (
        <p role="alert" className="error-message">
          {error}
        </p>
      )}
      <section
        className="device-panel"
        aria-label="Identity providers"
        aria-busy={loading}
      >
        <div
          className="table-region"
          tabIndex={0}
          aria-label="Identity provider table"
        >
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Provider</TableHead>
                <TableHead>Issuer</TableHead>
                <TableHead>Sign-in</TableHead>
                <TableHead>Client secret</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {page.items.map((provider) => (
                <TableRow key={provider.id}>
                  <TableCell>
                    <strong>{provider.display_name}</strong>
                    <span className="muted provider-slug">{provider.slug}</span>
                  </TableCell>
                  <TableCell>
                    <span className="provider-issuer">
                      {provider.issuer_url}
                    </span>
                  </TableCell>
                  <TableCell>
                    <span
                      className={`status-badge ${provider.enabled ? "online" : "revoked"}`}
                    >
                      <span />
                      {provider.enabled ? "Enabled" : "Disabled"}
                    </span>
                  </TableCell>
                  <TableCell>
                    {provider.has_client_secret
                      ? "Configured"
                      : "Not configured"}
                  </TableCell>
                  <TableCell>
                    <div className="provider-row-actions">
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={busy}
                        aria-label={`Edit ${provider.display_name}`}
                        onClick={() => edit(provider)}
                      >
                        Edit
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={busy}
                        aria-label={`Delete ${provider.display_name}`}
                        onClick={() => {
                          setOperationError("");
                          setUncertain(false);
                          setDeleting(provider);
                        }}
                      >
                        Delete
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        {page.items.length === 0 && (
          <p className="muted user-empty" role="status">
            {loading
              ? "Loading providers…"
              : error
                ? "Providers are unavailable."
                : "No providers on this page. Local password sign-in remains available."}
          </p>
        )}
        <footer className="inventory-footer">
          <span>{page.items.length} providers on this page</span>
          <div>
            <Button
              size="sm"
              variant="ghost"
              aria-label="Previous provider page"
              disabled={loading || busy || cursors.length === 1}
              onClick={() => setCursors((v) => v.slice(0, -1))}
            >
              <ChevronLeft />
              Previous
            </Button>
            <Button
              size="sm"
              variant="ghost"
              aria-label="Next provider page"
              disabled={loading || busy || !page.next_cursor}
              onClick={() => setCursors((v) => [...v, page.next_cursor])}
            >
              Next
              <ChevronRight />
            </Button>
          </div>
        </footer>
      </section>
      <NativeDialog
        open={draft !== null}
        title={draft?.original ? "Edit provider" : "Add provider"}
        dismissible={!busy}
        onClose={close}
      >
        {draft && (
          <form
            className="user-form provider-form"
            onSubmit={(event) => void save(event)}
          >
            <Label htmlFor="provider-name">Display name</Label>
            <Input
              id="provider-name"
              required
              maxLength={200}
              value={draft.name}
              disabled={busy || uncertain}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            />
            <Label htmlFor="provider-slug">Slug</Label>
            <Input
              id="provider-slug"
              required
              pattern="[a-z0-9][a-z0-9-]{0,62}"
              maxLength={63}
              value={draft.slug}
              disabled={busy || uncertain || !!draft.original}
              onChange={(e) => setDraft({ ...draft, slug: e.target.value })}
            />
            <p className="muted">
              A permanent name for the callback address. Deleted names remain
              reserved.
            </p>
            <Label htmlFor="provider-issuer">Issuer URL</Label>
            <Input
              id="provider-issuer"
              type="url"
              required
              maxLength={2048}
              value={draft.issuer}
              disabled={busy || uncertain}
              placeholder="https://idp.example.com"
              onChange={(e) => setDraft({ ...draft, issuer: e.target.value })}
            />
            <Label htmlFor="provider-client">Client ID</Label>
            <Input
              id="provider-client"
              required
              maxLength={4096}
              autoComplete="off"
              value={draft.client}
              disabled={busy || uncertain}
              onChange={(e) => setDraft({ ...draft, client: e.target.value })}
            />
            <Label htmlFor="provider-secret">
              {draft.original ? "Replacement client secret" : "Client secret"}
            </Label>
            <Input
              id="provider-secret"
              type="password"
              maxLength={16384}
              autoComplete="new-password"
              value={draft.secret}
              disabled={busy || uncertain || draft.removeSecret}
              onChange={(e) => setDraft({ ...draft, secret: e.target.value })}
            />
            <p className="muted">
              {draft.original
                ? "The saved secret is never shown. Leave blank to keep it."
                : "Leave blank only for a public client that does not use a secret."}{" "}
              Secret fields clear when a save is sent.
            </p>
            {draft.original?.has_client_secret && (
              <label className="user-disable">
                <input
                  type="checkbox"
                  checked={draft.removeSecret}
                  disabled={busy || uncertain}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      removeSecret: e.target.checked,
                      secret: "",
                    })
                  }
                />
                Remove saved secret for a public client
              </label>
            )}
            <Label htmlFor="provider-scopes">Scopes</Label>
            <Input
              id="provider-scopes"
              required
              value={draft.scopes}
              disabled={busy || uncertain}
              onChange={(e) => setDraft({ ...draft, scopes: e.target.value })}
            />
            <p className="muted">Space-separated scopes, including openid.</p>
            <label className="user-disable">
              <input
                type="checkbox"
                checked={draft.enabled}
                disabled={busy || uncertain}
                onChange={(e) =>
                  setDraft({ ...draft, enabled: e.target.checked })
                }
              />
              Enable sign-in
            </label>
            {draft.original && (
              <>
                <Label htmlFor="provider-callback">Callback address</Label>
                <textarea
                  id="provider-callback"
                  className="token-value"
                  readOnly
                  rows={3}
                  value={draft.original.redirect_uri}
                />
                <Button
                  type="button"
                  variant="outline"
                  disabled={busy}
                  onClick={() => void copy(draft.original!)}
                >
                  <Copy />
                  {copied === draft.original.id
                    ? "Copied"
                    : "Copy callback address"}
                </Button>
              </>
            )}
            {operationError && (
              <p role="alert" className="error-message">
                {operationError}
              </p>
            )}
            <div className="dialog-actions">
              <Button
                type="button"
                variant="outline"
                disabled={busy}
                onClick={close}
              >
                {uncertain ? "Close and refresh" : "Cancel"}
              </Button>
              <Button type="submit" disabled={busy || uncertain || !changed}>
                {busy ? "Saving…" : "Save provider"}
              </Button>
            </div>
          </form>
        )}
      </NativeDialog>
      <NativeDialog
        open={deleting !== null}
        title="Delete provider"
        dismissible={!busy}
        onClose={close}
      >
        {deleting && (
          <div className="user-form">
            <p>Delete {deleting.display_name}?</p>
            <p className="muted">
              Its saved secret is removed and unused restricted invitations are
              withdrawn. The name remains reserved. Providers with bound users
              must be disabled instead.
            </p>
            {operationError && (
              <p role="alert" className="error-message">
                {operationError}
              </p>
            )}
            <div className="dialog-actions">
              <Button variant="outline" disabled={busy} onClick={close}>
                {uncertain ? "Close and refresh" : "Cancel"}
              </Button>
              <Button
                disabled={busy || uncertain}
                onClick={() => void remove()}
              >
                {busy ? "Deleting…" : "Delete provider"}
              </Button>
            </div>
          </div>
        )}
      </NativeDialog>
    </>
  );
}
