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
  type SAMLProvider,
  type SAMLProviderPage,
  type SAMLProviderInput,
} from "./api";
import { NativeDialog } from "./dialog";
import { ProviderTabs } from "./provider-tabs";
import {
  samlDraft,
  samlChanges,
  samlProjection,
  verifiedSAMLAddresses,
  type SAMLDraft,
} from "./saml-provider-form";

const emptyPage: SAMLProviderPage = { items: [], next_cursor: null };
const message = (error: unknown) =>
  error instanceof Error
    ? error.message
    : "The request could not be completed.";

export function SAMLProviders({
  onAuthorityChanged,
}: {
  onAuthorityChanged: (active?: boolean) => Promise<void>;
}) {
  const [page, setPage] = useState<SAMLProviderPage>(emptyPage);
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [draft, setDraft] = useState<SAMLDraft | null>(null);
  const [deleting, setDeleting] = useState<SAMLProvider | null>(null);
  const [busy, setBusy] = useState(false);
  const [operationError, setOperationError] = useState("");
  const [uncertain, setUncertain] = useState(false);
  const [copied, setCopied] = useState("");
  const pending = useRef(false),
    alive = useRef(true);
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
      if (controller.signal.aborted || inFlight || pending.current) return;
      inFlight = true;
      setLoading(true);
      try {
        const value = await api.samlProviders(
          cursor,
          AbortSignal.any([controller.signal, AbortSignal.timeout(15000)]),
          background,
        );
        if (
          !Array.isArray(value.items) ||
          !value.items.every(samlProjection) ||
          (value.next_cursor !== null && typeof value.next_cursor !== "string")
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
    setPage(emptyPage);
    void load();
    const visible = () => {
      if (!document.hidden) void load(true);
    };
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
    setRefresh((value) => value + 1);
  }
  function edit(provider: SAMLProvider | null) {
    setDraft(samlDraft(provider));
    setOperationError("");
    setUncertain(false);
    setCopied("");
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
      setPage(emptyPage);
      setDraft(null);
      setDeleting(null);
      await onAuthorityChanged();
    }
  }
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!draft || pending.current || uncertain) return;
    let changes;
    try {
      changes = samlChanges(draft);
    } catch (value) {
      setOperationError(message(value));
      return;
    }
    if (draft.original && Object.keys(changes).length === 0) return;
    const original = draft.original,
      slug = draft.slug;
    pending.current = true;
    setBusy(true);
    setOperationError("");
    try {
      const value = original
        ? await api.updateSAMLProvider(original.id, changes)
        : await api.createSAMLProvider(changes as SAMLProviderInput);
      if (!alive.current) return;
      if (
        !samlProjection(value) ||
        value.slug !== slug ||
        (original && value.id !== original.id)
      )
        throw new ApiError(
          0,
          "provider_unconfirmed",
          "The change was not confirmed. Close and refresh providers.",
        );
      setDraft(null);
      setRefresh((value) => value + 1);
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
      await api.deleteSAMLProvider(deleting.id);
      if (alive.current) {
        setDeleting(null);
        setRefresh((value) => value + 1);
      }
    } catch (value) {
      await failure(value);
    } finally {
      pending.current = false;
      if (alive.current) setBusy(false);
    }
  }
  async function copy(provider: SAMLProvider, kind: "metadata" | "acs") {
    const addresses = verifiedSAMLAddresses(provider, window.location.origin);
    if (!addresses) {
      setError("Provider addresses could not be verified. Refresh providers.");
      return;
    }
    try {
      await navigator.clipboard.writeText(addresses[kind]);
      if (alive.current) setCopied(`${provider.id}:${kind}`);
    } catch {
      if (alive.current)
        setError(
          "Clipboard access is unavailable. Select and copy the address.",
        );
    }
  }
  let changed = false;
  if (draft) {
    try {
      changed = !draft.original || Object.keys(samlChanges(draft)).length > 0;
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
            Connect a SAML provider for invited console accounts.
          </p>
        </div>
        <div className="provider-heading-actions">
          <Button
            variant="outline"
            aria-label="Refresh providers"
            disabled={loading || busy}
            onClick={() => setRefresh((value) => value + 1)}
          >
            <RefreshCw />
            Refresh
          </Button>
          <Button disabled={busy} onClick={() => edit(null)}>
            <Plus />
            Add SAML provider
          </Button>
        </div>
      </header>
      <ProviderTabs active="saml" />
      {error && (
        <p role="alert" className="error-message">
          {error}
        </p>
      )}
      <section
        className="device-panel"
        aria-label="SAML providers"
        aria-busy={loading}
      >
        <div
          className="table-region"
          tabIndex={0}
          aria-label="SAML provider table"
        >
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Provider</TableHead>
                <TableHead>IdP entity ID</TableHead>
                <TableHead>Sign-in</TableHead>
                <TableHead>SP metadata</TableHead>
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
                      {provider.entity_id}
                    </span>
                  </TableCell>
                  <TableCell>
                    <span
                      className={`status-badge provider-status ${provider.enabled ? "online" : "revoked"}`}
                    >
                      <span />
                      {provider.enabled ? "Enabled" : "Disabled"}
                    </span>
                  </TableCell>
                  <TableCell>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => void copy(provider, "metadata")}
                    >
                      <Copy />
                      {copied === `${provider.id}:metadata`
                        ? "Copied"
                        : "Copy URL"}
                    </Button>
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
        {!page.items.length && (
          <p className="muted user-empty" role="status">
            {loading
              ? "Loading providers…"
              : error
                ? "Providers are unavailable."
                : "No SAML providers on this page. Local password sign-in remains available."}
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
              onClick={() => setCursors((value) => value.slice(0, -1))}
            >
              <ChevronLeft />
              Previous
            </Button>
            <Button
              size="sm"
              variant="ghost"
              aria-label="Next provider page"
              disabled={loading || busy || !page.next_cursor}
              onClick={() =>
                setCursors((value) => [...value, page.next_cursor])
              }
            >
              Next
              <ChevronRight />
            </Button>
          </div>
        </footer>
      </section>
      <NativeDialog
        open={draft !== null}
        title={draft?.original ? "Edit SAML provider" : "Add SAML provider"}
        dismissible={!busy}
        onClose={close}
      >
        {draft && (
          <form
            className="user-form provider-form"
            onSubmit={(event) => void save(event)}
          >
            <Label htmlFor="saml-name">Display name</Label>
            <Input
              id="saml-name"
              required
              maxLength={200}
              disabled={busy || uncertain}
              value={draft.name}
              onChange={(event) =>
                setDraft({ ...draft, name: event.target.value })
              }
            />
            <Label htmlFor="saml-slug">Slug</Label>
            <Input
              id="saml-slug"
              required
              pattern="[a-z0-9][a-z0-9-]{0,62}"
              maxLength={63}
              disabled={busy || uncertain || !!draft.original}
              value={draft.slug}
              onChange={(event) =>
                setDraft({ ...draft, slug: event.target.value })
              }
            />
            <p className="muted">
              This permanent name is used in your provider addresses. Deleted
              names remain reserved.
            </p>
            <Label htmlFor="saml-entity">IdP entity ID</Label>
            <Input
              id="saml-entity"
              required
              maxLength={2048}
              disabled={busy || uncertain}
              value={draft.entity}
              onChange={(event) =>
                setDraft({ ...draft, entity: event.target.value })
              }
            />
            <Label htmlFor="saml-mail">Email attribute name</Label>
            <Input
              id="saml-mail"
              required
              maxLength={512}
              disabled={busy || uncertain}
              value={draft.email}
              onChange={(event) =>
                setDraft({ ...draft, email: event.target.value })
              }
            />
            <p className="muted">
              Use the exact signed attribute name from your IdP, rather than its
              display label. New accounts require an invitation.
            </p>
            <Label htmlFor="saml-metadata">
              {draft.original
                ? "Replace IdP metadata XML (optional)"
                : "IdP metadata XML"}
            </Label>
            <textarea
              id="saml-metadata"
              className="saml-metadata-input"
              rows={8}
              required={!draft.original}
              maxLength={1 << 20}
              spellCheck={false}
              disabled={busy || uncertain}
              value={draft.metadata}
              onChange={(event) =>
                setDraft({ ...draft, metadata: event.target.value })
              }
            />
            <p className="muted">
              Obtain this XML directly from your trusted IdP administrator.{" "}
              {draft.original
                ? "Leave blank to retain the saved metadata and signing identity."
                : "The matching entity and signing certificates will be checked before saving."}
            </p>
            <label className="checkbox-field">
              <input
                type="checkbox"
                checked={draft.enabled}
                disabled={busy || uncertain}
                onChange={(event) =>
                  setDraft({ ...draft, enabled: event.target.checked })
                }
              />
              Enable console sign-in
            </label>
            {draft.original &&
              verifiedSAMLAddresses(draft.original, window.location.origin) && (
                <div className="saml-addresses">
                  <p className="muted">
                    Register these addresses with your IdP before enabling
                    sign-in.
                  </p>
                  <Label htmlFor="saml-sp-entity">
                    SP entity ID / metadata URL
                  </Label>
                  <Input
                    id="saml-sp-entity"
                    readOnly
                    value={draft.original.metadata_uri}
                  />
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => void copy(draft.original!, "metadata")}
                  >
                    <Copy />
                    {copied === `${draft.original.id}:metadata`
                      ? "Copied"
                      : "Copy metadata URL"}
                  </Button>
                  <Label htmlFor="saml-acs">Reply URL (ACS)</Label>
                  <Input
                    id="saml-acs"
                    readOnly
                    value={draft.original.acs_uri}
                  />
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => void copy(draft.original!, "acs")}
                  >
                    <Copy />
                    {copied === `${draft.original.id}:acs`
                      ? "Copied"
                      : "Copy reply URL"}
                  </Button>
                </div>
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
                Cancel
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
        title="Delete SAML provider"
        dismissible={!busy}
        onClose={close}
      >
        <p>
          Delete {deleting?.display_name}? Unused invitations restricted to this
          provider will be withdrawn. Its name remains reserved. Providers with
          bound users must be disabled instead.
        </p>
        {operationError && (
          <p role="alert" className="error-message">
            {operationError}
          </p>
        )}
        <div className="dialog-actions">
          <Button variant="outline" disabled={busy} onClick={close}>
            Cancel
          </Button>
          <Button disabled={busy || uncertain} onClick={() => void remove()}>
            {busy ? "Deleting…" : "Delete provider"}
          </Button>
        </div>
      </NativeDialog>
    </>
  );
}
