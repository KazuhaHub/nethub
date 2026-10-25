import { useEffect, useRef, useState, type FormEvent } from "react";
import { ChevronLeft, ChevronRight, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
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
  type ManagedUser,
  type UserPage,
  type UserPatch,
} from "./api";
import { NativeDialog } from "./dialog";

const emptyPage: UserPage = { items: [], next_cursor: null };
const message = (error: unknown) =>
  error instanceof Error
    ? error.message
    : "The request could not be completed.";
type Edit = { user: ManagedUser; role: ManagedUser["role"]; disabled: boolean };

export function Users({
  currentUserId,
  onAuthorityChanged,
}: {
  currentUserId: string;
  onAuthorityChanged: (active?: boolean) => Promise<void>;
}) {
  const [page, setPage] = useState<UserPage>(emptyPage);
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const cursor = cursors.at(-1)!;
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [editing, setEditing] = useState<Edit | null>(null);
  const [saving, setSaving] = useState(false);
  const savingRef = useRef(false);
  const [saveError, setSaveError] = useState("");
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    let pending = false;
    async function load(background = false) {
      if (pending || controller.signal.aborted || savingRef.current) return;
      pending = true;
      setLoading(true);
      try {
        const value = await api.users(cursor, controller.signal, background);
        if (!controller.signal.aborted && !savingRef.current) {
          setPage(value);
          setError("");
        }
      } catch (failure) {
        if (!controller.signal.aborted && !savingRef.current) {
          setError(message(failure));
          if (failure instanceof ApiError && failure.status === 403) {
            setPage(emptyPage);
            setEditing(null);
            await onAuthorityChanged(!background);
          }
        }
      } finally {
        pending = false;
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    const refreshVisible = () => {
      if (!document.hidden) void load(true);
    };
    setPage(emptyPage);
    void load();
    const timer = setInterval(refreshVisible, 15000);
    document.addEventListener("visibilitychange", refreshVisible);
    return () => {
      controller.abort();
      clearInterval(timer);
      document.removeEventListener("visibilitychange", refreshVisible);
    };
  }, [cursor, refresh, onAuthorityChanged]);

  async function save(event: FormEvent) {
    event.preventDefault();
    if (!editing || savingRef.current) return;
    const patch: UserPatch = {};
    if (editing.role !== editing.user.role) patch.role = editing.role;
    if (editing.disabled !== editing.user.disabled)
      patch.disabled = editing.disabled;
    if (Object.keys(patch).length === 0) return;
    savingRef.current = true;
    setSaving(true);
    setSaveError("");
    try {
      const updated = await api.updateUser(editing.user.id, patch);
      if (!alive.current) return;
      if (
        updated.id !== editing.user.id ||
        (patch.role !== undefined && updated.role !== patch.role) ||
        (patch.disabled !== undefined && updated.disabled !== patch.disabled)
      )
        throw new Error(
          "The change was not confirmed. Refresh before trying again.",
        );
      if (editing.user.id === currentUserId) {
        setPage(emptyPage);
        setEditing(null);
        await onAuthorityChanged();
      } else if (alive.current) {
        setEditing(null);
        setRefresh((value) => value + 1);
      }
    } catch (failure) {
      if (alive.current) {
        setSaveError(message(failure));
        if (failure instanceof ApiError && failure.status === 403) {
          setPage(emptyPage);
          setEditing(null);
          await onAuthorityChanged();
        }
      }
    } finally {
      savingRef.current = false;
      if (alive.current) setSaving(false);
    }
  }

  const changed =
    editing &&
    (editing.role !== editing.user.role ||
      editing.disabled !== editing.user.disabled);
  return (
    <>
      <header className="page-heading">
        <div>
          <span className="eyebrow">WORKSPACE ACCESS</span>
          <h1>Users</h1>
          <p className="muted">Manage roles and console access.</p>
        </div>
        <Button
          variant="outline"
          aria-label="Refresh users"
          disabled={loading || saving}
          onClick={() => setRefresh((value) => value + 1)}
        >
          <RefreshCw />
          Refresh
        </Button>
      </header>
      {error && (
        <p role="alert" className="error-message">
          {error}
        </p>
      )}
      <section
        className="device-panel"
        aria-label="User accounts"
        aria-busy={loading}
      >
        <div
          className="table-region"
          tabIndex={0}
          aria-label="User account table"
        >
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Email</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Access</TableHead>
                <TableHead>Sign-in methods</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {page.items.map((user) => (
                <TableRow key={user.id}>
                  <TableCell>
                    <strong>{user.email}</strong>
                    {user.id === currentUserId && (
                      <span className="muted"> (you)</span>
                    )}
                  </TableCell>
                  <TableCell>
                    {user.role === "admin" ? "Admin" : "Member"}
                  </TableCell>
                  <TableCell>
                    <span
                      className={`status-badge ${user.disabled ? "revoked" : "online"}`}
                    >
                      <span />
                      {user.disabled ? "Disabled" : "Enabled"}
                    </span>
                  </TableCell>
                  <TableCell>
                    {[
                      ...(user.has_password ? ["Local password"] : []),
                      ...user.identities.map(
                        (identity) => identity.provider_slug,
                      ),
                    ].join(", ") || "None"}
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="outline"
                      size="sm"
                      aria-label={`Edit ${user.email}`}
                      disabled={saving}
                      onClick={() => {
                        setSaveError("");
                        setEditing({
                          user,
                          role: user.role,
                          disabled: user.disabled,
                        });
                      }}
                    >
                      Edit
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        {page.items.length === 0 && (
          <p className="muted user-empty" role="status">
            {loading
              ? "Loading users…"
              : error
                ? "User accounts are unavailable."
                : "No users on this page."}
          </p>
        )}
        <footer className="inventory-footer">
          <span>{page.items.length} users on this page</span>
          <div>
            <Button
              variant="ghost"
              size="sm"
              aria-label="Previous user page"
              disabled={cursors.length === 1 || loading || saving}
              onClick={() => setCursors((values) => values.slice(0, -1))}
            >
              <ChevronLeft />
              Previous
            </Button>
            <Button
              variant="ghost"
              size="sm"
              aria-label="Next user page"
              disabled={!page.next_cursor || loading || saving}
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
        open={editing !== null}
        title="Edit user"
        dismissible={!saving}
        onClose={() => {
          if (!saving) setEditing(null);
        }}
      >
        {editing && (
          <form className="user-form" onSubmit={(event) => void save(event)}>
            <p>{editing.user.email}</p>
            {editing.user.id === currentUserId && (
              <p className="muted">
                You are changing your own access. Disabling signs you out;
                becoming a member removes administrator access.
              </p>
            )}
            <Label htmlFor="user-role">Role</Label>
            <select
              id="user-role"
              value={editing.role}
              disabled={saving}
              onChange={(event) =>
                setEditing({
                  ...editing,
                  role: event.target.value as ManagedUser["role"],
                })
              }
            >
              <option value="member">Member</option>
              <option value="admin">Admin</option>
            </select>
            <label className="user-disable">
              <input
                type="checkbox"
                checked={editing.disabled}
                disabled={saving}
                onChange={(event) =>
                  setEditing({ ...editing, disabled: event.target.checked })
                }
              />
              Disable console access
            </label>
            <p className="muted">
              Disabling signs out every console session. Re-enabling requires a
              new sign-in.
            </p>
            {saveError && (
              <p role="alert" className="error-message">
                {saveError}
              </p>
            )}
            <div className="dialog-actions">
              <Button
                type="button"
                variant="outline"
                disabled={saving}
                onClick={() => setEditing(null)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={!changed || saving}>
                {saving ? "Saving…" : "Save changes"}
              </Button>
            </div>
          </form>
        )}
      </NativeDialog>
    </>
  );
}
