import { useEffect, useRef, useState, type FormEvent } from "react";
import { ChevronLeft, ChevronRight, RefreshCw, Settings } from "lucide-react";
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
import { api, ApiError, type TrafficPage } from "./api";
import { NativeDialog } from "./dialog";
import {
  formatBytes,
  trafficProjection,
  validMonth,
  validWarning,
} from "./traffic-values";

const message = (error: unknown) =>
  error instanceof Error
    ? error.message
    : "The request could not be completed.";
const date = (value: string | null) =>
  value ? new Date(value).toLocaleString() : "No samples";

export function Traffic({
  onAuthorityChanged,
}: {
  onAuthorityChanged: (active?: boolean) => Promise<void>;
}) {
  const [month, setMonth] = useState(new Date().toISOString().slice(0, 7));
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const [refresh, setRefresh] = useState(0);
  const [page, setPage] = useState<TrafficPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [draft, setDraft] = useState<{
    value: string;
    revision: number;
  } | null>(null);
  const [operationError, setOperationError] = useState("");
  const [uncertain, setUncertain] = useState(false);
  const [busy, setBusy] = useState(false);
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
      if (
        controller.signal.aborted ||
        inFlight ||
        pending.current ||
        !validMonth(month)
      )
        return;
      inFlight = true;
      setLoading(true);
      try {
        const value = await api.traffic(
          month,
          cursor,
          AbortSignal.any([controller.signal, AbortSignal.timeout(15000)]),
          background,
        );
        if (!trafficProjection(value) || value.month !== month)
          throw new Error(
            "Traffic data could not be verified. Refresh to try again.",
          );
        if (!controller.signal.aborted && !pending.current) {
          setPage(value);
          setError("");
        }
      } catch (failure) {
        if (!controller.signal.aborted && !pending.current) {
          setError(message(failure));
          if (failure instanceof ApiError && failure.status === 403) {
            setPage(null);
            setDraft(null);
            await onAuthorityChanged(!background);
          }
        }
      } finally {
        inFlight = false;
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    setPage(null);
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
  }, [month, cursor, refresh, onAuthorityChanged]);

  function close() {
    if (!pending.current) {
      setDraft(null);
      setOperationError("");
      if (uncertain) setRefresh((value) => value + 1);
      setUncertain(false);
    }
  }
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!draft || pending.current || uncertain) return;
    if (!validWarning(draft.value)) {
      setOperationError(
        "Enter whole decimal bytes, up to 30 digits. Use 0 to disable warnings.",
      );
      return;
    }
    pending.current = true;
    setBusy(true);
    setOperationError("");
    try {
      const result = await api.setTrafficWarning(draft.value, draft.revision);
      if (
        result.warning_bytes !== (draft.value === "0" ? null : draft.value) ||
        !Number.isSafeInteger(result.revision) ||
        result.revision < draft.revision ||
        result.revision > draft.revision + 1 ||
        Object.keys(result).some(
          (key) => !["warning_bytes", "revision"].includes(key),
        )
      )
        throw new Error("The save response could not be verified.");
      if (alive.current) {
        setDraft(null);
        setRefresh((value) => value + 1);
      }
    } catch (failure) {
      if (alive.current) {
        if (
          failure instanceof ApiError &&
          (failure.status === 401 || failure.status === 403)
        ) {
          setDraft(null);
          setPage(null);
          await onAuthorityChanged();
        } else {
          setUncertain(true);
          setOperationError(
            failure instanceof ApiError && failure.status === 409
              ? "The warning changed in another session. Close and reload before editing."
              : `${message(failure)} Close and reload to check whether the change was saved. This request will not be retried.`,
          );
        }
      }
    } finally {
      pending.current = false;
      if (alive.current) setBusy(false);
    }
  }
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow">RELAY USAGE</div>
          <h1>Traffic</h1>
          <p>
            Monthly estimates across your workspace. Warnings never restrict
            access.
          </p>
        </div>
        <Button
          variant="outline"
          disabled={!page || loading}
          onClick={() => {
            if (page) {
              setDraft({
                value: page.warning_bytes ?? "0",
                revision: page.warning_revision,
              });
              setOperationError("");
              setUncertain(false);
            }
          }}
        >
          <Settings size={16} /> Monthly warning
        </Button>
      </div>
      <div className="inventory-toolbar traffic-toolbar">
        <Label htmlFor="traffic-month">Month (UTC)</Label>
        <Input
          id="traffic-month"
          type="month"
          value={month}
          min="0001-01"
          max="9999-12"
          onChange={(event) => {
            const value = event.target.value;
            if (validMonth(value)) {
              setMonth(value);
              setCursors([null]);
            }
          }}
        />
        <Button
          variant="outline"
          disabled={loading}
          onClick={() => setRefresh((value) => value + 1)}
        >
          <RefreshCw size={16} /> Refresh
        </Button>
      </div>
      {error && (
        <p className="error-message" role="alert">
          {error} Previously loaded values may be stale.
        </p>
      )}
      {loading && (
        <p className="muted" role="status">
          Updating traffic…
        </p>
      )}
      {page && (
        <>
          <div className="traffic-summary">
            {[
              ["Total", page.total_bytes],
              ["To devices", page.in_bytes],
              ["From devices", page.out_bytes],
            ].map(([label, value]) => (
              <section key={label}>
                <p className="muted">{label}</p>
                <strong title={`${value} bytes`}>{formatBytes(value)}</strong>
                <small>{value} bytes</small>
              </section>
            ))}
          </div>
          {page.warning && (
            <p role="status" className="traffic-warning">
              Monthly warning exceeded ({formatBytes(page.warning_bytes!)}).
              Connections remain available.
            </p>
          )}
          <p className="muted traffic-notes">
            Warning:{" "}
            {page.warning_bytes
              ? `${page.warning_bytes} bytes per month`
              : "Off"}
            . Latest sample: {date(page.last_observed_at)}. First sample:{" "}
            {date(page.first_observed_at)}. Counter resets observed:{" "}
            {page.reset_events}.
          </p>
          <p className="muted traffic-notes">
            Approximate relay payload bytes, not billing or a complete
            calendar-month measurement. The first sample can include earlier
            traffic that day; outages, restarts and missed resets can
            undercount. Removed devices retain their recorded usage.
          </p>
          <div className="device-panel">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Device</TableHead>
                  <TableHead>To device</TableHead>
                  <TableHead>From device</TableHead>
                  <TableHead>Total</TableHead>
                  <TableHead>Last sample</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {page.items.map((item) => (
                  <TableRow key={item.device_id}>
                    <TableCell>
                      <strong>
                        {item.label || item.hostname || "Unnamed device"}
                      </strong>
                      <small className="traffic-device-id">
                        {item.device_id}
                        {item.removed ? " · Removed" : ""}
                      </small>
                    </TableCell>
                    <TableCell title={`${item.in_bytes} bytes`}>
                      {formatBytes(item.in_bytes)}
                    </TableCell>
                    <TableCell title={`${item.out_bytes} bytes`}>
                      {formatBytes(item.out_bytes)}
                    </TableCell>
                    <TableCell title={`${item.total_bytes} bytes`}>
                      {formatBytes(item.total_bytes)}
                    </TableCell>
                    <TableCell>{date(item.last_observed_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {!page.items.length && (
              <div className="empty-state">
                <h2>No recorded traffic</h2>
                <p>No relay samples were recorded for this month.</p>
              </div>
            )}
            <div className="inventory-footer">
              <span>Workspace totals include every page</span>
              <div>
                <Button
                  variant="outline"
                  aria-label="Previous traffic page"
                  disabled={loading || cursors.length === 1}
                  onClick={() => setCursors((value) => value.slice(0, -1))}
                >
                  <ChevronLeft size={16} />
                </Button>
                <Button
                  variant="outline"
                  aria-label="Next traffic page"
                  disabled={loading || !page.next_cursor}
                  onClick={() => {
                    if (page.next_cursor)
                      setCursors((value) => [...value, page.next_cursor]);
                  }}
                >
                  <ChevronRight size={16} />
                </Button>
              </div>
            </div>
          </div>
        </>
      )}
      <NativeDialog
        open={draft !== null}
        title="Monthly traffic warning"
        onClose={close}
        dismissible={!busy}
      >
        {draft && (
          <form onSubmit={save} className="user-form">
            <p>
              This workspace setting warns on monthly totals. It never blocks or
              revokes a device. Use 0 to disable it.
            </p>
            <Label htmlFor="traffic-warning">Warning threshold (bytes)</Label>
            <Input
              id="traffic-warning"
              inputMode="numeric"
              autoComplete="off"
              maxLength={30}
              value={draft.value}
              disabled={busy || uncertain}
              onChange={(event) =>
                setDraft({ ...draft, value: event.target.value })
              }
            />
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
                onClick={() => {
                  close();
                }}
              >
                {uncertain ? "Close and reload" : "Cancel"}
              </Button>
              <Button type="submit" disabled={busy || uncertain}>
                {busy ? "Saving…" : "Save warning"}
              </Button>
            </div>
          </form>
        )}
      </NativeDialog>
    </>
  );
}
