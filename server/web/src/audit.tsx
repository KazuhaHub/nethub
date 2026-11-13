import { useEffect, useState, type FormEvent } from "react";
import { ChevronLeft, ChevronRight, RefreshCw } from "lucide-react";
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
import { api, ApiError, type AuditPage, type AuditFilters } from "./api";

const empty: AuditFilters = {
  action: "",
  device_id: "",
  user_id: "",
  since: "",
  until: "",
};

export function Audit({
  isAdmin,
  onAuthorityChanged,
}: {
  isAdmin: boolean;
  onAuthorityChanged: (active?: boolean) => Promise<void>;
}) {
  const [draft, setDraft] = useState(empty);
  const [filters, setFilters] = useState(empty);
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const [refresh, setRefresh] = useState(0);
  const [page, setPage] = useState<AuditPage | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const cursor = cursors.at(-1)!;
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setPage(null);
    setError("");
    void api
      .audit(
        filters,
        cursor,
        AbortSignal.any([controller.signal, AbortSignal.timeout(15000)]),
      )
      .then((value) => {
        if (!controller.signal.aborted) setPage(value);
      })
      .catch(async (failure) => {
        if (controller.signal.aborted) return;
        setError(
          failure instanceof Error
            ? failure.message
            : "Audit events are unavailable.",
        );
        if (failure instanceof ApiError && failure.status === 403)
          await onAuthorityChanged();
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [filters, cursor, refresh, onAuthorityChanged]);

  function apply(event: FormEvent) {
    event.preventDefault();
    if (
      draft.since &&
      draft.until &&
      Date.parse(draft.since) >= Date.parse(draft.until)
    ) {
      setError("The start time must precede the end time.");
      return;
    }
    setCursors([null]);
    setFilters({ ...draft, user_id: isAdmin ? draft.user_id : "" });
  }
  const field = (name: keyof AuditFilters, label: string, type = "text") => (
    <div>
      <Label htmlFor={`audit-${name}`}>{label}</Label>
      <Input
        id={`audit-${name}`}
        type={type}
        value={draft[name]}
        maxLength={100}
        onChange={(event) => setDraft({ ...draft, [name]: event.target.value })}
      />
    </div>
  );
  return (
    <>
      <div className="page-heading">
        <div>
          <h1>Audit log</h1>
          <p className="muted">
            {isAdmin
              ? "Review activity across this instance."
              : "Review your account and device activity."}
          </p>
        </div>
        <Button
          variant="outline"
          disabled={loading}
          onClick={() => setRefresh((value) => value + 1)}
        >
          <RefreshCw size={16} /> Refresh
        </Button>
      </div>
      <form
        onSubmit={apply}
        className="audit-filters"
        aria-label="Audit filters"
      >
        {field("action", "Action")}
        {field("device_id", "Device ID")}
        {isAdmin && field("user_id", "User ID")}
        {field("since", "From (local time)", "datetime-local")}
        {field("until", "Until (local time)", "datetime-local")}
        <Button type="submit" disabled={loading}>
          Apply filters
        </Button>
        <Button
          type="button"
          variant="outline"
          disabled={loading}
          onClick={() => {
            setDraft(empty);
            setFilters(empty);
            setCursors([null]);
          }}
        >
          Clear filters
        </Button>
      </form>
      <p className="muted">
        Times below use your local timezone. Missing details were not recorded
        or are outside your access. This view does not independently verify the
        audit chain.
      </p>
      {error && (
        <p className="error-message" role="alert">
          {error}
        </p>
      )}
      <p className="muted audit-scroll-hint">
        Scroll the table sideways to see all columns.
      </p>
      <section
        aria-label="Audit events"
        aria-busy={loading}
        className="audit-events"
      >
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Time</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Actor</TableHead>
              <TableHead>Device</TableHead>
              <TableHead>Source IP</TableHead>
              <TableHead>Details</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {page?.items.map((entry) => (
              <TableRow key={entry.id}>
                <TableCell>
                  <time dateTime={entry.created_at}>
                    {new Date(entry.created_at).toLocaleString()}
                  </time>
                </TableCell>
                <TableCell>{entry.action}</TableCell>
                <TableCell>
                  {entry.actor_type}
                  {entry.actor && <div className="muted">{entry.actor}</div>}
                </TableCell>
                <TableCell>{entry.target_device_id ?? "—"}</TableCell>
                <TableCell>{entry.client_ip ?? "—"}</TableCell>
                <TableCell>
                  <dl>
                    {Object.entries(entry.details).map(([key, value]) => (
                      <div key={key}>
                        <dt>{key.replaceAll("_", " ")}</dt>
                        <dd>
                          {key === "expires_at"
                            ? new Date(String(value)).toLocaleString()
                            : String(value)}
                        </dd>
                      </div>
                    ))}
                  </dl>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {loading && <p role="status">Loading audit events…</p>}
        {!loading && page?.items.length === 0 && (
          <p role="status">No audit events match these filters.</p>
        )}
      </section>
      <div className="pagination" aria-label="Audit pagination">
        <Button
          variant="outline"
          disabled={loading || cursors.length === 1}
          onClick={() => setCursors((values) => values.slice(0, -1))}
        >
          <ChevronLeft size={16} /> Previous
        </Button>
        <span>Page {cursors.length}</span>
        <Button
          variant="outline"
          disabled={loading || !page?.next_cursor}
          onClick={() => {
            if (page?.next_cursor)
              setCursors((values) => [...values, page.next_cursor]);
          }}
        >
          Next <ChevronRight size={16} />
        </Button>
      </div>
    </>
  );
}
