import { useEffect, useRef, useState, type FormEvent } from "react";
import { KeyRound, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, ApiError, type InvitationInfo, type Session } from "./api";
import { Brand, ThemeButton } from "./app";
import { validInvitationPassword } from "./invitation-safety";

export function Invite({ takeToken }: { takeToken: () => string | null }) {
  const [token, setToken] = useState(takeToken);
  const [info, setInfo] = useState<InvitationInfo | null>(null);
  const [existing, setExisting] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [uncertain, setUncertain] = useState(false);
  const [retry, setRetry] = useState(0);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  useEffect(() => {
    if (!token) {
      setLoading(false);
      return;
    }
    const controller = new AbortController();
    const signal = AbortSignal.any([
      controller.signal,
      AbortSignal.timeout(15000),
    ]);
    setLoading(true);
    setError("");
    Promise.all([
      api.inspectInvitation(token, signal),
      api.session(signal, true),
    ])
      .then(([invitation, session]) => {
        if (controller.signal.aborted) return;
        if (
          Date.parse(invitation.expires_at) <= Date.now() ||
          !Number.isFinite(Date.parse(invitation.expires_at))
        ) {
          setToken(null);
          return;
        }
        setInfo(invitation);
        setExisting(session);
      })
      .catch((failure) => {
        if (controller.signal.aborted) return;
        if (failure instanceof ApiError && failure.code === "invite_invalid")
          setToken(null);
        else
          setError(
            "Could not inspect this invitation. Check your connection and try again.",
          );
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [token, retry]);
  useEffect(() => {
    if (!info) return;
    const expire = () => {
      if (!pending.current && Date.parse(info.expires_at) <= Date.now()) {
        setToken(null);
        setInfo(null);
        setPassword("");
        setConfirm("");
      }
    };
    const timer = setInterval(expire, 1000);
    expire();
    return () => clearInterval(timer);
  }, [info]);
  async function logout() {
    if (pending.current) return;
    pending.current = true;
    setBusy(true);
    setError("");
    try {
      await api.logout();
      if (alive.current) setExisting(null);
    } catch {
      if (alive.current)
        setError(
          "Sign-out was not confirmed. Try signing out again before accepting.",
        );
    } finally {
      pending.current = false;
      if (alive.current) setBusy(false);
    }
  }
  async function accept(event: FormEvent) {
    event.preventDefault();
    if (
      !token ||
      !info?.password_allowed ||
      existing ||
      pending.current ||
      uncertain
    )
      return;
    if (!validInvitationPassword(password)) {
      setError(
        "Use at least 15 characters and at most 1024 UTF-8 bytes, without line endings or NUL.",
      );
      return;
    }
    if (password !== confirm) {
      setError("The passwords do not match.");
      return;
    }
    const supplied = password;
    setPassword("");
    setConfirm("");
    setError("");
    pending.current = true;
    setBusy(true);
    try {
      await api.acceptInvitation(token, supplied);
      if (!alive.current) return;
      setToken(null);
      setInfo(null);
      window.location.replace("/");
    } catch (failure) {
      if (!alive.current) return;
      if (
        failure instanceof ApiError &&
        failure.code === "invitation_unconfirmed"
      ) {
        setUncertain(true);
        setToken(null);
        setInfo(null);
      } else if (
        failure instanceof ApiError &&
        failure.code === "invite_invalid"
      ) {
        setToken(null);
        setInfo(null);
      } else
        setError(
          failure instanceof Error
            ? failure.message
            : "Could not accept the invitation.",
        );
    } finally {
      pending.current = false;
      if (alive.current) setBusy(false);
    }
  }
  return (
    <div className="signin-shell">
      <aside className="signin-story">
        <Brand />
        <div className="story-content">
          <span className="eyebrow">WORKSPACE ACCESS</span>
          <h1>
            Join your
            <br />
            network console.
          </h1>
          <p>
            Accept your administrator’s invitation
            <br />
            to manage your devices with NetHub.
          </p>
        </div>
        <span className="story-footer">
          <ShieldCheck size={16} />
          Self-hosted remote management
        </span>
      </aside>
      <main className="signin-main">
        <div className="signin-top">
          <span className="mobile-brand">
            <Brand />
          </span>
          <ThemeButton />
        </div>
        <section className="signin-form-wrap" aria-busy={loading || busy}>
          <span className="form-icon">
            <KeyRound />
          </span>
          <h2>Accept invitation</h2>
          {loading ? (
            <p className="muted" role="status">
              Checking your invitation…
            </p>
          ) : uncertain ? (
            <div>
              <p className="error-message" role="alert">
                Account creation could not be confirmed. This page will not
                submit the invitation again.
              </p>
              <p className="muted">
                Try signing in with the email and password you chose. If that
                fails, ask your administrator to check your account and
                invitation.
              </p>
              <a href="/">Go to sign in</a>
            </div>
          ) : !token ? (
            <div>
              <p className="error-message" role="alert">
                Invitation unavailable
              </p>
              <p className="muted">
                Reopen the original invitation link. If it was used, withdrawn
                or expired, ask your administrator for help.
              </p>
              <a href="/">Go to sign in</a>
            </div>
          ) : !info ? (
            <>
              <p className="error-message" role="alert">
                {error || "Invitation unavailable"}
              </p>
              <Button onClick={() => setRetry((value) => value + 1)}>
                Check invitation again
              </Button>
            </>
          ) : (
            <>
              <p className="muted">
                Join as <strong>{info.email}</strong> with the{" "}
                <strong>{info.role}</strong> role.
              </p>
              <p className="signin-note">
                Expires {new Date(info.expires_at).toLocaleString()}.
              </p>
              {existing ? (
                <div className="user-form">
                  <p>
                    You are signed in as {existing.user.email}. Sign out before
                    accepting this invitation.
                  </p>
                  <Button disabled={busy} onClick={() => void logout()}>
                    {busy ? "Signing out…" : "Sign out to accept"}
                  </Button>
                </div>
              ) : info.password_allowed ? (
                <form onSubmit={(event) => void accept(event)} aria-busy={busy}>
                  <div className="field">
                    <Label htmlFor="invite-password">New password</Label>
                    <Input
                      id="invite-password"
                      type="password"
                      autoComplete="new-password"
                      required
                      maxLength={1024}
                      value={password}
                      disabled={busy}
                      onChange={(event) => setPassword(event.target.value)}
                    />
                  </div>
                  <div className="field">
                    <Label htmlFor="invite-confirm">Confirm password</Label>
                    <Input
                      id="invite-confirm"
                      type="password"
                      autoComplete="new-password"
                      required
                      maxLength={1024}
                      value={confirm}
                      disabled={busy}
                      onChange={(event) => setConfirm(event.target.value)}
                    />
                  </div>
                  <p className="muted">
                    Use at least 15 characters. This creates a new account.
                  </p>
                  <Button
                    className="signin-submit"
                    type="submit"
                    disabled={busy}
                  >
                    {busy ? "Creating account…" : "Create account"}
                  </Button>
                </form>
              ) : (
                <div>
                  <p>SSO is required for this invitation.</p>
                  <p className="muted">
                    Ask your administrator to complete SSO setup before claiming
                    it.
                  </p>
                </div>
              )}
              {info.password_allowed && info.providers.length > 0 && (
                <p className="signin-note">
                  SSO claim support is being configured. You can set a local
                  password instead.
                </p>
              )}
              {error && (
                <p className="error-message" role="alert">
                  {error}
                </p>
              )}
            </>
          )}
        </section>
        <footer className="signin-footer">
          NetHub console<span>Private by deployment</span>
        </footer>
      </main>
    </div>
  );
}
