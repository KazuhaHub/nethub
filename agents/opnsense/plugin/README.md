# OPNsense plugin development

The W2 integration adds an independently managed frpc service to
Services → NetHub Agent. Native validation is recorded in
[the integration report](tests/w2-progress.md).
W4 now adds the HTTPS enrollment/client/model/UI flow and removes
the temporary debug credential editor. Enrollment passed actual public-console
and native-device acceptance; see [the W4 report](tests/w4-progress.md).
The 0.0.4 health/removal increment also passed current-head CI and actual native
public enrollment, manual/cron reporting, revocation and cleanup acceptance.
Saved model settings remain in config.xml after uninstall.

Enter the separate console HTTPS address and one-use token in Enrollment.
The client uses system trust, refuses redirects and environment proxies, validates
the bounded response, and passes known fields back to PHP through configd.
PHP revalidates and saves through the native model/configuration lock, then starts
the tunnel. Only a mode-0600 request-file path crosses the command interface;
the token is consumed/unlinked, returned credentials never reach browser JSON,
and configd output caching is disabled. A separate process deadline bounds the
worker even during a stalled resolver or TLS peer.

Initial relay trust is retained in the model and restored into
`/usr/local/etc/nethub-agent/relay-ca.pem` on reconcile. Changing an existing,
different CA remains blocked pending the authenticated trust-transition flow;
this is not CA rotation/ACK implementation. The explicit TLS server name is
independent of the connection address. Candidates are verified before
replacing the live configuration. A failed candidate keeps the previous file and
running process. Stop sets a persistent local stop marker; Start clears that
marker but never clears the separate kill switch. No newwanip hook is registered.
Package-owned system cron entries run reconcile and a delayed health report each
minute, plus an independent watchdog every five minutes. All use the same
persistent `lockf -t 0` lock and
skip contention; logs go to `/var/log/nethub-agent/scheduler.log`. The watchdog
starts ten seconds after the minute boundary to avoid recurring contention with
ordinary reconcile runs. Failed configd actions preserve their structured JSON
result; callers must check `success` rather than the transport exit status.
The watchdog
records a rejected configuration hash and one-attempt recovery budget in
`/var/db/nethub-agent/recovery.json`. Reconcile cannot reapply that configuration
or restart an abandoned service until a different desired configuration validates.
The local `revoked` marker blocks both jobs and explicit Start; authenticated
remote revocation receipt remains W5 work. pkg owns and removes the cron file.

An existing device ID makes enrollment idempotent without requesting another
server token. A failed tunnel start retains the saved enrollment for Apply/retry.
If the response or local save is lost after the console consumed a token, inspect
the console inventory and revoke the orphan before creating another token; token
replay does not recover its returned credentials. Unenroll/status reporting and
native certificate installation remain later W4 work. Keep the exact assigned
Alternate Hostnames entry and both GUI security checks as required by D17.

On the isolated OPNsense test guest, run `sh build.sh`, then install
`dist/os-nethub-agent.pkg` with `pkg add`. Build requirements are FreeBSD, pkg,
sha256, Python 3.13, and the Go compiler pinned in `server/.go-version`.
Go is a build dependency; the installed agent and independent watchdog use the existing Python runtime.
The builder validates version agreement, stages source files, and checks the
resulting package before publishing the local artifact. Release packaging and
signing remain separate from this development build.

Run `python -m pytest agents/opnsense/plugin/tests` from the repository root with
PHP and POSIX sh available. CI checks model/form/package structure, XML parsing,
PHP and shell syntax, and the text masks against configuration-injection inputs.
Device installation, native model validation, menu visibility, save, uninstall,
and reinstall still require the target guest.

Reference structures were inspected at opnsense/plugins
`a2a4b2de7aa343760f6d41c22152abf7a13f54ae` (helloworld) and
KKazuhaK/OPNsense-repo `b19db0c5b97fefa229b6a77c15107b4aac5177ef`
(os-easytier). NetHub files are independently written. No reference plugin source,
shared packaging files, or mirror scripts are incorporated.

## frp build prerequisite

The development package builds upstream frpc 0.71.1 under
`/usr/local/opnsense/nethub-agent/bin/`, separately from os-frp. The official
release binary was compiled with Go 1.26.8 and is affected by newer advisories;
the historical W2 archive checks do not establish its current security status.
`frpc-build/go.mod` and `go.sum` lock the source and patched dependencies. The
builder requires the exact shared Go compiler, uses `frpc,noweb`, disables CGO,
checks the FreeBSD amd64 ELF/build identity and runs native `--version` before
creating the package. It does not fall back to an official prebuilt binary.

`FRP_VERSION`, `FRP_BUILD.json`, the upstream license and linked-module/Go licenses
accompany the executable. No large binary is committed. CI scans both the
FreeBSD source target and the actual rebuilt binary. Official release archives
remain checksum-pinned interoperability fixtures; they are not the packaged
client. Changes to the separate os-frp packaging repository and release signing
still require the later release gate.
