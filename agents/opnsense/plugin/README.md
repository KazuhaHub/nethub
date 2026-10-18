# OPNsense plugin development

The W2 integration under development adds an independent frpc service to
Services → NetHub Agent. Native tunnel acceptance is still pending. It does not
enroll devices; temporary debug settings will be removed or made read-only in W4.
Saved model settings remain in config.xml after uninstall.

The service requires a locally provisioned deployment CA at
`/usr/local/etc/nethub-agent/relay-ca.pem`. The relay hostname must match the
server certificate. Save the settings, then Apply; candidates are verified before
replacing the live configuration. A failed candidate keeps the previous file and
running process. Stop sets a persistent local stop marker; Start clears that
marker but never clears the separate kill switch. No newwanip hook is registered.
Package-owned system cron entries run reconcile each minute and an independent
watchdog every five minutes. Both use the same persistent `lockf -t 0` lock and
skip contention; logs go to `/var/log/nethub-agent/scheduler.log`. The watchdog
records a rejected configuration hash and one-attempt recovery budget in
`/var/db/nethub-agent/recovery.json`. Reconcile cannot reapply that configuration
or restart an abandoned service until a different desired configuration validates.
The local `revoked` marker blocks both jobs and explicit Start; authenticated
remote revocation receipt remains W5 work. pkg owns and removes the cron file.

On the isolated OPNsense test guest, run `sh build.sh`, then install
`dist/os-nethub-agent.pkg` with `pkg add`. Build requirements are FreeBSD, pkg,
sha256, and Python 3.13. Python is a build tool here, not a new runtime service.
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

The W2 build stages official frpc 0.71.1 under
`/usr/local/opnsense/nethub-agent/bin/`, separately from os-frp. The archive is
downloaded during the build and checked against `frp-artifacts.json`; it is not
committed to NetHub. `FRP_VERSION` accompanies the executable. The builder checks
the FreeBSD amd64 ELF header and native `--version` before creating the package.
This prerequisite adds no tunnel service or enrollment behavior.
