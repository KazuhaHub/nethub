# Fresh server and native enrollment

A separate deployment completed W4-9's clean-state browser flow on
2026-10-23 UTC. The CLI initialized new authorities, state and backup directories;
Compose created a distinct project, network and PostgreSQL volume. Existing lab
deployments were retained. The accepted runtime images were reused only after
checking that their source inputs were unchanged.

Before the browser started, PostgreSQL contained no devices or enrollment
tokens. The client was restored to its unenrolled baseline and installed the
verified unsigned 0.0.14 package. The browser logged into the console, generated
its first token, enrolled through the native OPNsense page and observed the
rendered **Recently online** row after **3.723 seconds**. API online took
2.975 seconds. The token input cleared; script errors and requests outside the
allowed origins were both zero. All five steps were captured, including the
rendered row rather than an intermediate loading screen.

Independent snapshots confirmed exactly one new device, one consumed UI token
and three new audits. The archived native secret passed the production NetHub
Argon2id verifier; a changed secret failed. Independent key parsing matched the
archived test key to the public key in both the native record and PostgreSQL.
The operator's private recovery copy is on the VM host, not the relay. Product
enrollment transmitted only the public key. Actual PHP-saved settings and owned
files were exported before checkpoint restoration.

All three independent guard closure paths passed before the window. Afterward,
SSH checks confirmed the original 0.0.6 package, exact configuration and stopped
tunnel intent. Both test projects were stopped, and the original 14 containers
and 443/8443 listener owners were verified. Databases, authorities and recovery
material remain available. The new authority backup was independently exported
and checked off-host before startup.

The [sanitized receipt](validation-native-fresh-browser.json) records inputs and
screenshot hashes. Raw screenshots, credentials and operational evidence remain
private. This was fresh application state on the shared lab host, using the
supported offline initializer, fixture DNS/CA and the approved 1 GiB appliance
allocation. Browser exceptions covered only the independently verified console
and pinned native GUI SPKIs. This establishes the fresh browser enrollment path,
not public CA trust, formal release backup acceptance or GUI certificate
issuance, installation, renewal, rollback and reboot persistence.
