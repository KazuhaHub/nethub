# W4 implementation decisions

Status: D16, D19, and W4-7 confirmed by Kazuha on 2026-10-18. W3 evidence is
complete, and Kazuha accepted the fresh Debian VM/public-ingress environment
on 2026-10-18. Implementation follows the closing PR merge. This document records the approved choices before schemas or handlers exist. D22 lifecycle details below remain specification work.

## D16: protocol versions

Use one semantic version in proto/VERSION, initially 1.0.0, and include it as
agent_protocol_version in enrollment. Reject an incompatible major before
consuming a token. Publish the supported major in a readable error without
revealing whether the token exists.

Within the supported major, preserve required fields and their meaning. Minor
releases may add optional fields; patch releases may correct implementation or
documentation without changing the wire contract. Consumers validate and use
known fields, ignore bounded optional extensions, and never copy unknown response
fields into local configuration. Enforce whole-body size limits independently of
JSON Schema. Breaking field changes require a new major and explicit rejection,
not a best-effort adapter. Claims and authorization inputs retain their own strict
canonical representation and security checks.

Every protocol change updates the shared schemas, Go/Python contract tests, and
a compatibility statement in the same PR. The first release has no deployed
stable agent to migrate. Runtime Python does not require jsonschema.

## D19: finding the console

Confirmed: a separate HTTPS console URL input on the plugin enrollment
form. Preserve the existing enrollment token as an opaque, single-use 32-byte
secret encoded with unpadded base64url. The UI shows a copyable console URL beside
the token. Neither token parsing nor a client-selected redirect chooses a second
server implicitly.

Validate the configured HTTPS origin, reject embedded credentials and URL
fragments, use the system CA bundle, and refuse enrollment redirects. Local and
private HTTPS origins remain valid for self-hosted installations; destination
selection is an explicit administrator action. Show the chosen origin before
submission. Never send the token in a URL/query, command argument, or log.

Alternative requiring an explicit format decision: one pasteable enrollment
bundle containing the console origin and the same opaque token. Such a bundle
would be parsed locally and would not be a browser navigation link.

## W4-7: saving configuration and passing secrets

Use the recommended split: agentctl sends HTTPS, validates the result, and returns
bounded JSON to the PHP controller. The controller validates known fields again,
saves through the OPNsense model/configuration lock, and then triggers reconcile.
Python never writes config.xml directly.

PHP places the request in a private, mode-0600 temporary file; configd receives
only its path. agentctl checks the parent, owner, type, mode, and size, refuses
links, reads once, and unlinks the file. Do not put the token or returned
credentials into configd arguments, browser URLs, or diagnostic logs. Remove or
lock the W2 debugging controls when enrollment owns these settings.

## Remaining specification work

D22 already selects a deployment CA, a relay leaf certificate, and explicit
trustedCaFile/serverName, with no CA private key in runtime containers. W4 still
must define validity, expiry checks, backup coverage, and staged rotation behavior
before implementation. Do not treat this proposal as approval of unreviewed CA
lifecycle details. Formal package signing/publication remains D13.

## Platform extension boundary

The device model already stores platform and capabilities, and agents live in
separate platform directories. The current v1 database constraint accepts only
opnsense; it is an explicit current support limit, not a completed generic agent
interface. When W4 defines the shared wire contract, preserve platform-neutral
messages and capability-based behavior. Replace this historical constraint with
bounded platform-identifier validation through a forward migration and test other
platform identifiers without claiming their agents are implemented or supported.

Future OpenWrt/VyOS agents must implement the same enrollment and tunnel contract
plus their own installation, configuration, and service integration. OPNsense is
the only implemented/tested platform in the current scope.
