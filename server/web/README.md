# NetHub console

W3's React/TypeScript console implements local sign-in, session restoration,
device listing/filtering/search/pagination, logout, and one-time enrollment-token
issuance. It uses the approved shadcn/ui New York controls and native HTML dialog.
The dialog keeps keyboard focus within its controls, supports Escape, and returns
focus to its opener. CSS and scripts are local files; no inline styles, remote
fonts, analytics, or external requests are required.

Run from this directory with Node 24.14.0 and Go 1.26.10. The OpenSSL CLI is
required for disposable certificate-rejection tests; NETHUB_OPENSSL_BINARY can
select its path on Windows.

```sh
npm ci --ignore-scripts
npm run format:check
npm test
npm run build
npx playwright install chromium
npm run verify
```

The build writes server/internal/webui/dist, including runtime license texts and
the retained .gitkeep placeholder. Generated assets and node_modules are ignored.
Go embeds the production build; nethub web refuses startup when it is missing.
Build the UI before compiling the deployment binary. Only known assets and the
root document are served; source maps, hidden files, and directory listings are
unavailable. Hashed assets are immutable-cacheable; HTML/API responses are no-store.

The request wrapper attaches per-session CSRF, uses same-origin credentials and
no-store, and clears the signed-in view on 401. Password state is cleared on
submission. Session/CSRF/enrollment values never enter browser storage or URLs.
Only the optional light/dark preference is stored locally. The enrollment dialog
clears its token on close, expiry, or unmount, cancels pending requests, and makes
plaintext available only from the issue response. Clipboard writes are explicit;
copied text remains in the user's system clipboard. No background network polling
renews idle sessions or device grants.

The visible inventory refreshes every five seconds, with one request in flight.
Hidden pages pause polling and refresh when visible again. Closing enrollment
also refreshes immediately. Background reads use passive session validation:
tenant, role, disable state, idle expiry and absolute expiry are checked without
updating session activity. User-initiated loads retain normal activity updates.

Browser verification compiles a separate loopback TLS fixture using production
authentication and HTTP handlers, with isolated accounts and in-memory storage.
Its test-control routes are confined to that fixture and are not linked into the
product CLI. Real PostgreSQL actor/tenant, audit rollback, and token-consumption
boundaries are covered separately by server/tests/postgres.sh. The deployment CI
also drives Chromium through the actual Caddy/web/PostgreSQL Compose project.
Public HTTPS acceptance uses tests/public-browser.mjs with a private configuration
outside the checkout; its TLS probe verifies the bundled public CA set and the
browser keeps certificate checking enabled. npm test verifies that an untrusted
self-signed server is rejected before an HTTP request can reach it.

NETHUB_UI_EVIDENCE selects a private screenshot/results directory; otherwise the
script retains evidence under its temporary stage. PLAYWRIGHT_CHANNEL=chrome can
use an installed Chrome for local verification. CI installs the pinned Playwright
Chromium and runs the same flows. The tested flows include keyboard focus, token
clearing and expiry, storage isolation, light/dark, a 390px viewport, logout, and
401 redirect; this is not a full accessibility or cross-browser audit.
Inventory tests also cover automatic updates without reload, a response spanning
another poll tick, and simulated hidden/visible transitions.

Four registry component sources were taken from the W3-0 reviewed snapshot
outside this repository, then formatted. Their upstream MIT text is retained in
THIRD_PARTY_LICENSE.txt. The native dialog adapter is independently implemented.
The build collects license files from every runtime npm package into the served
notice page. Dependencies and Actions are fixed in manifests/lockfiles or by SHA.
