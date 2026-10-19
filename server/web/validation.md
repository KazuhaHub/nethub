# W3 console validation (2026-10-18)

The production Vite build and embedded Go HTTP handler passed local Chrome
verification against an isolated loopback TLS fixture using the real authentication
service and console handlers. All fourteen exercised groups passed: sign-in,
reload/session recovery, empty inventory, enrollment, explicit clipboard copy,
modal focus containment, Escape/focus return, token clearing, two-second fixture
expiry, search, light/dark, 390px mobile layout, 401 redirect, and logout.

The run observed zero CSP violations across navigation, zero browser script
errors, and zero external requests. The session cookie was HttpOnly/Secure and
unavailable to document.cookie. Raw cookie and enrollment values were absent
from local/session storage and server logs. Modal Tab cycling initially reached
the document root; explicit first/last-control wrapping corrected it and the
unchanged containment assertion passed afterward.

The first Linux Chromium run also exposed Escape close-event ordering: the native
dialog became hidden before React cleared enrollment state. The cancel handler
now prevents native auto-close, clears the parent state, and lets the controlled
effect close the dialog. Local Chrome passes the unchanged DOM-clearing assertion;
the revised CI run verifies the same behavior in pinned Chromium.

Desktop login, empty inventory, populated light/dark inventory, and mobile
screenshots were visually inspected and retained privately. Screenshots contain
fixture account/device data only; no enrollment plaintext is captured. The mobile
table scrolls within its panel without horizontal document overflow.

The production bundle is about 95 KiB gzip across HTML, JavaScript, and CSS.
This measurement excludes the separately served license text and does not claim
production transfer or real-network latency. npm runtime audit found no known
vulnerabilities in the pinned dependency set at implementation time.

The API-wrapper tests verify CSRF attachment/clearing, same-origin/no-store fetch,
credential-free URLs, generic network errors, and bounded Retry-After display.
Go asset tests reject hidden/source-map/directory/traversal paths, test HEAD and
immutable asset caching, and return 503 for a missing build.

This browser fixture uses in-memory storage; the genuine PostgreSQL API tests are
recorded in ../internal/store/validation.md. Separate
[deployment validation](../../deploy/validation-w3.md) covers first-admin creation,
initialization, scoped doctor, Compose/Caddy startup, and real deployed browser
flows, including the combined clean-host public run. Device enrollment and SSO
remain W4/W6 work; this page records the isolated fixture scope.
