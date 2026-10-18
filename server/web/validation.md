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
recorded in ../internal/store/validation.md. First-admin creation, init/doctor,
complete Compose/Caddy startup, real deployed browser acceptance, device enrollment,
and SSO remain future stage work. W3 as a whole is not yet accepted.
