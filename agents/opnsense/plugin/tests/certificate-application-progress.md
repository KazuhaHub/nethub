# Authenticated GUI application reports

Protocol 1.4 adds an authenticated applied-generation report and immutable server
receipt. The authz repository holds the current credential/tenant/assignment lock
through original CSR/key correlation, valid issued-generation lookup, report and
one audit. A newer issuance alone does not invalidate an older installed valid
leaf. A newer confirmed application refuses older reports. Exact retries return
the first accepted_at; expiry and revocation are checked again. Reports neither
issue certificates nor establish relay online state.

Migration 00012 gives only authz the narrow function. Application roles have no
raw table/column grants, and the history has forced RLS plus an immutable trigger.
Health checks require the function owner/security boundary and table guards.

Native 0.0.11 reports only after the local transaction and actual served
CA/hostname/leaf/GET verification. Losing a confirmation keeps the durable applied
journal; the next cycle verifies and retries it without reinstalling. A 1.3
console produces an applied_unconfirmed upgrade message and no unsupported POST.
Updating the console minor alone enables reporting without reinstalling unchanged
material. Confirmation state is separate from tunnel health and no new private
runtime path was added.

Working-tree validation passed Go protocol/device/store unit or compile checks,
26 Python wire cases, four new native coordinator cases, and the genuine isolated
PostgreSQL harness. SQL cases exercised audit-failure rollback, eight concurrent
identical receipts, live credential/tenant/generation bindings, immutable grants,
valid superseded issuance, monotonic application and a request blocked until
revocation committed. Its second-generation rows were administratively seeded;
this does not establish renewal scheduling. Initial native fixture setup errors
were corrected in the test fixture; appliance configuration/package stayed
unchanged and temporary keys were removed. Exact committed-source validation and
artifact receipts belong to the PR/checkpoint, not this earlier working-tree run.

Reports are authenticated device statements. The server cannot independently
observe the router's local GUI through this API. Fresh combined public/native
acceptance, automatic renewal and staged trust/offline recovery remain. The
previous 0.0.10 Core/TLS/quick-reboot proof is separately recorded; it does not
establish a live 0.0.11 report to a deployed console.
