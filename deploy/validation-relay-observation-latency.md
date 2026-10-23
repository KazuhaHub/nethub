# Online display timing regression

A retained native enrollment on 2026-10-23 returned HTTP 200 in 1.854 seconds,
with `enrolled: true` and `tunnel_ready: true`. The console API reported online
after 15.651 seconds and the rendered row after 16.862 seconds. The 15-second
acceptance assertion failed; the coordinator did not continue into its offline
certificate experiment. Its model/key export and genuine fixture removal were
retained, and independent guards restored the original services and appliance.

The read-only relay observer polled every 15 seconds. A proxy registered just
after an empty snapshot could therefore wait a full period before discovery,
leaving no time for enrollment or rendering within the same 15-second target.
Earlier successful measurements, including the 3.723-second fresh run, did not
exercise that timer phase and remain archived separately.

The recorded rendered-row measurement included an explicit console reload. The
inventory previously had no automatic refresh. The visible inventory now polls
every five seconds, skips overlapping requests, pauses while hidden and refreshes
on visibility restoration or enrollment-dialog close. Native revalidation waits
for the rendered online row without reloading or clicking Refresh.

The observer now polls every five seconds. Each poll still uses one bounded,
read-only admin request, without overlap. Parser limits, storage bounds, skipped
busy rows, credential isolation and safe failure logging are unchanged. The
45-second recent-observation window remains unchanged. This display signal does
not authorize access or change revocation-discovery confirmations or D6 heartbeats.

`TestNewProxyAfterEmptyPollLeavesEnrollmentDisplayBudget` runs the real production
timer. It waits for the initial empty snapshot, then registers a valid proxy and
requires delivery to the repository within eight seconds. The test failed with
the former period and passed after the correction. It does not shorten or replace
the production timer. The compiled-runtime PostgreSQL test also checks a
four-to-eight-second interval between actual admin requests and matching persisted
state, followed by revocation and clean shutdown.

The browser regression changes fixture inventory without a manual refresh. It
failed against the former UI and passes with automatic refresh. Further cases
hold a response across another timer tick and test hidden/visible transitions.
Background inventory requests use passive authentication, preserving current
user/tenant and expiry checks without updating session activity. Database tests
cover unchanged activity, natural idle expiry, role/disable changes and expiry
after user/session lock waits for both authentication modes.

Local relay observer tests passed. Complete hosted regression, assembled-image
acceptance and a native repeat with the corrected runtime remain required. The
W4 online-latency checkbox is reopened until that native revalidation passes;
the failed run is not relabeled as a successful 15-second result.

Hosted acceptance also exposed duplicate dialog dismissal. Escape and the close
button notified the parent, then the controlled native `close` event notified it
again. Each dismissal started two inventory refreshes and cancelled the first.
The dialog now uses its native close event as the single notification boundary.
A real-browser regression observed two active refreshes before the change and
requires exactly one after each dismissal. The deployed browser also waits for
the active response and completed body before its next transition. Both the
zero-unexpected-network-failures assertion and native focus behavior remain.

A later run reached official frps configuration validation, then exhausted its
20-minute job deadline without reporting the next phase. The available log does
not establish which subsequent command stalled. Compose startup, administrator
initialization and cleanup now have separate command deadlines and fixed phase
messages; failure output includes only service state, without configuration or
credentials. The repeat-initialization check additionally requires the actual
account-state refusal and exit 1. A shell control demonstrated that the former
check accepted exit 124; current tests reject timeout, unexpected success and a
daemon failure. No integration check was removed or job deadline increased.
