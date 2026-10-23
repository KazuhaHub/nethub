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

Local relay observer tests passed. Complete hosted regression, assembled-image
acceptance and a native repeat with the corrected runtime remain required. The
W4 online-latency checkbox is reopened until that native revalidation passes;
the failed run is not relabeled as a successful 15-second result.
