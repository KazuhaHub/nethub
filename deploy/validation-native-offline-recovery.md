# Native online display and offline recovery

Follow-up: the corrected 0.0.15 package passed a separate guarded offline-renewal
and reboot-persistence experiment. See [its measurements and scope](validation-native-offline-renewal.md).
The failed 0.0.14 result below remains unchanged.

The corrected runtime from source `ab20628` passed all six jobs in run
39953411565 before PR #138 merged as `4ae1caa`. Actual job logs were checked for
the session-expiry, dialog, browser, compiled observation and retained deployment
gates. The downloaded archive, image configurations and uncompressed layers were
verified before importing it. Only the retained test deployment's runtime image
changed; its earlier accepted Caddy, frps and PostgreSQL images remained selected.

The native client was OPNsense 26.7.7 with unsigned plugin 0.0.14, built from
`aaf0dbe`. It used the owner-approved 1 GiB allocation, below the documented
3 GiB VM minimum. Console and device certificate trust used independent private
test roots and explicit lab DNS. This is not public CA acceptance.

## Automatic online display

The browser enrolled a new native identity and rendered **Recently online in
2.511 seconds**, measured from clicking Enroll. It did not reload the console or
click Refresh. The earlier fresh-backend measurement remains recorded in
[fresh enrollment validation](validation-native-fresh-browser.md); this repeat
used the retained backend with a clean, unenrolled native checkpoint.

Independent checks bound the consumed browser token to PostgreSQL, the returned
identity to the actual native model, and the native private key and credential
to their server records. Wrong-secret controls passed. Five screenshots and
complete initial profile exports were retained privately. The browser reported
zero script errors or external requests.

The earlier 16.862-second failure remains a failure. This is a distinct repeat
with the corrected image, rather than a relaxed target or reclassified result.

## Offline certificate result

Genuine package cron installed and confirmed generation 1. Its relayed TLS leaf
passed independent root, hostname and fingerprint checks. The guarded guest was
then shut down. Natural renewal issued generation 2 while the host observer
confirmed that the same guest was off; no generation-2 application appeared.

After starting that guest once, an early boot receipt confirmed the same native
key, selected certificate reference, leaf and applied generation-1 journal.
Both test roots survived the supported native trust rebuild, and the explicit
lab DNS fixture became ready. Generation 2 still had about 181 seconds of
validity at that point.

**Generation 2 was not confirmed after boot.** Its first retained application
error occurred with about 76 seconds of validity remaining. The public status
reported a native application failure; it does not establish the underlying
cause. The private CA recorded exactly two orders and finalizations. Both
generation records and the sole generation-1 application remained unchanged
through the retained observations. No clock or immutable database row was edited.

This experiment is a failed offline lifecycle result. Boot preservation and the
online-display prefix passed; automatic post-boot certificate application,
rollback and the combined W4 certificate acceptance remain open. Additional
diagnostics will capture the transaction, selected native entry and exact PHP
store failure before cleanup. Public error responses remain unchanged.

The created fixture completed signed fallback unenrollment. Independent guards
restored the original cold checkpoint, package 0.0.6, configuration and stopped
intent. All 14 original relay containers, service bindings and TCP listener
owners were verified, and the owned stack stopped. Historical fixture records,
keys and failed-run evidence were retained outside Git.
