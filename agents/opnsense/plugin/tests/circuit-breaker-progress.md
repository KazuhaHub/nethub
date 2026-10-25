# Local circuit breaker

The 0.0.17 development sources add a local Stop remote access switch to the
plugin page and an independent-access reminder before enrollment. Configd exposes
fixed `disable` and `enable` actions behind POST-only, write-authorized PHP
handlers. Both actions use the existing nonblocking lock and bounded job runner.

Disable atomically writes the private `disabled` marker and syncs its directory,
stops frpc directly, verifies the service stopped and disables its rc flag. It
does not parse native XML or run trust recovery before stopping. Failed stop or
failed rc writes return failure with the marker retained. A competing operation
returns busy without claiming the circuit breaker took effect.

Enable removes only `disabled` and reconciles saved intent. It never clears
`stopped`, `revoked` or `uninstalling`, or changes the saved enabled setting.
Runtime marker files are outside config.xml and remain across package replacement;
the existing rc prestart and watchdog also honor them. Releasing the switch does
not guarantee a tunnel when another stop condition remains.

Tests exercise broken XML/trust recovery, idempotent stop, exact native-XML bytes,
saved intent, other stop markers, failed/ineffective stop, rc-write failure, lock
contention and symlink refusal. The PHP contract tests POST/read-only enforcement,
bounded backend dispatch, busy responses and invalid output. Scheduler contracts
cover the shared lock and deadline. These are isolated source tests; they do not
prove native installation, real process cutoff timing or physical reboot behavior.
Those W5 acceptance items remain open until measured on the appliance.

The unsigned 0.0.17 package was built on the native FreeBSD appliance from
`77ddab2` in 457.032 seconds with the accepted 1 GiB allocation. The package,
product and model versions agree; all 46 tracked packaged source files matched
their committed hashes. The exported package SHA256 is
`450dc403d8a326ba8ab8d493b9b144a51572db92d698b59569108ec87893d0a5`.
Independent post-restore checks confirmed the original 0.0.6 package, byte-identical
native configuration, operator stop, stopped frpc and usable configd. The candidate
was not installed. This proves package preparation and baseline restoration;
installed circuit-breaker and combined public W5 acceptance remain open.
