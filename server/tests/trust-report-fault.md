# Lost trust-report response fixture

`trust_report_fault.py` forwards the relay trust application endpoint to a
loopback device API origin. For one selected device/generation, it records a
matching successful response and closes the downstream connection before sending
that response. Further requests receive the backend's original status/body.

Run it inside an independently bounded, isolated Linux lab window. Prepare an
unused root-owned directory with mode 0700 and a mode-0600 `config.json`:

```json
{
  "device_id": "01234567-89ab-4cde-8123-456789abcdef",
  "generation": 2,
  "backend_port": 18081,
  "listen_port": 18991,
  "seconds": 300
}
```

```sh
python3 server/tests/trust_report_fault.py --directory /root/trust-report-lab
```

The listener and upstream use 127.0.0.1. Configure the operator-owned HTTPS proxy
to send only `/api/v1/devices/relay-trust/applied` to the fixture. Preserve the
generated Host, forwarded client address and HTTPS scheme headers. In Caddy,
use a `route` block to place this specific upstream before the broader device
API route. Native console TLS verification remains enabled.

`ready.json` binds the process, port and configuration hash. `dropped.json`
records the accepted timestamp and response hash after the backend reply has
been read. Request credentials are forwarded without logging them. The fixture
allows four workers, bounds both bodies and transport timeouts, and exits within
the configured duration (at most ten minutes).

Before publication, hold the native shared reconcile lock so the scheduler
cannot consume the intended first report. Publish the desired overlap through
the protected host command, then invoke the real native trust worker under that
lock. Require `applied_unconfirmed` and the drop receipt. Independently verify
the generation-specific PostgreSQL application/audit row and accepted timestamp.
Retry the worker; require confirmation with unchanged CA bytes/PID and the same
server receipt. Restore the original proxy route and stop the owned fixture in
the cleanup path, including after a failed assertion.

The loopback unit tests establish forwarding, response-loss selection and resource
bounds using a synthetic backend. Native application, genuine database commit
and retry acceptance require the separate live run.
