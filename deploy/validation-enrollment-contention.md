# Native enrollment lock contention

Interactive enrollment previously ran behind configd's nonblocking `lockf`.
If a scheduled operation held the shared lock, the wrapper could exit before
Python produced a response. The controller then displayed a generic enrollment
failure. The 0.0.16 development package lets enrollment acquire the same lock
internally, waiting at most three seconds before returning a structured busy
result. The controller displays a fixed retry message and removes its temporary
request. It never forwards the child diagnostic.

Reconcile and watchdog retain their shared `lockf -t 0` behavior. Enrollment's
25-second internal deadline, 30-second outer timeout with a two-second kill
grace, and 35-second controller timeout are unchanged.

## Native source validation

On OPNsense 26.7.7 / FreeBSD 15, fourteen targeted tests passed against public
source staged in a disposable directory. No installed package or appliance
configuration was changed by these tests.

- A held mutation lock prevents request consumption, key creation and network
  access. Releasing the lock during the bounded wait allows enrollment to
  continue once, retaining the original native configuration.
- An actual `/usr/bin/lockf -sk -t 0` child excludes Python's `fcntl.flock` on
  the same file. Enrollment returns busy while it is held and reaches the
  controlled network boundary after the child releases it.
- The real PHP controller contract recognizes service contention, returns only
  its fixed message, removes the protected request, and neither saves an
  assignment nor starts the tunnel. A synthetic secret in the child message
  does not reach the browser response.
- The configd command contract retains the outer deadline and passes only the
  request path, with no credentials or output cache.

Running the same fourteen tests with the three original implementation files
from `62b0316` produced the three expected failures: delayed lock release,
configd dispatch and controller busy handling. The other eleven passed.

## Limits

The latest physical offline trust trial failed during browser enrollment before
local key creation. Its exact cause remains unclassified; these tests establish
the lock-handling defect independently. They do not prove that contention caused
that particular failure, nor do they replace installed-package browser acceptance.
The appliance baseline and original relay services were restored after that
trial. Physical offline root-transition recovery, public CA acceptance, combined
W4 certificate acceptance and W5-W7 remain incomplete.
