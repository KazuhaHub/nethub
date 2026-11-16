# External TCP observations

`doctor --external-tcp-check-host --expected-address <public-IP>` explicitly asks
[Check-Host's TCP API](https://check-host.net/about/api) to test only ports 443,
7000 and 8443. The provider receives the target IP and ports, and its report may
be public. No deployment credentials, device names, tokens, claims or keys are
sent. Other doctor modes do not call this service.

All three provider-selected observers must connect to the exact expected IP on
each port. Responses are bounded and checked against the new request's protocol,
target, observer identities and creation time. Pending results have a finite
poll budget and the complete check has a 45-second context deadline. Submission
is not retried; provider failures, rate limits, incomplete observations, wrong
addresses and closed ports fail without partial success or raw provider errors.
HTTPS uses normal system trust and refuses redirects.

Run DNS checks separately against the initialized manifest. TCP observations
do not verify a certificate, hostname routing, a source-IP grant, successful
device admission or the published appliance version. Availability from three
provider nodes does not imply availability from every operator network. The
service is an optional external dependency, not a replacement for mobile and
independent operator acceptance.

Unit fixtures exercise the protocol and denial paths without contacting the
provider. They do not establish real public reachability; the compiled command
still requires a separate owned public positive/closed-port acceptance sample.
