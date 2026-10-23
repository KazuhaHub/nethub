# Enrollment rejection evidence

The isolated deployment used for [fresh native browser enrollment](validation-native-fresh-browser.md)
was resumed without resetting its database or authority. The accepted server
images remained unchanged. Two additional protocol clients used independently
generated P-256 keys and genuine console-issued tokens. They are synthetic API
clients, not additional OPNsense appliances.

## Observed responses

| Request | HTTP | Result |
| --- | --- | --- |
| Valid unused token, protocol `99.0.0` | 400 | `incompatible_protocol`: `Unsupported device protocol; supported major is 1` |
| Same token and key, supported protocol `1.5.0` | 201 | Device enrolled |
| Immediate replay while that token remained unexpired | 401 | `enrollment_failed` |
| Different unused token after its natural 900-second lifetime | 401 | `enrollment_failed` |
| Same expired-request fields and key, with a fresh token | 201 | Device enrolled |

Independent PostgreSQL snapshots showed identical device, token and audit rows
before and after each rejected request. Incompatible protocol did not consume
the token. Replay preserved its original first-use timestamp. The expired token
remained unused, with exactly its original creation and expiry timestamps; the
server clock and token lifetime were not changed. The expiry sample reached the
server 3,377.396 seconds after expiry. Its fresh-token positive control excludes
an invalid key or other request field as the reason for rejection.

Both successful fixture assignments were retained privately and independently
bound to their database device IDs, subdomains, public keys and password hashes.
The production password verifier accepted each returned secret and rejected a
one-character wrong-secret control. PKCS#8 private keys matched the database
public keys. No assignment was reconstructed from another device's configuration.

## Secret separation and cleanup

After both windows, all six owned service containers were stopped. Their actual
logs contained none of the 20 distinct known credential values checked, including
the three enrolled devices' secrets/claims and the test enrollment tokens.
This covers the successful, incompatible-version, replay and expired-token paths;
claim-tampering and cross-device proxy attempts require their own log checks.

The actual accepted web image had a read-only root filesystem and exactly one
read-only bind at `/run/secrets`. A bounded archive read from the stopped container
confirmed only `pg_nethub_web` and `secrets_key`. The latter encrypts application
provider secrets; no claim-signing key, relay administrator credential, FRP auth
token or issuer private key was present. Docker's writable-layer diff contained
only the `/run` and `/run/secrets` mountpoint preparation entries.

The protected `nethub doctor` command returned success for secret checksums,
independent backup coverage and service ownership. It does not establish runtime
health or DNS correctness. Independent restoration verified all 14 original
running container IDs, original configurations and port owners. The isolated
database, authority, genuine assignments and recovery copies were retained.
The native appliance was not modified by these API tests.

Raw requests, replies, snapshots, logs and key material remain outside Git.
Public-CA trust, tampered-claim Login rejection, cross-device NewProxy rejection,
unenrollment and the remaining certificate lifecycle acceptance stay open.
