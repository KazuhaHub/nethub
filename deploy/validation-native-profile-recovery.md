# Retained native identity recovery

The device from [fresh browser enrollment](validation-native-fresh-browser.md)
reconnected after the appliance had returned to its original cold checkpoint.
The guarded experiment installed the same tested unsigned 0.0.14 package, restored
the actual PHP-saved model and its exported P-256 key, and started it through
configd. No new enrollment request or token was created.

Before restoration, all four exported files matched their recorded hashes and
0600 modes. The original device row, subdomain and public key matched PostgreSQL.
The production password verifier accepted the saved secret and rejected a
wrong-secret control; the PKCS#8 private key matched the database public key.
The saved model was not converted into a fabricated protocol assignment.

On the appliance, native PHP model validation and exact saved-field comparison
passed. The two key files remained byte-identical. Console HTTPS used verified
fixture trust and hostname resolution. Explicit start succeeded, and the actual
frps administrator API reported that same device's HTTPS proxy online.

A subsequent native `configctl nethub-agent trust` returned applied/confirmed for
generation 1. The model's public CA matched the runtime file, frpc remained
running, and PostgreSQL held one matching trust application and audit record
for the published bundle. The backend retained three devices and four tokens:
the genuine native device and the two labeled API fixtures. The newly saved
trust state and unchanged key files were exported before cleanup.

Independent guards closed the relay window and restored the cold appliance
checkpoint. After boot, checks confirmed exact original configuration, package
0.0.6, stopped intent, ready configd/SSH, the 1 GiB allocation and the pinned cold
checkpoint. All 14 original running container IDs, original configurations and
443/8443 owners matched; owned services were stopped. A further scan of six owned
service logs found none of 20 known credential literals, and secret mount/file
doctor checks passed again.

This establishes reuse of a genuine retained identity for further certificate
acceptance. It does not establish GUI certificate issuance, installation,
renewal, rollback or public-CA trust. The owner-approved 1 GiB deviation and
fixture CA/DNS scope remain. Raw models, credentials, keys, logs and recovery
snapshots stay outside Git.
