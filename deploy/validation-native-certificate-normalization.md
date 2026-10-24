# Native certificate model normalization

## Observed failure

The guarded offline repeat on OPNsense 26.7.7 reproduced the post-boot
generation-2 application failure with unsigned plugin 0.0.14. Generation 1 had
been applied and independently verified over relayed TLS. Generation 2 was
issued through natural renewal while the same 1 GiB guest was confirmed off.
The original key, selected reference, leaf and applied journal survived boot.

A protected diagnostic ran the exact installed PHP store against a private
shadow snapshot and captured `Native managed selection was changed` at the
last-good check. The real configuration remained unchanged. The saved native
entry still matched the journal's device, selected reference and description;
its certificate chain and private key were byte-identical to the installed
snapshot. Core had added a `uuid` attribute, empty `caref` and `csr` fields, and
reordered the fields. The raw canonical XML digest therefore differed.

These fields match the native [Trust certificate model](https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/models/OPNsense/Trust/Cert.xml).

## Correction and limits

Managed-entry hashes retain the original four-field representation across this
native model serialization. A syntactically valid native UUID and absent versus
empty optional CA/CSR fields do not change that identity. Nonempty CA/CSR values
remain bound. Unknown attributes or fields, duplicates and nested fields are
refused; certificate material, description, device and selected reference checks
remain in place. Unmanaged certificate hashing is unchanged.
Renewal retains the existing native UUID and emits the native model's six
persistent fields, so it preserves that entry's UI identity.

The actual FreeBSD PHP implementation rejected the saved boot entry before the
change and matched its original last-good digest afterward. Eleven changed
material/shape controls remained rejected. Both source hashes and unchanged
native configuration were independently checked. Private XML, keys, credentials
and diagnostic payloads remain outside Git.

The complete PHP store contract file then ran on the actual FreeBSD appliance
using root-owned temporary fixtures and temporary pure-Python test dependencies.
Both newly added native-model serialization cases failed against the original
store. The corrected store passed all 29 cases, covering unchanged retries,
generation-2 renewal, rollback and eleven material/shape refusals. Rollback
compares complete parsed XML because the native save serializes empty elements
differently; the unchanged retry must preserve the file byte-for-byte. No test
package was installed, and the real native configuration digest was unchanged.

The failed experiment completed genuine signed fixture removal. Independent
guards restored the original appliance checkpoint, package, configuration and
stopped intent, plus all 14 original relay services and listener ownership.
The lightweight host helper completed the actual single guarded start at the
unchanged 1 GiB allocation, with a successful Windows asynchronous job and no
job error; it changed no VM settings or unrelated processes.

The corrected 0.0.15 package subsequently passed a separate native offline
renewal and reboot-persistence experiment; see [the measurements and scope](validation-native-offline-renewal.md).
Wrong-host/key rejection, native restart failure/rollback, public CA and the
remaining W4-W7 acceptance remain open. The earlier failed lifecycle retains
its original outcome.
