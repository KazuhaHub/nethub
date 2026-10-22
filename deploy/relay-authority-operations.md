# Relay authority operations

These Linux root commands use the existing protected deployment, database fence,
file journal and bound service adapter. Trust publication and device confirmation
must precede activation. An offline active device remains an admission barrier;
these commands do not waive it or repair an expired original authority.

First inspect the healthy, existing deployment binding:

```sh
nethub certificates relay-authority binding \
  --directory /root/deployment --project-name nethub
```

This read-only action returns `service_fingerprint`. Prepare an explicit original
options JSON file in a canonical root-owned mode-0700 directory; the file must be
a regular, single-link, root-owned mode-0600 file. Its fields are:

| Field | Required value |
| --- | --- |
| `deployment` | Absolute confirmed deployment path |
| `candidate` | Independently prepared successor authority directory |
| `candidate_backup` | Verified independent candidate backup directory |
| `custody_file` | Explicit candidate backup acknowledgement receipt |
| `successor_backup` | New protected destination for the successor deployment backup |
| `service_fingerprint` | Exact fingerprint returned by the binding action |
| `request.id` | New nonzero canonical operation UUID |
| `request.trust_generation_id` | Current, acknowledged overlap generation UUID |
| `request.previous_root`, `request.next_root` | Exact distinct SHA256 root fingerprints |
| `request.previous_leaf`, `request.next_leaf` | Exact distinct SHA256 leaf fingerprints |

Unknown and duplicate JSON fields, relative paths and missing identities are
refused. The command does not fill missing values from mutable live state.

```sh
nethub certificates relay-authority activate \
  --directory /root/deployment --project-name nethub \
  --options-file /root/operations/original.json
```

Before invoking the transition, activation atomically retains the full canonical
input, project and override path in
`authority-commands/<operation-id>.json` inside the deployment. It never replaces
another record. An exact activation retry uses the original record; conflicting,
partial, aliased or public records are refused and retained for inspection.
The filesystem must support atomic no-replace rename; unsupported retention
fails before the transition starts.

After interruption, use the same explicit project and override with the retained
operation ID:

```sh
nethub certificates relay-authority resume \
  --directory /root/deployment --project-name nethub --operation-id "$operation_id"
```

`abort` cancels a prepared operation only after independently verifying the
complete original state and serialized database decision. `cancel-preparation`
handles initialization that stopped before a complete snapshot existed, using
the original retained input. Both require the same deployment, project,
optional `--compose-file` and `--operation-id` as `resume`. Neither command deletes
or repairs partial material, restores services to make cancellation pass, or
treats a missing database record as authorization to cancel.

Retain the input, operation journal, backups and database receipts after any
failure. Successful command output contains public transition metadata; it does
not establish native installation, offline recovery or public GUI acceptance.
