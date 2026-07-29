# BPF pin owner journal hardening

## Scope and durable files

The default pin directory is `/sys/fs/bpf/wg-mix-ebpf`. Resource locks live
under `/run/wg-mix-ebpf/pin-locks`; owner records and their index live under
`/var/lib/wg-mix-ebpf/pin-owners`. All owner/index operations use anchored
directory FDs, regular files owned by the expected UID, mode `0600`, and
single-link inode checks.

The canonical owner record is `<resource_key>.owner.json` (schema v3).
Descriptor CAS uses the exact `.owner.next` and `.owner.retired` names. The
index is `instances.v2.json`, with corresponding `.next` and `.retired`
descriptors.

Index identity is `(resource_key, boot_id)`, while an explicit active pointer
selects one entry for each FD-anchored resource identity. Path strings must
also be unique, but bind-mount aliases with the same parent device/inode and
basename resolve to the same resource pointer instead of creating a second
ownership domain. A prior-boot record is archived with `RENAME_NOREPLACE` as:

```text
history-<resource_key>-<boot_id>-<owner_sha256>.owner.json
```

`.owner.archive` and `.rotating` are exact, journaled transition names. No
history recovery or rotation scans directories or expands globs.

## Reboot and retention rules

Both changed-resource and same-resource-key reboots are recoverable. The old
record first becomes the indexed `rekey_source`; the new record names the old
`resource_key` and `boot_id` as immutable lineage. Publishing the new current
record changes the old entry to `retired` and moves the active pointer in the
same index CAS. The historical file remains available as audit evidence.

Each pin path and each FD-anchored resource identity retains at most eight
non-active records, so aliases cannot bypass the history bound; the whole
index retains at most 128 entries. At a bound, only the oldest fully validated
`retired` record in the constrained path/resource lineage (or the global index
for its global bound) is eligible. Rotation writes one exact victim into the
index journal, renames only its deterministic filename to its exact
`.rotating` name, validates the same owner digest and inode, unlinks it, then
removes only that `(resource_key, boot_id)` entry. Missing, duplicate, changed,
or colliding evidence fails closed.

## Owner state and crash recovery

Valid phase/step pairs are:

| Phase | Valid steps |
| --- | --- |
| `active` | `ready` |
| `applying` | `staging`, `mutating`, `cleanup` |
| `detaching` | `staging`, `mutating_tc`, `unlinking_maps`, `cleanup_stages` |

Recovery is deterministic at every durable boundary:

| Journal | Durable state | Recovery |
| --- | --- | --- |
| Owner update | `.owner.next` staged | Validate immutable fields, exchange, sync index, then unlink old record |
| Owner update | canonical exchanged, old record still `.owner.next` | Sync the canonical digest into the index, then unlink the exact old record |
| Reboot archive | canonical moved to `.owner.archive` or final history name, index still active | Validate the indexed digest and roll back to canonical |
| Reboot archive | index pointer is `rekey_source` | Preserve history and continue same-key or changed-key rekey |
| History rotation | rotation journal with original, `.rotating`, or neither file | Resume the one authorized rename/unlink/index removal |
| Detach | owner moved to `.owner.retired` | Remove the exact active index entry before unlinking the retired owner |

The old owner descriptor remains present until its new digest is durably
indexed. This prevents a crash from leaving an unprovable “new owner plus old
index digest” state.

## Public ownership API and locking

`InspectPinOwnership(ctx, pinPath)` validates owner, index-derived path
identity, maps, generation, and TC bindings without repairing or mutating
owner/index/pin/map/TC state. It still acquires the per-resource lease, whose
lock file records the inspection.

An absent pin directory does not erase durable ownership: inspection reports
the exact canonical or historical record as recovery-required, and detach
refuses to treat the missing directory as successful cleanup while owner/index
evidence remains.

`RecoverPinOwnership(ctx, pinPath, lifecycleLease)` and
`DetachPinOwnership(ctx, pinPath, lifecycleLease)` require the caller's
already-held global lifecycle lease. They verify the exact lifecycle path and
inode, retain its file description for the full call, and only then acquire
the resource lock. Shared-index read/modify/write and recovery is additionally
serialized by a process-local mutex, including the pre-stage
`current == expected` CAS check. They never reacquire the global lease, so the
mutation lock order is always:

```text
global lifecycle lease -> per-resource lease -> shared-index mutex
```

Pinned maps are normally opened read-only. A control or owner-map update
reopens the exact pin read-write, verifies that its kernel map ID still equals
the read-only observation, performs the update through that FD, and closes it.

## Transaction boundary

TC filter writes use a preflighted multi-slot rollback transaction, and pin
files use the owner filesystem journal. They are coordinated by the durable
owner phase but are not a single cross-subsystem atomic kernel transaction.
Recovery therefore validates every recorded map, program, filter, and
generation identity before completing or rolling back a phase. It never
deletes `clsact`, and it never trusts prior-boot TC program IDs: recorded TC
slots must be absent before reboot rekey.
