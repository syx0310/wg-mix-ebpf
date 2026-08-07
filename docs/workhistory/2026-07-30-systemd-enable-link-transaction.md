# Systemd enable-link transaction

`install --enable` no longer delegates enablement to `systemctl enable`. The
installed unit has one reviewed install target,
`multi-user.target.wants/wg-mix-ebpf.service`, so installation creates only that
exact relative symlink through a held directory descriptor.

Before creating the link, installation reloads and verifies the systemd manager
and publishes the cleanup ownership manifest. The enable transaction then opens
an already-existing wants directory. It does not create or remove that
directory; a missing declared wants directory is a fail-closed installation
error.

The declared-directory walk starts at a kernel `/` FD and retains an FD plus
identity for every canonical path component through `systemRoot` and the
artifact parent. Thus `systemRoot` itself also has a held parent-to-child edge.
Aliases such as `/var` to `/private/var` are resolved once into a canonical edge
sequence. Ordinary mount transitions such as a separate `/usr` or `/etc` are
allowed while walking to `systemRoot`, but every resulting mount identity is
held and compared; the artifact-relative subtree may not cross another mount.
Revalidation requires the declared alias to keep resolving to that same
canonical root. The walk also records each directory's change generation
separately from its stable inode identity. Hooks are followed immediately by a
full held-prefix identity, generation, and edge check. Commit performs a second
complete walk and compares every component and generation with the original
chain before and after validating the exact symlink inode, owner, and target.
Only a narrowly identified directory generation is refreshed after a
transaction-owned mutation: creation of the final directory, object-bound
publication in the final parent, or creation plus snapshot and sync of the
enable link. This rejects persistent replacements and transient
replace-then-reattach attacks against higher ancestors, `systemRoot`, and the
wants subtree.

Non-declared managed directories, including the held config/manifest parent,
separately pin both their held parent generation and their own directory
generation. Constructors record these baselines only after any exclusive
`mkdirat` and parent sync. Revalidation compares the parent FD, directory FD,
and named edge. A successful object publication may refresh only the directory
generation; state-directory creation or authorized recreation may refresh a
held sibling's parent generation only after proving both objects hold the same
post-creation parent.
Binary and service artifact parent directories are prepared before ownership
baselining, while the systemd wants directory remains strictly pre-existing.

Failure after enablement is non-destructive. The transaction does not rename,
unlink, restore, or remove any link or directory. Its error reports the original
declared path, held symlink identity, current descriptor-relative status, and
manual follow-up. A later uninstall does not trust the manifest as an inode
record: it snapshots the symlink currently at the one declared wants path,
requires its UID and target to match the installation contract, and carries
that held inode through the existing quarantine and no-replace cleanup chain.
An inode or target replacement after preflight fails closed while a normal
enabled installation is removed in one uninstall operation.

Retained enable-link evidence is bounded without deleting old evidence by
pathname. Each artifact preflight and the final pre-rename boundary enumerate
the project quarantine prefix through the held, revalidated wants-directory
descriptor. Existing exact paths are surfaced in the uninstall plan. The
operational pre-rename threshold permits at most six existing names: one slot
is reserved for the current owned quarantine and one for the supported case in
which that binding is replaced while both the moved owned link and its foreign
replacement must be retained. Normal cycles therefore stop at seven names,
while one binding ambiguity can reach but not exceed the hard limit of eight.

Entering final service-artifact execution first downgrades every non-empty
preflight evidence snapshot to last-known, before hooks or plan revalidation.
Only a final stable descriptor-based enumeration upgrades that directory back
to current. The post-final-check boundary always attempts this enumeration,
even when the hook or binding check fails. A successful enumeration replaces
the plan's evidence list and the error reports every current exact prefix path.
If execution returns earlier or stable enumeration itself fails, the error
labels the list only as last-known. This scope is carried into the public
uninstall error audit: a later error may assert each path only when the final
list was stably enumerated, otherwise it reports one last-known record and
states that current exact paths are unavailable. An independently privileged
concurrent writer can create arbitrarily many names and cannot be bounded by
this process; an observed count above eight is reported in full and fails
closed, and seven or more existing names block every later active-link move. No
evidence is restored or deleted by pathname.

Fresh service-unit, install-config, and ownership-manifest files prefer a Linux
`O_TMPFILE` object under the held parent. Filesystems without that primitive,
and Darwin, use a portable same-directory fallback: a cryptographically random
name is created with `O_EXCL` and mode `0600`, retained by FD, changed to the
requested final mode, and renamed with no-replace semantics only after its
pathname, held identity, bytes, hash, link count, destination absence, and
parent generation have been revalidated. The final pathname and held FD are
checked again after publication. A concurrent replacement is never published
or deleted; the conflicting objects are retained with an exact audit path.

After the link and parent sync, publication refreshes only its own final-parent
generation before invoking the post-link hook. It then performs an
unexceptioned parent identity/generation revalidation before rechecking the held
FD, final pathname, bytes, hash, and link count. Consequently a hook cannot hide
a final-name away/back cycle or a sibling create/remove cycle inside the
publisher's allowed generation refresh. Fresh-file inputs also require one
clean basename and an exact clean display path under the held parent; declared
artifact paths reject non-clean raw path and default-path inputs before
canonicalization. Install and uninstall validate the active init system's raw
service-directory inputs before manifest path construction. When no explicit
config path is supplied, they also validate the raw default config directory
before `filepath.Join`, so path construction cannot silently normalize these
inputs.

Before-publication failures remove a portable named stage only while its exact
held identity, one-link ownership, parent binding, and generation remain
provable. Otherwise the stage is retained for manual inspection. Failure after
publication reports that the final object was published and explicitly forbids
automatic unlink or rollback. The general config replacement API and binary
replacement path remain unchanged from their pre-change behavior and are
outside this fix.

Local regression coverage includes:

- missing wants-directory rejection without auto-creation;
- fresh and marked link swaps with successful and failing post-link hooks;
- wants-directory and persistent higher-ancestor replacement;
- deterministic replacement inside the second descriptor walk;
- transient higher-ancestor replacement followed by reattachment of the
  original inode, plus reattachment of the old wants subtree;
- replacement of `systemRoot` after opening its component and replacement of a
  canonical root alias;
- object-bound publication with a hook-inserted foreign final or foreign named
  object, forced `O_TMPFILE` fallback, exclusive-stage replacement retention,
  unsafe name/display-path rejection, simultaneous post-link hook and
  content-mutation rejection, failure auditing, and an in-place install retry
  with no temporary-name accumulation;
- install and uninstall dry runs rejecting non-clean raw systemd, OpenWrt, and
  default config directory inputs before any normalized path is used;
- declared and ordinary managed-parent publication tests that reject a
  post-link final-name away/back cycle and sibling create/remove cycle while
  retaining the published final and foreign evidence;
- ordinary managed-directory parent-entry away/back rejection and successful
  publication with both generation-baseline representations;
- check-to-unlink and quarantine-name swaps with both owned and foreign links
  preserved;
- normal evidence growth from six to seven, a six-name post-final replacement
  consuming the ambiguity reserve at eight, seven-name pre-rename rejection,
  repeated-cycle bounding at seven, complete reporting above eight, and
  last-known labeling when post-final stable enumeration fails;
- the generic concurrent `mkdirat` `EEXIST` path remaining non-owned and now
  failing closed on the unowned generation change;
- one-step uninstall of a validated enable link, plus rejection of same-target
  inode replacement, changed-target replacement, and a foreign link present at
  preflight.

Validation completed locally without SSH, root, real systemd, BPF, or network
namespace operations:

- `make test-unit`
- `make test-unit-race`
- `make test-lint`
- Linux `amd64` and `arm64` compile-only install tests using
  `go test -exec /usr/bin/true`
- Linux `amd64` and `arm64` `go vet ./internal/install`
- Linux `amd64` and `arm64` `go build -trimpath ./cmd/wg-mix-ebpf`
- Darwin `arm64` production build and install-test compilation
