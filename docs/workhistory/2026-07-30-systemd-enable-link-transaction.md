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
canonical root. At each return and commit boundary the code
revalidates every held FD and every edge. Commit performs a second complete
walk and compares every component with the original chain before and after
validating the exact symlink inode, owner, and target. This rejects persistent
higher-ancestor replacement, `systemRoot` replacement after it was opened, and
a tree replacement performed inside the second walk.

Failure after enablement is non-destructive. The transaction does not rename,
unlink, restore, or remove any link or directory. Its error reports the original
declared path, held symlink identity, current descriptor-relative status, and
manual follow-up. The manifest records path and target but not a durable symlink
inode, so automatic uninstall cleanup of a present enable link is blocked.
Operators must inspect and manually remove or retain that exact link before
retrying validated uninstall.

The adjacent install paths were also audited for mutable-name cleanup. Failed
temporary service-unit, binary, config, and ownership-manifest publications now
retain their unique temporary names with an exact-path error instead of
unlinking by name. Fresh config creation uses a held directory descriptor and a
no-replace rename, so a concurrently appearing config is preserved and causes a
fail-closed error. Each writer checks for an earlier retained temporary prefix
before creating another file, so repeated retries stop for manual resolution
instead of accumulating additional temporaries. Successful commits clear the
temporary state after rename and leave no temporary name.

Local regression coverage includes:

- missing wants-directory rejection without auto-creation;
- fresh and marked link swaps with successful and failing post-link hooks;
- wants-directory and persistent higher-ancestor replacement;
- deterministic replacement inside the second descriptor walk;
- replacement of `systemRoot` after opening its component and replacement of a
  canonical root alias;
- check-to-unlink and quarantine-name swaps with both owned and foreign links
  preserved;
- the generic concurrent `mkdirat` `EEXIST` path remaining non-owned;
- automatic uninstall refusal when no durable enable-link inode is recorded,
  followed by successful uninstall after manual link resolution.

Validation completed locally without SSH, root, real systemd, BPF, or network
namespace operations:

- `make test-unit`
- `make test-unit-race`
- `make test-lint`
- Linux `amd64` and `arm64` compile-only install tests using
  `go test -exec /usr/bin/true`
- Linux `amd64` and `arm64` `go vet ./internal/install`
- Linux `amd64` and `arm64` `go build -trimpath ./cmd/wg-mix-ebpf`
