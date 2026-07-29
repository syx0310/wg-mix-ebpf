# Systemd enable-link transaction

`install --enable` no longer delegates enablement to `systemctl enable`.
The installed unit has one reviewed install target,
`multi-user.target.wants/wg-mix-ebpf.service`, so installation now creates only
that exact relative symlink through held directory descriptors.

Before creating the link, installation reloads and verifies the systemd manager,
publishes the cleanup ownership manifest, and reopens the manifest and config as
held descriptors. The wants directory is opened or exclusively created in one
descriptor walk. Only a successful `mkdirat` in that walk marks the directory as
transaction-created; a concurrent creator that wins the absent-to-create window
is reopened but is never eligible for parent rollback. The link is then
validated by inode, owner, target, and parent directory identity.

Immediately before committing the transaction, installation reopens the full
artifact-parent path from its declared trusted root and compares that directory
with the held wants-directory descriptor. It performs this full-root validation
both before and after checking the exact link inode, UID, and target, so moving a
self-consistent held subtree behind a replaced higher ancestor is rejected. For
the real default path, the declared root is `/etc/systemd/system` and the exact
artifact parent is `multi-user.target.wants`.

A later validation failure removes only the link created by that transaction
through the held directory descriptor and existing quarantine protocol. A
foreign replacement is never deleted or overwritten. If an exact rollback
cannot be completed, the already-published manifest retains the precise link
path and target for recovery; a failed no-replace quarantine restore retains the
owned object at the exact quarantine path reported in the error.

Uninstall no longer calls broad `systemctl disable`. Its cleanup plan validates
and removes the declared enable link before removing the owned unit. A
pre-existing link with another target is rejected and preserved.

Local validation covered successful enablement, unit and manifest swaps during
the enable window, fresh and marked ownership with both successful and failing
post-link hooks, wants-directory pathname replacement, failure after link
creation with rollback and retry, a concurrent creator winning the exact
absent-to-`mkdirat` window, higher-ancestor subtree replacement, transaction
quarantine restore conflict, exact quarantine preservation, and foreign-link
preservation on install and uninstall.
