# Systemd enable-link transaction

`install --enable` no longer delegates enablement to `systemctl enable`.
The installed unit has one reviewed install target,
`multi-user.target.wants/wg-mix-ebpf.service`, so installation now creates only
that exact relative symlink through held directory descriptors.

Before creating the link, installation reloads and verifies the systemd manager,
publishes the cleanup ownership manifest, and reopens the manifest and config as
held descriptors. The link is then validated by inode, owner, target, and parent
directory identity. A later unit/manifest validation failure removes only the
link created by that transaction through the existing quarantine protocol. If
an exact rollback cannot be completed, the already-published manifest retains
the precise link path and target for recovery.

Uninstall no longer calls broad `systemctl disable`. Its cleanup plan validates
and removes the declared enable link before removing the owned unit. A
pre-existing link with another target is rejected and preserved.

Local validation covered successful enablement, unit and manifest swaps during
the enable window, failure after link creation with rollback and retry, and
foreign-link preservation on install and uninstall.
