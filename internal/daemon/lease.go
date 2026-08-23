package daemon

import "github.com/syx0310/wg-mix-ebpf/internal/lockfile"

const DefaultLifecycleLeasePath = lockfile.DefaultLifecycleLeasePath
const DefaultLifecycleMaintenancePath = lockfile.DefaultLifecycleMaintenancePath

var ErrAlreadyRunning = lockfile.ErrLifecycleLeaseHeld

type leaseOwner = lockfile.LifecycleOwner
type lifecycleLeaseHandle = lockfile.LifecycleLease

func acquireLifecycleLease(
	path string,
	maintenancePath string,
	owner leaseOwner,
) (*lifecycleLeaseHandle, error) {
	return lockfile.AcquireLifecycleAt(path, maintenancePath, owner)
}
