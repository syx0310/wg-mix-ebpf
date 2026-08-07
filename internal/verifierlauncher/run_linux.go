//go:build linux

package verifierlauncher

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/sys/unix"
)

type fileMetadata struct {
	device      uint64
	inode       uint64
	mode        uint32
	uid         uint32
	gid         uint32
	links       uint64
	size        int64
	modifiedSec int64
	modifiedNS  int64
	changedSec  int64
	changedNS   int64
}

type linuxSystem struct {
	getEUID    func() int
	open       func(string, int, uint32) (int, error)
	openat     func(int, string, int, uint32) (int, error)
	fstat      func(int, *unix.Stat_t) error
	close      func(int) error
	read       func(int, []byte) (int, error)
	seek       func(int, int64, int) (int64, error)
	fcntlInt   func(uintptr, int, int) (int, error)
	dup3       func(int, int, int) error
	closeRange func(uint, uint, uint) error
	exec       func(string, []string, []string) error
}

func productionLinuxSystem() linuxSystem {
	return linuxSystem{
		getEUID:    unix.Geteuid,
		open:       unix.Open,
		openat:     unix.Openat,
		fstat:      unix.Fstat,
		close:      unix.Close,
		read:       unix.Read,
		seek:       unix.Seek,
		fcntlInt:   unix.FcntlInt,
		dup3:       unix.Dup3,
		closeRange: unix.CloseRange,
		exec:       unix.Exec,
	}
}

func metadataFromStat(value unix.Stat_t) fileMetadata {
	return fileMetadata{
		device:      uint64(value.Dev),
		inode:       uint64(value.Ino),
		mode:        value.Mode,
		uid:         value.Uid,
		gid:         value.Gid,
		links:       uint64(value.Nlink),
		size:        value.Size,
		modifiedSec: value.Mtim.Sec,
		modifiedNS:  value.Mtim.Nsec,
		changedSec:  value.Ctim.Sec,
		changedNS:   value.Ctim.Nsec,
	}
}

func descriptorMetadata(descriptor int, system linuxSystem) (fileMetadata, error) {
	var value unix.Stat_t
	if err := system.fstat(descriptor, &value); err != nil {
		return fileMetadata{}, err
	}
	return metadataFromStat(value), nil
}

func validateDirectory(
	metadata fileMetadata,
	displayPath string,
	currentPolicy policy,
) error {
	if metadata.mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("staging ancestor is not a directory: %s", displayPath)
	}
	fileOwner := owner{uid: metadata.uid, gid: metadata.gid}
	if _, accepted := currentPolicy.directoryOwners[fileOwner]; !accepted {
		return fmt.Errorf(
			"staging ancestor is not owned by an accepted uid:gid: %s",
			displayPath,
		)
	}
	if metadata.links < 2 {
		return fmt.Errorf("staging ancestor has an invalid link count: %s", displayPath)
	}
	writable := metadata.mode & 0o022
	stickySystemDirectory := currentPolicy.allowStickyAncestor &&
		fileOwner == (owner{uid: 0, gid: 0}) && metadata.mode&unix.S_ISVTX != 0
	if writable != 0 && !stickySystemDirectory {
		return fmt.Errorf(
			"staging ancestor is group- or other-writable: %s",
			displayPath,
		)
	}
	return nil
}

func validateRunner(metadata fileMetadata, currentPolicy policy) error {
	if metadata.mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("runner is not a regular file")
	}
	if (owner{uid: metadata.uid, gid: metadata.gid}) != currentPolicy.runnerOwner {
		return fmt.Errorf("runner is not owned by the required uid:gid")
	}
	if metadata.links != 1 {
		return fmt.Errorf("runner link count must be exactly one")
	}
	if metadata.size <= 0 {
		return fmt.Errorf("runner must not be empty")
	}
	if metadata.mode&0o022 != 0 {
		return fmt.Errorf("runner must not be group- or other-writable")
	}
	if metadata.mode&(unix.S_ISUID|unix.S_ISGID) != 0 {
		return fmt.Errorf("runner must not have set-user-ID or set-group-ID bits")
	}
	return nil
}

func openAbsoluteDirectory(
	absolutePath string,
	currentPolicy policy,
	system linuxSystem,
) (int, error) {
	flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	descriptor, err := system.open("/", flags, 0)
	if err != nil {
		return -1, fmt.Errorf("open staging root ancestor /: %w", err)
	}
	displayPath := "/"
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = system.close(descriptor)
		}
	}()

	metadata, err := descriptorMetadata(descriptor, system)
	if err != nil {
		return -1, fmt.Errorf("stat staging root ancestor /: %w", err)
	}
	if err := validateDirectory(metadata, displayPath, currentPolicy); err != nil {
		return -1, err
	}

	for _, component := range strings.Split(strings.TrimPrefix(absolutePath, "/"), "/") {
		nextDescriptor, openErr := system.openat(descriptor, component, flags, 0)
		if openErr != nil {
			return -1, fmt.Errorf("open staging ancestor %s: %w", component, openErr)
		}
		if closeErr := system.close(descriptor); closeErr != nil {
			_ = system.close(nextDescriptor)
			return -1, fmt.Errorf("close prior staging ancestor: %w", closeErr)
		}
		descriptor = nextDescriptor
		if displayPath == "/" {
			displayPath += component
		} else {
			displayPath += "/" + component
		}
		metadata, err = descriptorMetadata(descriptor, system)
		if err != nil {
			return -1, fmt.Errorf("stat staging ancestor %s: %w", displayPath, err)
		}
		if err := validateDirectory(metadata, displayPath, currentPolicy); err != nil {
			return -1, err
		}
	}
	closeOnError = false
	return descriptor, nil
}

func duplicateDirectory(descriptor int, system linuxSystem) (int, error) {
	duplicate, err := system.fcntlInt(uintptr(descriptor), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return -1, err
	}
	return duplicate, nil
}

func openRelativeParent(
	stagingDescriptor int,
	parentParts []string,
	stagingRoot string,
	currentPolicy policy,
	system linuxSystem,
) (int, error) {
	descriptor, err := duplicateDirectory(stagingDescriptor, system)
	if err != nil {
		return -1, fmt.Errorf("duplicate staging descriptor: %w", err)
	}
	displayPath := stagingRoot
	flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = system.close(descriptor)
		}
	}()
	for _, component := range parentParts {
		nextDescriptor, openErr := system.openat(descriptor, component, flags, 0)
		if openErr != nil {
			return -1, fmt.Errorf("open runner ancestor %s: %w", component, openErr)
		}
		if closeErr := system.close(descriptor); closeErr != nil {
			_ = system.close(nextDescriptor)
			return -1, fmt.Errorf("close prior runner ancestor: %w", closeErr)
		}
		descriptor = nextDescriptor
		displayPath += "/" + component
		metadata, statErr := descriptorMetadata(descriptor, system)
		if statErr != nil {
			return -1, fmt.Errorf("stat runner ancestor %s: %w", displayPath, statErr)
		}
		if err := validateDirectory(metadata, displayPath, currentPolicy); err != nil {
			return -1, err
		}
	}
	closeOnError = false
	return descriptor, nil
}

func sha256Descriptor(descriptor int, system linuxSystem) (string, error) {
	if _, err := system.seek(descriptor, 0, io.SeekStart); err != nil {
		return "", err
	}
	digest := sha256.New()
	buffer := make([]byte, 1024*1024)
	for {
		count, err := system.read(descriptor, buffer)
		if count > 0 {
			_, _ = digest.Write(buffer[:count])
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return "", err
		}
		if count == 0 {
			break
		}
	}
	if _, err := system.seek(descriptor, 0, io.SeekStart); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", digest.Sum(nil)), nil
}

func openVerifiedRunner(
	arguments Arguments,
	currentPolicy policy,
	system linuxSystem,
) (int, error) {
	parts, err := targetRelativeParts(
		arguments.Runner,
		arguments.StagingRoot,
		"runner",
	)
	if err != nil {
		return -1, err
	}
	stagingDescriptor, err := openAbsoluteDirectory(
		arguments.StagingRoot,
		currentPolicy,
		system,
	)
	if err != nil {
		return -1, err
	}
	defer func() { _ = system.close(stagingDescriptor) }()

	parentDescriptor, err := openRelativeParent(
		stagingDescriptor,
		parts[:len(parts)-1],
		arguments.StagingRoot,
		currentPolicy,
		system,
	)
	if err != nil {
		return -1, err
	}
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	runnerDescriptor, err := system.openat(
		parentDescriptor,
		parts[len(parts)-1],
		flags,
		0,
	)
	closeParentErr := system.close(parentDescriptor)
	if err != nil {
		return -1, fmt.Errorf("open runner: %w", err)
	}
	if closeParentErr != nil {
		_ = system.close(runnerDescriptor)
		return -1, fmt.Errorf("close runner parent: %w", closeParentErr)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = system.close(runnerDescriptor)
		}
	}()

	flagsValue, err := system.fcntlInt(
		uintptr(runnerDescriptor),
		unix.F_GETFD,
		0,
	)
	if err != nil {
		return -1, fmt.Errorf("read runner descriptor flags: %w", err)
	}
	if flagsValue&unix.FD_CLOEXEC == 0 {
		return -1, fmt.Errorf("runner descriptor must initially be close-on-exec")
	}
	before, err := descriptorMetadata(runnerDescriptor, system)
	if err != nil {
		return -1, fmt.Errorf("stat runner descriptor: %w", err)
	}
	if err := validateRunner(before, currentPolicy); err != nil {
		return -1, err
	}
	actualSHA256, err := sha256Descriptor(runnerDescriptor, system)
	if err != nil {
		return -1, fmt.Errorf("hash runner descriptor: %w", err)
	}
	after, err := descriptorMetadata(runnerDescriptor, system)
	if err != nil {
		return -1, fmt.Errorf("restat runner descriptor: %w", err)
	}
	if after != before {
		return -1, fmt.Errorf("runner metadata changed while hashing")
	}
	if actualSHA256 != arguments.RunnerSHA256 {
		return -1, fmt.Errorf("runner SHA-256 mismatch")
	}
	closeOnError = false
	return runnerDescriptor, nil
}

func requireUnusedDescriptor(descriptor int, system linuxSystem) error {
	_, err := system.fcntlInt(uintptr(descriptor), unix.F_GETFD, 0)
	if errors.Is(err, unix.EBADF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect reserved descriptor %d: %w", descriptor, err)
	}
	return fmt.Errorf("reserved descriptor %d is already in use", descriptor)
}

func requireReservedDescriptorsUnused(system linuxSystem) error {
	for _, descriptor := range []int{
		runnerExecFD,
		childBinaryExecFD,
		childObjectExecFD,
	} {
		if err := requireUnusedDescriptor(descriptor, system); err != nil {
			return err
		}
	}
	return nil
}

func duplicateRunnerForExec(sourceDescriptor int, system linuxSystem) error {
	if sourceDescriptor == runnerExecFD || sourceDescriptor == childBinaryExecFD ||
		sourceDescriptor == childObjectExecFD {
		return fmt.Errorf("runner source descriptor conflicts with a reserved descriptor")
	}
	if err := requireReservedDescriptorsUnused(system); err != nil {
		return err
	}
	if err := system.dup3(sourceDescriptor, runnerExecFD, 0); err != nil {
		return fmt.Errorf("duplicate runner to descriptor %d: %w", runnerExecFD, err)
	}
	flagsValue, err := system.fcntlInt(uintptr(runnerExecFD), unix.F_GETFD, 0)
	if err != nil {
		_ = system.close(runnerExecFD)
		return fmt.Errorf("read inherited runner descriptor flags: %w", err)
	}
	if flagsValue&unix.FD_CLOEXEC != 0 {
		_ = system.close(runnerExecFD)
		return fmt.Errorf("inherited runner descriptor is unexpectedly close-on-exec")
	}
	return nil
}

func closeUnapprovedDescriptors(system linuxSystem) error {
	if err := system.closeRange(3, runnerExecFD-1, 0); err != nil {
		return fmt.Errorf("close descriptors below runner descriptor: %w", err)
	}
	if err := system.closeRange(runnerExecFD+1, ^uint(0), 0); err != nil {
		return fmt.Errorf("close descriptors above runner descriptor: %w", err)
	}
	return nil
}

func runWithPolicy(
	argv []string,
	currentPolicy policy,
	system linuxSystem,
	beforeExec func(int) error,
) error {
	arguments, err := parseArguments(argv)
	if err != nil {
		return err
	}
	if err := validateArguments(arguments, currentPolicy); err != nil {
		return err
	}
	if currentPolicy.requireRoot && system.getEUID() != 0 {
		return fmt.Errorf("launcher must run as root")
	}
	if err := requireReservedDescriptorsUnused(system); err != nil {
		return err
	}
	runnerDescriptor, err := openVerifiedRunner(arguments, currentPolicy, system)
	if err != nil {
		return err
	}
	defer func() { _ = system.close(runnerDescriptor) }()
	if beforeExec != nil {
		if err := beforeExec(runnerDescriptor); err != nil {
			return fmt.Errorf("pre-exec hook: %w", err)
		}
	}
	if err := duplicateRunnerForExec(runnerDescriptor, system); err != nil {
		return err
	}
	defer func() { _ = system.close(runnerExecFD) }()
	plan := makeExecPlan(arguments, currentPolicy)
	if err := closeUnapprovedDescriptors(system); err != nil {
		return err
	}
	if err := system.exec(plan.path, plan.argv, plan.env); err != nil {
		return fmt.Errorf("exec fixed isolated Python: %w", err)
	}
	return fmt.Errorf("exec fixed isolated Python returned unexpectedly")
}

// Run enters the production launcher contract. The caller must establish the
// initial trust boundary by approving this root-owned launcher binary and its
// SHA-256 before execution; a process cannot bootstrap that trust by self-hash.
func Run(argv []string) error {
	return runWithPolicy(argv, productionPolicy, productionLinuxSystem(), nil)
}
