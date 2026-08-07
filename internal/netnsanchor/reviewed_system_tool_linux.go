//go:build linux

package netnsanchor

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	reviewedSystemRoot          = "/"
	reviewedSystemUID    uint32 = 0
	reviewedSystemGID    uint32 = 0
	maximumSymlinkHops          = 40
	maximumResolvedParts        = 1024
)

var reviewedSystemToolPaths = []string{
	"/usr/bin/bash",
	"/usr/bin/env",
	"/usr/bin/realpath",
	"/usr/bin/sha256sum",
	"/usr/bin/stat",
	"/usr/bin/unshare",
}

var reviewedSystemToolSet = func() map[string]struct{} {
	result := make(map[string]struct{}, len(reviewedSystemToolPaths))
	for _, path := range reviewedSystemToolPaths {
		result[path] = struct{}{}
	}
	return result
}()

type reviewedPathPolicy struct {
	filesystemRoot string
	expectedUID    uint32
	expectedGID    uint32
	afterResolve   func() error
}

type reviewedMetadata struct {
	device uint64
	inode  uint64
	mode   uint32
	uid    uint32
	gid    uint32
	nlink  uint64
}

type reviewedChainEntry struct {
	path       string
	kind       string
	linkTarget string
	metadata   reviewedMetadata
}

type reviewedResolution struct {
	targetFD      int
	target        reviewedMetadata
	canonicalPath string
	chain         []reviewedChainEntry
	heldFDs       []int
	rootFD        int
}

type reviewedDirectory struct {
	fd   int
	name string
}

type reviewedExecFunc func(string, []string, []string) error

func productionReviewedPathPolicy() reviewedPathPolicy {
	return reviewedPathPolicy{
		filesystemRoot: reviewedSystemRoot,
		expectedUID:    reviewedSystemUID,
		expectedGID:    reviewedSystemGID,
	}
}

func runReviewSystemToolsCommand(arguments []string) error {
	if len(arguments) != 0 {
		return errors.New("review-system-tools does not accept arguments")
	}
	policy := productionReviewedPathPolicy()
	for _, path := range reviewedSystemToolPaths {
		resolved, err := openReviewedSystemTool(path, policy)
		if err != nil {
			return fmt.Errorf("review fixed system tool %s: %w", path, err)
		}
		if err := resolved.close(); err != nil {
			return fmt.Errorf("close reviewed system tool %s: %w", path, err)
		}
	}
	return nil
}

func runReviewedExecCommand(arguments []string) error {
	if len(arguments) < 2 || arguments[1] != "--" {
		return errors.New(
			"reviewed-exec requires one fixed logical path followed by --",
		)
	}
	return execReviewedSystemTool(
		arguments[0],
		arguments[2:],
		[]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"},
		productionReviewedPathPolicy(),
		unix.Exec,
	)
}

func execReviewedSystemTool(
	logicalPath string,
	arguments []string,
	environment []string,
	policy reviewedPathPolicy,
	exec reviewedExecFunc,
) error {
	if exec == nil {
		return errors.New("reviewed executable callback is nil")
	}
	resolved, err := openReviewedSystemTool(logicalPath, policy)
	if err != nil {
		return err
	}
	defer resolved.close()
	executable := "/proc/self/fd/" + strconv.Itoa(resolved.targetFD)
	argv := make([]string, 1, len(arguments)+1)
	argv[0] = logicalPath
	argv = append(argv, arguments...)
	if err := exec(executable, argv, environment); err != nil {
		return fmt.Errorf("execute held reviewed system tool %s: %w", logicalPath, err)
	}
	return nil
}

func openReviewedSystemTool(
	logicalPath string,
	policy reviewedPathPolicy,
) (*reviewedResolution, error) {
	if _, allowed := reviewedSystemToolSet[logicalPath]; !allowed {
		return nil, fmt.Errorf("system tool logical path is not allowlisted: %q", logicalPath)
	}
	if err := validateReviewedLogicalPath(logicalPath); err != nil {
		return nil, err
	}
	if policy.filesystemRoot == "" || !filepath.IsAbs(policy.filesystemRoot) {
		return nil, errors.New("reviewed filesystem root must be absolute")
	}
	first, err := resolveReviewedPath(logicalPath, policy)
	if err != nil {
		return nil, err
	}
	keepFirst := false
	defer func() {
		if !keepFirst {
			_ = first.close()
		}
	}()
	if policy.afterResolve != nil {
		if err := policy.afterResolve(); err != nil {
			return nil, fmt.Errorf("reviewed path race hook: %w", err)
		}
	}
	second, err := resolveReviewedPath(logicalPath, policy)
	if err != nil {
		return nil, fmt.Errorf("re-resolve reviewed system tool: %w", err)
	}
	defer second.close()
	if first.target != second.target ||
		first.canonicalPath != second.canonicalPath ||
		!equalReviewedChains(first.chain, second.chain) {
		return nil, errors.New("reviewed system tool path changed while being sealed")
	}
	openedFD, err := unix.Openat2(
		first.rootFD,
		strings.TrimPrefix(logicalPath, "/"),
		&unix.OpenHow{
			Flags: uint64(unix.O_PATH | unix.O_CLOEXEC),
			Resolve: uint64(
				unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
			),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("open reviewed system tool without magic links: %w", err)
	}
	defer unix.Close(openedFD)
	openedMetadata, err := reviewedMetadataFromFD(openedFD)
	if err != nil {
		return nil, fmt.Errorf("stat final reviewed system tool FD: %w", err)
	}
	if openedMetadata != first.target {
		return nil, errors.New("reviewed system tool final FD identity mismatch")
	}
	keepFirst = true
	return first, nil
}

func validateReviewedLogicalPath(path string) error {
	if !strings.HasPrefix(path, "/") ||
		path == "/" ||
		filepath.Clean(path) != path ||
		strings.Contains(path, "//") ||
		strings.Contains(path, "/./") ||
		strings.Contains(path, "/../") ||
		strings.HasSuffix(path, "/.") ||
		strings.HasSuffix(path, "/..") {
		return fmt.Errorf("reviewed logical path is not canonical-looking: %q", path)
	}
	return nil
}

func resolveReviewedPath(
	logicalPath string,
	policy reviewedPathPolicy,
) (*reviewedResolution, error) {
	rootFD, err := unix.Open(
		policy.filesystemRoot,
		unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open reviewed filesystem root: %w", err)
	}
	resolution := &reviewedResolution{
		targetFD: -1,
		rootFD:   rootFD,
		heldFDs:  []int{rootFD},
	}
	keep := false
	defer func() {
		if !keep {
			_ = resolution.close()
		}
	}()
	rootMetadata, err := reviewedMetadataFromFD(rootFD)
	if err != nil {
		return nil, fmt.Errorf("stat reviewed filesystem root: %w", err)
	}
	if err := validateReviewedDirectory("/", rootMetadata, policy); err != nil {
		return nil, err
	}
	resolution.chain = append(resolution.chain, reviewedChainEntry{
		path:     "/",
		kind:     "directory",
		metadata: rootMetadata,
	})

	parts := strings.Split(strings.TrimPrefix(logicalPath, "/"), "/")
	directories := []reviewedDirectory{{fd: rootFD}}
	canonicalParts := make([]string, 0, len(parts))
	symlinkHops := 0
	resolvedParts := 0
	for len(parts) > 0 {
		resolvedParts++
		if resolvedParts > maximumResolvedParts {
			return nil, errors.New("reviewed path expands to too many components")
		}
		part := parts[0]
		parts = parts[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			if len(directories) == 1 {
				return nil, errors.New("reviewed symlink target escapes filesystem root")
			}
			directories = directories[:len(directories)-1]
			canonicalParts = canonicalParts[:len(canonicalParts)-1]
			continue
		}

		parentFD := directories[len(directories)-1].fd
		componentFD, err := unix.Openat(
			parentFD,
			part,
			unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if err != nil {
			return nil, fmt.Errorf("open reviewed path component %q: %w", part, err)
		}
		resolution.heldFDs = append(resolution.heldFDs, componentFD)
		metadata, err := reviewedMetadataFromFD(componentFD)
		if err != nil {
			return nil, fmt.Errorf("stat reviewed path component %q: %w", part, err)
		}
		componentPath := "/" + strings.Join(
			append(append([]string{}, canonicalParts...), part),
			"/",
		)
		switch metadata.mode & unix.S_IFMT {
		case unix.S_IFLNK:
			symlinkHops++
			if symlinkHops > maximumSymlinkHops {
				return nil, errors.New("reviewed path contains too many symlink hops")
			}
			if err := validateReviewedSymlink(componentPath, metadata, policy); err != nil {
				return nil, err
			}
			target, err := readStableReviewedSymlink(
				parentFD,
				part,
				componentFD,
				metadata,
			)
			if err != nil {
				return nil, err
			}
			resolution.chain = append(resolution.chain, reviewedChainEntry{
				path:       componentPath,
				kind:       "symlink",
				linkTarget: target,
				metadata:   metadata,
			})
			targetParts := strings.Split(target, "/")
			if strings.HasPrefix(target, "/") {
				directories = directories[:1]
				canonicalParts = canonicalParts[:0]
			}
			parts = append(targetParts, parts...)
		case unix.S_IFDIR:
			if len(parts) == 0 {
				return nil, fmt.Errorf("reviewed system tool resolves to directory: %s", componentPath)
			}
			if err := validateReviewedDirectory(componentPath, metadata, policy); err != nil {
				return nil, err
			}
			canonicalParts = append(canonicalParts, part)
			directories = append(directories, reviewedDirectory{
				fd:   componentFD,
				name: part,
			})
			resolution.chain = append(resolution.chain, reviewedChainEntry{
				path:     "/" + strings.Join(canonicalParts, "/"),
				kind:     "directory",
				metadata: metadata,
			})
		case unix.S_IFREG:
			if len(parts) != 0 {
				return nil, fmt.Errorf("non-directory appears inside reviewed path: %s", componentPath)
			}
			if err := validateReviewedExecutable(componentPath, metadata, policy); err != nil {
				return nil, err
			}
			canonicalParts = append(canonicalParts, part)
			resolution.chain = append(resolution.chain, reviewedChainEntry{
				path:     "/" + strings.Join(canonicalParts, "/"),
				kind:     "executable",
				metadata: metadata,
			})
			resolution.targetFD = componentFD
			resolution.target = metadata
			resolution.canonicalPath = "/" + strings.Join(canonicalParts, "/")
		default:
			return nil, fmt.Errorf("reviewed path component has unsafe type: %s", componentPath)
		}
	}
	if resolution.targetFD < 0 {
		return nil, errors.New("reviewed path did not resolve to an executable")
	}
	keep = true
	return resolution, nil
}

func reviewedMetadataFromFD(descriptor int) (reviewedMetadata, error) {
	var metadata unix.Stat_t
	if err := unix.Fstat(descriptor, &metadata); err != nil {
		return reviewedMetadata{}, err
	}
	return reviewedMetadata{
		device: uint64(metadata.Dev),
		inode:  metadata.Ino,
		mode:   metadata.Mode,
		uid:    metadata.Uid,
		gid:    metadata.Gid,
		nlink:  uint64(metadata.Nlink),
	}, nil
}

func reviewedMetadataAt(parentFD int, name string) (reviewedMetadata, error) {
	var metadata unix.Stat_t
	if err := unix.Fstatat(
		parentFD,
		name,
		&metadata,
		unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return reviewedMetadata{}, err
	}
	return reviewedMetadata{
		device: uint64(metadata.Dev),
		inode:  metadata.Ino,
		mode:   metadata.Mode,
		uid:    metadata.Uid,
		gid:    metadata.Gid,
		nlink:  uint64(metadata.Nlink),
	}, nil
}

func validateReviewedDirectory(
	path string,
	metadata reviewedMetadata,
	policy reviewedPathPolicy,
) error {
	if metadata.mode&unix.S_IFMT != unix.S_IFDIR ||
		metadata.uid != policy.expectedUID ||
		metadata.gid != policy.expectedGID ||
		metadata.mode&0o022 != 0 ||
		metadata.nlink == 0 {
		return fmt.Errorf("reviewed directory metadata is unsafe: %s", path)
	}
	return nil
}

func validateReviewedSymlink(
	path string,
	metadata reviewedMetadata,
	policy reviewedPathPolicy,
) error {
	if metadata.mode&unix.S_IFMT != unix.S_IFLNK ||
		metadata.uid != policy.expectedUID ||
		metadata.gid != policy.expectedGID ||
		metadata.nlink == 0 {
		return fmt.Errorf("reviewed symlink metadata is unsafe: %s", path)
	}
	return nil
}

func validateReviewedExecutable(
	path string,
	metadata reviewedMetadata,
	policy reviewedPathPolicy,
) error {
	if metadata.mode&unix.S_IFMT != unix.S_IFREG ||
		metadata.uid != policy.expectedUID ||
		metadata.gid != policy.expectedGID ||
		metadata.mode&0o022 != 0 ||
		metadata.mode&0o111 == 0 ||
		metadata.mode&(unix.S_ISUID|unix.S_ISGID) != 0 ||
		metadata.nlink == 0 {
		return fmt.Errorf("reviewed executable metadata is unsafe: %s", path)
	}
	return nil
}

func readStableReviewedSymlink(
	parentFD int,
	name string,
	symlinkFD int,
	expected reviewedMetadata,
) (string, error) {
	before, err := reviewedMetadataAt(parentFD, name)
	if err != nil {
		return "", fmt.Errorf("stat reviewed symlink before read: %w", err)
	}
	if before != expected {
		return "", errors.New("reviewed symlink changed before it was read")
	}
	buffer := make([]byte, 256)
	var target string
	for {
		count, err := unix.Readlinkat(parentFD, name, buffer)
		if err != nil {
			return "", fmt.Errorf("read reviewed symlink: %w", err)
		}
		if count < len(buffer) {
			target = string(buffer[:count])
			break
		}
		if len(buffer) >= 65536 {
			return "", errors.New("reviewed symlink target is too long")
		}
		buffer = make([]byte, len(buffer)*2)
	}
	if target == "" {
		return "", errors.New("reviewed symlink target is empty")
	}
	afterPath, err := reviewedMetadataAt(parentFD, name)
	if err != nil {
		return "", fmt.Errorf("stat reviewed symlink after read: %w", err)
	}
	afterFD, err := reviewedMetadataFromFD(symlinkFD)
	if err != nil {
		return "", fmt.Errorf("stat held reviewed symlink: %w", err)
	}
	if afterPath != expected || afterFD != expected {
		return "", errors.New("reviewed symlink changed while it was read")
	}
	return target, nil
}

func equalReviewedChains(left, right []reviewedChainEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (resolution *reviewedResolution) close() error {
	if resolution == nil {
		return nil
	}
	var result error
	for index := len(resolution.heldFDs) - 1; index >= 0; index-- {
		if err := unix.Close(resolution.heldFDs[index]); err != nil {
			result = errors.Join(result, err)
		}
	}
	resolution.heldFDs = nil
	resolution.targetFD = -1
	resolution.rootFD = -1
	return result
}
