//go:build linux

package netnsanchor

import (
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	stagedSourcePrefix = "/run/wg-mix-ebpf-source-stages"
	stagedLauncherName = "scripts/run-smoke-netns-wg-private-mountns.sh"
	stagedSmokeName    = "scripts/smoke-netns-wg.sh"
	stagedHelperName   = "scripts/source-commit.sh"
	stagedAnchorName   = "bin/wg-mix-ebpf-netns-anchor"
)

var (
	launchNoncePattern = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
	hexSHA256Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	deviceInodePattern = regexp.MustCompile(
		`^[1-9][0-9]*:[1-9][0-9]*$`,
	)
)

var requiredPrivateMountNSChildEnvironment = []string{
	"PATH",
	"LC_ALL",
	"WG_MIX_EBPF_SMOKE_MOUNTNS_CHILD",
	"WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_FD",
	"WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_NONCE",
	"WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_SHA256",
	"WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_FD",
	"WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_ID",
	"WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_PID",
	"WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_DEV",
	"WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_FD",
	"WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_INO",
	"WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_SHA256",
	"WG_MIX_EBPF_SMOKE_MOUNTNS_SOURCE_COMMIT",
	"WG_MIX_EBPF_SMOKE_MOUNTNS_SOURCE_ROOT",
	"WG_MIX_EBPF_SMOKE_MOUNTNS_XOR_SECRET_FD",
}

var optionalPrivateMountNSChildEnvironment = []string{
	"ATTACHMENT_BACKEND",
	"DATAPLANE_MODE",
	"INITIAL_CAPTURE_TIMEOUT",
	"NETNS_ANCHOR_TTL_SECONDS",
	"OUTER_FAMILY",
	"RUN_ID",
	"TCP_CAPTURE_PACKETS",
	"TCP_CHECKS",
	"TCP_DIRECTIONS",
	"TCP_DURATION",
	"TCP_GSO_CHECKS",
	"TCP_INNER_GSO_CHECKS",
	"TCP_MAX_RETRANSMITS",
	"TCP_MIN_BYTES",
	"TCP_MIN_FAIRNESS",
	"TCP_MTUS",
	"TCP_OUTER_GSO_CHECKS",
	"TCP_PORT",
	"TCP_REPETITIONS",
	"TCP_STREAMS",
	"UDP_ZERO_CHECKSUM_CHECKS",
	"UNDERLAY_MTU",
	"WG_MTU",
	"XOR_DISPATCH_FAILURE_CHECKS",
	"XOR_GENERATION_CHECKS",
	"XOR_MAX_BYTES",
	"XOR_SCOPE",
}

var privateMountNSChildEnvironmentSet = func() map[string]struct{} {
	result := make(
		map[string]struct{},
		len(requiredPrivateMountNSChildEnvironment)+
			len(optionalPrivateMountNSChildEnvironment),
	)
	for _, name := range requiredPrivateMountNSChildEnvironment {
		result[name] = struct{}{}
	}
	for _, name := range optionalPrivateMountNSChildEnvironment {
		result[name] = struct{}{}
	}
	return result
}()

type repeatedStringFlag []string

func (values *repeatedStringFlag) String() string {
	return strings.Join(*values, ",")
}

func (values *repeatedStringFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type privateMountNSOperations struct {
	lockThread            func()
	unlockThread          func()
	threadID              func() int
	unshare               func(int) error
	mount                 func(string, string, string, uintptr, string) error
	setNamespace          func(int, int) error
	inspectMountNamespace func() (unix.Stat_t, int, error)
	exec                  reviewedExecFunc
}

type privateMountNSChildContract struct {
	environment  []string
	inheritedFDs []int
	outerFD      int
	outer        unix.Stat_t
}

func runReviewStagedLaunchCommand(arguments []string) error {
	flags := flag.NewFlagSet("review-staged-launch", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	sourceRoot := flags.String("source-root", "", "fixed staged source root")
	launcherFD := flags.Int("launcher-fd", -1, "held launcher source FD")
	smokeFD := flags.Int("smoke-fd", -1, "held smoke source FD")
	helperFD := flags.Int("source-helper-fd", -1, "held source identity helper FD")
	anchorFD := flags.Int("anchor-fd", -1, "held anchor image FD")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("review-staged-launch does not accept positional arguments")
	}
	return reviewStagedLaunch(
		*sourceRoot,
		map[string]int{
			stagedLauncherName: *launcherFD,
			stagedSmokeName:    *smokeFD,
			stagedHelperName:   *helperFD,
			stagedAnchorName:   *anchorFD,
		},
		productionReviewedPathPolicy(),
		true,
	)
}

func reviewStagedLaunch(
	sourceRoot string,
	descriptors map[string]int,
	policy reviewedPathPolicy,
	requireCurrentAnchor bool,
) error {
	if err := validateStagedSourceRoot(sourceRoot); err != nil {
		return err
	}
	if len(descriptors) != 4 {
		return errors.New("staged launch descriptor set is incomplete")
	}
	seenFDs := make(map[int]string, len(descriptors))
	var anchorMetadata reviewedMetadata
	for _, name := range []string{
		stagedLauncherName,
		stagedSmokeName,
		stagedHelperName,
		stagedAnchorName,
	} {
		descriptor, present := descriptors[name]
		if !present || descriptor < 3 {
			return fmt.Errorf("staged launch descriptor is invalid: %s", name)
		}
		if previous, duplicate := seenFDs[descriptor]; duplicate {
			return fmt.Errorf(
				"staged launch descriptors alias: %s and %s",
				previous,
				name,
			)
		}
		seenFDs[descriptor] = name
		path := sourceRoot + "/" + name
		resolved, err := openStrictStagedExecutable(path, descriptor, policy)
		if err != nil {
			return fmt.Errorf("review staged executable %s: %w", name, err)
		}
		if name == stagedAnchorName {
			anchorMetadata = resolved.target
		}
		if err := resolved.close(); err != nil {
			return fmt.Errorf("close reviewed staged executable %s: %w", name, err)
		}
	}
	if requireCurrentAnchor {
		currentFD, err := unix.Open("/proc/self/exe", unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open current staged anchor image: %w", err)
		}
		defer unix.Close(currentFD)
		currentMetadata, err := reviewedMetadataFromFD(currentFD)
		if err != nil {
			return fmt.Errorf("stat current staged anchor image: %w", err)
		}
		if currentMetadata != anchorMetadata {
			return errors.New("staged anchor path, held FD, and current image differ")
		}
	}
	return nil
}

func runLaunchPrivateMountNSCommand(arguments []string) error {
	flags := flag.NewFlagSet("launch-private-mountns", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	sourceRoot := flags.String("source-root", "", "fixed staged source root")
	smokeFD := flags.Int("smoke-fd", -1, "held staged smoke script FD")
	var childEnvironment repeatedStringFlag
	flags.Var(&childEnvironment, "child-env", "allowlisted child environment entry")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("launch-private-mountns does not accept positional arguments")
	}
	return launchPrivateMountNS(
		*sourceRoot,
		*smokeFD,
		childEnvironment,
		productionReviewedPathPolicy(),
		privateMountNSOperations{
			lockThread:            runtime.LockOSThread,
			unlockThread:          runtime.UnlockOSThread,
			threadID:              unix.Gettid,
			unshare:               unix.Unshare,
			mount:                 unix.Mount,
			setNamespace:          unix.Setns,
			inspectMountNamespace: inspectCurrentThreadMountNamespace,
			exec:                  unix.Exec,
		},
	)
}

func launchPrivateMountNS(
	sourceRoot string,
	smokeFD int,
	childEnvironment []string,
	policy reviewedPathPolicy,
	operations privateMountNSOperations,
) error {
	if operations.lockThread == nil ||
		operations.unlockThread == nil ||
		operations.threadID == nil ||
		operations.unshare == nil ||
		operations.mount == nil ||
		operations.setNamespace == nil ||
		operations.inspectMountNamespace == nil ||
		operations.exec == nil {
		return errors.New("private mount namespace operations are incomplete")
	}
	if err := validateStagedSourceRoot(sourceRoot); err != nil {
		return err
	}
	if smokeFD < 3 {
		return errors.New("held staged smoke FD is invalid")
	}
	smokePath := sourceRoot + "/" + stagedSmokeName
	stagedSmoke, err := openStrictStagedExecutable(smokePath, smokeFD, policy)
	if err != nil {
		return fmt.Errorf("revalidate staged smoke before mount unshare: %w", err)
	}
	defer stagedSmoke.close()
	bash, err := openReviewedSystemTool("/usr/bin/bash", policy)
	if err != nil {
		return fmt.Errorf("hold reviewed Bash before mount unshare: %w", err)
	}
	defer bash.close()
	child, err := validatePrivateMountNSChildEnvironment(
		childEnvironment,
		sourceRoot,
		smokeFD,
		stagedSmoke.target,
	)
	if err != nil {
		return err
	}
	for _, descriptor := range child.inheritedFDs {
		fdFlags, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFD, 0)
		if err != nil {
			return fmt.Errorf("inspect child FD %d inheritance: %w", descriptor, err)
		}
		if fdFlags&unix.FD_CLOEXEC != 0 {
			if _, err := unix.FcntlInt(
				uintptr(descriptor),
				unix.F_SETFD,
				fdFlags&^unix.FD_CLOEXEC,
			); err != nil {
				return fmt.Errorf("preserve child FD %d across Bash exec: %w", descriptor, err)
			}
		}
	}
	operations.lockThread()
	lockedTID := operations.threadID()
	if lockedTID <= 0 {
		operations.unlockThread()
		return errors.New("locked private mount namespace thread has an invalid TID")
	}
	lockedMetadata, lockedType, err := operations.inspectMountNamespace()
	if err != nil {
		operations.unlockThread()
		return fmt.Errorf("inspect locked mount namespace before unshare: %w", err)
	}
	if err := validateOuterMountNamespacePair(
		child.outer,
		unix.CLONE_NEWNS,
		lockedMetadata,
		lockedType,
	); err != nil {
		operations.unlockThread()
		return err
	}
	if err := operations.unshare(unix.CLONE_NEWNS); err != nil {
		operations.unlockThread()
		return fmt.Errorf("create private mount namespace: %w", err)
	}
	if operations.threadID() != lockedTID {
		return errors.New("private mount namespace thread changed TID after unshare")
	}
	if err := operations.mount(
		"",
		"/",
		"",
		unix.MS_REC|unix.MS_PRIVATE,
		"",
	); err != nil {
		return restoreOuterMountNamespaceAfterFailure(
			child.outerFD,
			child.outer,
			lockedTID,
			operations,
			fmt.Errorf("make new mount namespace recursively private: %w", err),
		)
	}
	if operations.threadID() != lockedTID {
		return errors.New("private mount namespace thread changed TID before exec")
	}
	// Execute in this helper process: no fork/wait layer may change the smoke
	// script's PPID contract with the outer launcher.
	execErr := operations.exec(
		"/proc/self/fd/"+strconv.Itoa(bash.targetFD),
		[]string{
			"/usr/bin/bash",
			"/proc/self/fd/" + strconv.Itoa(smokeFD),
			"--private-mountns-child-v1",
		},
		child.environment,
	)
	if execErr == nil {
		execErr = errors.New("held Bash exec returned without replacing the helper")
	} else {
		execErr = fmt.Errorf("execute held Bash in private mount namespace: %w", execErr)
	}
	return restoreOuterMountNamespaceAfterFailure(
		child.outerFD,
		child.outer,
		lockedTID,
		operations,
		execErr,
	)
}

func restoreOuterMountNamespaceAfterFailure(
	outerFD int,
	outerMetadata unix.Stat_t,
	lockedTID int,
	operations privateMountNSOperations,
	cause error,
) error {
	if cause == nil {
		cause = errors.New("private mount namespace launch failed")
	}
	if operations.threadID() != lockedTID {
		return errors.Join(
			cause,
			errors.New("cannot restore outer mount namespace after locked TID changed"),
		)
	}
	if err := operations.setNamespace(outerFD, unix.CLONE_NEWNS); err != nil {
		return errors.Join(
			cause,
			fmt.Errorf("restore sealed outer mount namespace: %w", err),
		)
	}
	restoredMetadata, restoredType, err := operations.inspectMountNamespace()
	if err != nil {
		return errors.Join(
			cause,
			fmt.Errorf("inspect restored outer mount namespace: %w", err),
		)
	}
	if err := validateOuterMountNamespacePair(
		outerMetadata,
		unix.CLONE_NEWNS,
		restoredMetadata,
		restoredType,
	); err != nil {
		return errors.Join(cause, fmt.Errorf("verify restored outer mount namespace: %w", err))
	}
	operations.unlockThread()
	return cause
}

func validatePrivateMountNSChildEnvironment(
	entries []string,
	sourceRoot string,
	smokeFD int,
	smokeMetadata reviewedMetadata,
) (privateMountNSChildContract, error) {
	if len(entries) < len(requiredPrivateMountNSChildEnvironment) || len(entries) > 64 {
		return privateMountNSChildContract{}, errors.New("private mount namespace child environment size is invalid")
	}
	values := make(map[string]string, len(entries))
	totalBytes := 0
	for _, entry := range entries {
		totalBytes += len(entry) + 1
		if len(entry) > 4096 || totalBytes > 65536 {
			return privateMountNSChildContract{}, errors.New("private mount namespace child environment is too large")
		}
		name, value, found := strings.Cut(entry, "=")
		if !found || name == "" {
			return privateMountNSChildContract{}, errors.New("private mount namespace child environment entry is malformed")
		}
		if _, allowed := privateMountNSChildEnvironmentSet[name]; !allowed {
			return privateMountNSChildContract{}, fmt.Errorf("private mount namespace child environment name is forbidden: %s", name)
		}
		if _, duplicate := values[name]; duplicate {
			return privateMountNSChildContract{}, fmt.Errorf("private mount namespace child environment name is duplicated: %s", name)
		}
		values[name] = value
	}
	for _, name := range requiredPrivateMountNSChildEnvironment {
		if _, present := values[name]; !present {
			return privateMountNSChildContract{}, fmt.Errorf("private mount namespace child environment is missing: %s", name)
		}
	}
	if values["PATH"] != "/usr/sbin:/usr/bin:/sbin:/bin" ||
		values["LC_ALL"] != "C" ||
		values["WG_MIX_EBPF_SMOKE_MOUNTNS_CHILD"] != "1" ||
		values["WG_MIX_EBPF_SMOKE_MOUNTNS_SOURCE_ROOT"] != sourceRoot ||
		values["WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_FD"] != strconv.Itoa(smokeFD) ||
		values["WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_DEV"] != strconv.FormatUint(smokeMetadata.device, 10) ||
		values["WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_INO"] != strconv.FormatUint(smokeMetadata.inode, 10) ||
		values["WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_PID"] != strconv.Itoa(os.Getppid()) {
		return privateMountNSChildContract{}, errors.New("private mount namespace child environment identity is inconsistent")
	}
	if !launchNoncePattern.MatchString(values["WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_NONCE"]) ||
		!hexSHA256Pattern.MatchString(values["WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_SHA256"]) ||
		!hexSHA256Pattern.MatchString(values["WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_SHA256"]) ||
		!deviceInodePattern.MatchString(values["WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_ID"]) {
		return privateMountNSChildContract{}, errors.New("private mount namespace child environment seal is malformed")
	}
	commit := values["WG_MIX_EBPF_SMOKE_MOUNTNS_SOURCE_COMMIT"]
	if len(commit) != 40 || !isLowerHex(commit) || commit != normalizedSourceCommit() {
		return privateMountNSChildContract{}, errors.New("private mount namespace child source commit is inconsistent")
	}
	fdNames := []string{
		"WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_FD",
		"WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_FD",
		"WG_MIX_EBPF_SMOKE_MOUNTNS_XOR_SECRET_FD",
	}
	inheritedFDs := []int{smokeFD}
	seenFDs := map[int]string{smokeFD: "WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_FD"}
	parsedFDs := make(map[string]int, len(fdNames))
	for _, name := range fdNames {
		value, err := strconv.Atoi(values[name])
		if err != nil || value < 3 {
			return privateMountNSChildContract{}, fmt.Errorf("private mount namespace child FD is invalid: %s", name)
		}
		if previous, duplicate := seenFDs[value]; duplicate {
			return privateMountNSChildContract{}, fmt.Errorf(
				"private mount namespace child FDs alias: %s and %s",
				previous,
				name,
			)
		}
		if _, err := unix.FcntlInt(uintptr(value), unix.F_GETFD, 0); err != nil {
			return privateMountNSChildContract{}, fmt.Errorf("inspect inherited child FD %s: %w", name, err)
		}
		seenFDs[value] = name
		parsedFDs[name] = value
		inheritedFDs = append(inheritedFDs, value)
	}
	outerFD := parsedFDs["WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_FD"]
	var outerMetadata unix.Stat_t
	if err := unix.Fstat(outerFD, &outerMetadata); err != nil {
		return privateMountNSChildContract{}, fmt.Errorf("stat outer mount namespace FD: %w", err)
	}
	namespaceType, err := unix.IoctlRetInt(outerFD, unix.NS_GET_NSTYPE)
	if err != nil {
		return privateMountNSChildContract{}, fmt.Errorf("query outer mount namespace FD type: %w", err)
	}
	if namespaceType != unix.CLONE_NEWNS {
		return privateMountNSChildContract{}, fmt.Errorf(
			"outer namespace descriptor is type %#x, expected mount namespace %#x",
			namespaceType,
			unix.CLONE_NEWNS,
		)
	}
	observedOuterIdentity := fmt.Sprintf("%d:%d", outerMetadata.Dev, outerMetadata.Ino)
	if values["WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_ID"] != observedOuterIdentity {
		return privateMountNSChildContract{}, errors.New("outer mount namespace FD identity differs from launch seal")
	}
	currentMountNSFD, err := unix.Open(
		"/proc/thread-self/ns/mnt",
		unix.O_RDONLY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return privateMountNSChildContract{}, fmt.Errorf("open current mount namespace before unshare: %w", err)
	}
	defer unix.Close(currentMountNSFD)
	var currentMountNSMetadata unix.Stat_t
	if err := unix.Fstat(currentMountNSFD, &currentMountNSMetadata); err != nil {
		return privateMountNSChildContract{}, fmt.Errorf("stat current mount namespace before unshare: %w", err)
	}
	currentNamespaceType, err := unix.IoctlRetInt(
		currentMountNSFD,
		unix.NS_GET_NSTYPE,
	)
	if err != nil {
		return privateMountNSChildContract{}, fmt.Errorf("query current mount namespace type before unshare: %w", err)
	}
	if err := validateOuterMountNamespacePair(
		outerMetadata,
		namespaceType,
		currentMountNSMetadata,
		currentNamespaceType,
	); err != nil {
		return privateMountNSChildContract{}, err
	}
	smokeDigest, err := sha256RegularFD(smokeFD, 16*1024*1024)
	if err != nil {
		return privateMountNSChildContract{}, fmt.Errorf("hash held staged smoke FD: %w", err)
	}
	if values["WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_SHA256"] != smokeDigest {
		return privateMountNSChildContract{}, errors.New("held staged smoke hash differs from launch seal")
	}
	launchRecord := expectedPrivateMountNSLaunchRecord(values)
	if err := validateAndRebindLaunchRecordFD(
		parsedFDs["WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_FD"],
		launchRecord,
		values["WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_SHA256"],
	); err != nil {
		return privateMountNSChildContract{}, err
	}
	return privateMountNSChildContract{
		environment:  append([]string(nil), entries...),
		inheritedFDs: inheritedFDs,
		outerFD:      outerFD,
		outer:        outerMetadata,
	}, nil
}

func validateOuterMountNamespacePair(
	outer unix.Stat_t,
	outerType int,
	current unix.Stat_t,
	currentType int,
) error {
	if outerType != unix.CLONE_NEWNS ||
		currentType != unix.CLONE_NEWNS ||
		outer.Dev == 0 ||
		outer.Ino == 0 ||
		current.Dev != outer.Dev ||
		current.Ino != outer.Ino {
		return errors.New("current and sealed outer mount namespace identities differ before unshare")
	}
	return nil
}

func inspectCurrentThreadMountNamespace() (unix.Stat_t, int, error) {
	descriptor, err := unix.Open(
		"/proc/thread-self/ns/mnt",
		unix.O_RDONLY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return unix.Stat_t{}, 0, err
	}
	defer unix.Close(descriptor)
	var metadata unix.Stat_t
	if err := unix.Fstat(descriptor, &metadata); err != nil {
		return unix.Stat_t{}, 0, err
	}
	namespaceType, err := unix.IoctlRetInt(descriptor, unix.NS_GET_NSTYPE)
	if err != nil {
		return unix.Stat_t{}, 0, err
	}
	return metadata, namespaceType, nil
}

func expectedPrivateMountNSLaunchRecord(values map[string]string) string {
	return strings.Join([]string{
		"format=wg-mix-ebpf-smoke-mountns-launch-v1",
		"nonce=" + values["WG_MIX_EBPF_SMOKE_MOUNTNS_LAUNCH_NONCE"],
		"outer_pid=" + values["WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_PID"],
		"outer_id=" + values["WG_MIX_EBPF_SMOKE_MOUNTNS_OUTER_ID"],
		"script_fd=" + values["WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_FD"],
		"script_dev=" + values["WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_DEV"],
		"script_ino=" + values["WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_INO"],
		"script_sha256=" + values["WG_MIX_EBPF_SMOKE_MOUNTNS_SCRIPT_SHA256"],
		"source_commit=" + values["WG_MIX_EBPF_SMOKE_MOUNTNS_SOURCE_COMMIT"],
		"source_root=" + values["WG_MIX_EBPF_SMOKE_MOUNTNS_SOURCE_ROOT"],
		"xor_secret_fd=" + values["WG_MIX_EBPF_SMOKE_MOUNTNS_XOR_SECRET_FD"],
	}, "\n")
}

func validateAndRebindLaunchRecordFD(
	descriptor int,
	expectedRecord string,
	expectedDigest string,
) error {
	if descriptor < 3 || expectedRecord == "" ||
		!hexSHA256Pattern.MatchString(expectedDigest) {
		return errors.New("launch record FD contract is invalid")
	}
	observed, err := readBoundedFD(descriptor, 64*1024)
	if err != nil {
		return fmt.Errorf("read launch record FD before unshare: %w", err)
	}
	expectedBytes := []byte(expectedRecord + "\n")
	digest := sha256.Sum256([]byte(expectedRecord))
	if string(observed) != string(expectedBytes) ||
		fmt.Sprintf("%x", digest[:]) != expectedDigest {
		return errors.New("launch record FD content differs from its sealed contract")
	}
	sealedFD, err := unix.MemfdCreate(
		"wg-mix-ebpf-launch-record",
		unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING,
	)
	if err != nil {
		return fmt.Errorf("create sealed launch record FD: %w", err)
	}
	defer unix.Close(sealedFD)
	for written := 0; written < len(expectedBytes); {
		count, writeErr := unix.Write(sealedFD, expectedBytes[written:])
		if writeErr != nil {
			return fmt.Errorf("write sealed launch record FD: %w", writeErr)
		}
		if count == 0 {
			return errors.New("write sealed launch record FD made no progress")
		}
		written += count
	}
	if _, err := unix.Seek(sealedFD, 0, 0); err != nil {
		return fmt.Errorf("rewind sealed launch record FD: %w", err)
	}
	if _, err := unix.FcntlInt(
		uintptr(sealedFD),
		unix.F_ADD_SEALS,
		unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE,
	); err != nil {
		return fmt.Errorf("seal launch record FD: %w", err)
	}
	if err := unix.Dup3(sealedFD, descriptor, 0); err != nil {
		return fmt.Errorf("rebind launch record to its inherited FD number: %w", err)
	}
	return nil
}

func readBoundedFD(descriptor int, maximumBytes int) ([]byte, error) {
	if descriptor < 0 || maximumBytes <= 0 {
		return nil, errors.New("bounded FD read contract is invalid")
	}
	result := make([]byte, 0, 4096)
	buffer := make([]byte, 4096)
	deadline := time.Now().Add(ioTimeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, errors.New("bounded FD input did not reach EOF before its deadline")
		}
		pollTimeout := int((remaining + time.Millisecond - 1) / time.Millisecond)
		ready, err := unix.Poll(
			[]unix.PollFd{{
				Fd:     int32(descriptor),
				Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR,
			}},
			pollTimeout,
		)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, err
		}
		if ready == 0 {
			return nil, errors.New("bounded FD input did not reach EOF before its deadline")
		}
		count, err := unix.Read(descriptor, buffer)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, err
		}
		if count == 0 {
			return result, nil
		}
		if len(result)+count > maximumBytes {
			return nil, errors.New("bounded FD input exceeds its maximum size")
		}
		result = append(result, buffer[:count]...)
	}
}

func sha256RegularFD(descriptor int, maximumBytes int64) (string, error) {
	if descriptor < 0 || maximumBytes <= 0 {
		return "", errors.New("held hash contract is invalid")
	}
	var metadata unix.Stat_t
	if err := unix.Fstat(descriptor, &metadata); err != nil {
		return "", err
	}
	if metadata.Mode&unix.S_IFMT != unix.S_IFREG ||
		metadata.Size < 0 ||
		metadata.Size > maximumBytes {
		return "", errors.New("held hash input is not a bounded regular file")
	}
	hash := sha256.New()
	buffer := make([]byte, 64*1024)
	var offset int64
	for offset < metadata.Size {
		want := int64(len(buffer))
		if remaining := metadata.Size - offset; remaining < want {
			want = remaining
		}
		count, err := unix.Pread(descriptor, buffer[:int(want)], offset)
		if err != nil {
			return "", err
		}
		if count == 0 {
			return "", errors.New("held hash input ended before its sealed size")
		}
		if _, err := hash.Write(buffer[:count]); err != nil {
			return "", err
		}
		offset += int64(count)
	}
	var after unix.Stat_t
	if err := unix.Fstat(descriptor, &after); err != nil {
		return "", err
	}
	beforeMetadata := reviewedMetadata{
		device: uint64(metadata.Dev),
		inode:  metadata.Ino,
		mode:   metadata.Mode,
		uid:    metadata.Uid,
		gid:    metadata.Gid,
		nlink:  uint64(metadata.Nlink),
	}
	afterMetadata := reviewedMetadata{
		device: uint64(after.Dev),
		inode:  after.Ino,
		mode:   after.Mode,
		uid:    after.Uid,
		gid:    after.Gid,
		nlink:  uint64(after.Nlink),
	}
	if beforeMetadata != afterMetadata || metadata.Size != after.Size {
		return "", errors.New("held hash input metadata changed while hashing")
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func validateStagedSourceRoot(sourceRoot string) error {
	prefix := stagedSourcePrefix + "/"
	if !strings.HasPrefix(sourceRoot, prefix) ||
		!strings.HasSuffix(sourceRoot, "/source") ||
		filepath.Clean(sourceRoot) != sourceRoot {
		return errors.New("staged source root is outside the fixed run-bound prefix")
	}
	runID := strings.TrimSuffix(strings.TrimPrefix(sourceRoot, prefix), "/source")
	if !runIDPattern.MatchString(runID) {
		return errors.New("staged source root does not contain one canonical run ID")
	}
	return nil
}

func openStrictStagedExecutable(
	path string,
	heldFD int,
	policy reviewedPathPolicy,
) (*reviewedResolution, error) {
	if heldFD < 3 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("strict staged executable contract is invalid")
	}
	first, err := resolveStrictStagedExecutable(path, policy)
	if err != nil {
		return nil, err
	}
	keepFirst := false
	defer func() {
		if !keepFirst {
			_ = first.close()
		}
	}()
	second, err := resolveStrictStagedExecutable(path, policy)
	if err != nil {
		return nil, fmt.Errorf("re-resolve strict staged executable: %w", err)
	}
	defer second.close()
	if first.target != second.target || !equalReviewedChains(first.chain, second.chain) {
		return nil, errors.New("strict staged executable changed while being sealed")
	}
	heldMetadata, err := reviewedMetadataFromFD(heldFD)
	if err != nil {
		return nil, fmt.Errorf("stat held strict staged executable: %w", err)
	}
	if heldMetadata != first.target {
		return nil, errors.New("strict staged path and held FD identities differ")
	}
	openedFD, err := unix.Openat2(
		first.rootFD,
		strings.TrimPrefix(path, "/"),
		&unix.OpenHow{
			Flags: uint64(unix.O_PATH | unix.O_CLOEXEC),
			Resolve: uint64(
				unix.RESOLVE_IN_ROOT |
					unix.RESOLVE_NO_MAGICLINKS |
					unix.RESOLVE_NO_SYMLINKS,
			),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("open strict staged executable without symlinks: %w", err)
	}
	defer unix.Close(openedFD)
	openedMetadata, err := reviewedMetadataFromFD(openedFD)
	if err != nil {
		return nil, fmt.Errorf("stat final strict staged executable FD: %w", err)
	}
	if openedMetadata != first.target {
		return nil, errors.New("strict staged executable final FD identity mismatch")
	}
	keepFirst = true
	return first, nil
}

func resolveStrictStagedExecutable(
	path string,
	policy reviewedPathPolicy,
) (*reviewedResolution, error) {
	rootFD, err := unix.Open(
		policy.filesystemRoot,
		unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open strict staged filesystem root: %w", err)
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
		return nil, fmt.Errorf("stat strict staged filesystem root: %w", err)
	}
	if err := validateReviewedDirectory("/", rootMetadata, policy); err != nil {
		return nil, err
	}
	resolution.chain = append(resolution.chain, reviewedChainEntry{
		path:     "/",
		kind:     "directory",
		metadata: rootMetadata,
	})
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	currentFD := rootFD
	canonicalParts := make([]string, 0, len(parts))
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, errors.New("strict staged path contains an unsafe component")
		}
		componentFD, err := unix.Openat(
			currentFD,
			part,
			unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if err != nil {
			return nil, fmt.Errorf("open strict staged path component %q: %w", part, err)
		}
		resolution.heldFDs = append(resolution.heldFDs, componentFD)
		metadata, err := reviewedMetadataFromFD(componentFD)
		if err != nil {
			return nil, fmt.Errorf("stat strict staged path component %q: %w", part, err)
		}
		canonicalParts = append(canonicalParts, part)
		componentPath := "/" + strings.Join(canonicalParts, "/")
		last := index == len(parts)-1
		if !last {
			if metadata.mode&unix.S_IFMT == unix.S_IFLNK {
				return nil, fmt.Errorf("strict staged ancestor is a symlink: %s", componentPath)
			}
			if err := validateReviewedDirectory(componentPath, metadata, policy); err != nil {
				return nil, err
			}
			resolution.chain = append(resolution.chain, reviewedChainEntry{
				path:     componentPath,
				kind:     "directory",
				metadata: metadata,
			})
			currentFD = componentFD
			continue
		}
		if metadata.mode&unix.S_IFMT == unix.S_IFLNK {
			return nil, fmt.Errorf("strict staged executable is a symlink: %s", componentPath)
		}
		if err := validateStagedExecutable(componentPath, metadata, policy); err != nil {
			return nil, err
		}
		resolution.chain = append(resolution.chain, reviewedChainEntry{
			path:     componentPath,
			kind:     "staged-executable",
			metadata: metadata,
		})
		resolution.targetFD = componentFD
		resolution.target = metadata
		resolution.canonicalPath = componentPath
	}
	if resolution.targetFD < 0 {
		return nil, errors.New("strict staged path did not resolve to an executable")
	}
	keep = true
	return resolution, nil
}

func validateStagedExecutable(
	path string,
	metadata reviewedMetadata,
	policy reviewedPathPolicy,
) error {
	if err := validateReviewedExecutable(path, metadata, policy); err != nil {
		return err
	}
	if metadata.nlink != 1 {
		return fmt.Errorf("strict staged executable has multiple links: %s", path)
	}
	return nil
}

func isLowerHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
