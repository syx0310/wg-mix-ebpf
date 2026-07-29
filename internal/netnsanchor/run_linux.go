//go:build linux

package netnsanchor

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	readyFormat       = "wg-mix-ebpf-netns-anchor-v1"
	bootstrapFDEnv    = "WG_MIX_EBPF_NETNS_ANCHOR_BOOTSTRAP_FD"
	minimumTTLSeconds = 60
	maximumTTLSeconds = 86400
	ioTimeout         = 5 * time.Second
	workerTimeout     = 10 * time.Second
)

type readyRecord struct {
	RunID     string
	Role      string
	Socket    string
	AnchorPID int
	Identity  Identity
	Deadline  int64
	AnchorUID uint32
	ParentPID int
}

type clientFlags struct {
	socket            string
	tokenFile         string
	runID             string
	role              string
	expectedDevice    uint64
	expectedInode     uint64
	expectedAnchorPID int
	expectedAnchorUID uint
}

type selfImage struct {
	file     *os.File
	identity fileIdentity
}

type fileIdentity struct {
	Device uint64
	Inode  uint64
}

type vethLinkHandle interface {
	LinkAdd(netlink.Link) error
	Close()
}

type vethPairThreadOperations struct {
	setNamespace             func(int, int) error
	currentNamespaceIdentity func() (Identity, error)
	newLinkHandle            func() (vethLinkHandle, error)
}

// Run dispatches the Linux-only anonymous network namespace helper.
func Run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New(
			"expected identity, anchor, inspect-ready, probe, exec, create-veth-pair, or stop",
		)
	}
	if arguments[0] != "__worker" {
		if err := consumeBootstrapImageFD(); err != nil {
			return err
		}
	}
	switch arguments[0] {
	case "identity":
		return runIdentityCommand(arguments[1:])
	case "anchor":
		return runAnchorCommand(arguments[1:])
	case "inspect-ready":
		return runInspectReadyCommand(arguments[1:])
	case "probe":
		return runProbeCommand(arguments[1:])
	case "exec":
		return runExecCommand(arguments[1:])
	case "create-veth-pair":
		return runCreateVethPairCommand(arguments[1:])
	case "stop":
		return runStopCommand(arguments[1:])
	case "__worker":
		return runWorkerCommand(arguments[1:])
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func consumeBootstrapImageFD() error {
	value, present := os.LookupEnv(bootstrapFDEnv)
	if err := os.Unsetenv(bootstrapFDEnv); err != nil {
		return fmt.Errorf("unset bootstrap image FD environment: %w", err)
	}
	if !present {
		return errors.New("held helper image bootstrap FD is required")
	}
	descriptor, err := strconv.Atoi(value)
	if err != nil || descriptor < 3 {
		return errors.New("held helper image bootstrap FD is invalid")
	}
	defer unix.Close(descriptor)
	var heldMetadata unix.Stat_t
	if err := unix.Fstat(descriptor, &heldMetadata); err != nil {
		return fmt.Errorf("stat bootstrap helper image FD: %w", err)
	}
	currentDescriptor, err := unix.Open(
		"/proc/self/exe",
		unix.O_PATH|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf("open current bootstrap helper image: %w", err)
	}
	defer unix.Close(currentDescriptor)
	var currentMetadata unix.Stat_t
	if err := unix.Fstat(currentDescriptor, &currentMetadata); err != nil {
		return fmt.Errorf("stat current bootstrap helper image: %w", err)
	}
	if heldMetadata.Mode&unix.S_IFMT != unix.S_IFREG ||
		currentMetadata.Mode&unix.S_IFMT != unix.S_IFREG ||
		heldMetadata.Dev != currentMetadata.Dev ||
		heldMetadata.Ino != currentMetadata.Ino {
		return fmt.Errorf(
			"bootstrap helper image mismatch: held=%d:%d current=%d:%d",
			heldMetadata.Dev,
			heldMetadata.Ino,
			currentMetadata.Dev,
			currentMetadata.Ino,
		)
	}
	return nil
}

func runIdentityCommand(arguments []string) error {
	if len(arguments) != 0 {
		return errors.New("identity does not accept arguments")
	}
	commit := normalizedSourceCommit()
	if commit == unknownSourceCommit {
		return errors.New("helper source commit is unknown")
	}
	fmt.Println(commit)
	return nil
}

func runAnchorCommand(arguments []string) error {
	flags := flag.NewFlagSet("anchor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	socketName := flags.String("socket", "", "abstract unixpacket socket name")
	tokenFile := flags.String("token-file", "", "authentication token file")
	runID := flags.String("run-id", "", "run identity")
	role := flags.String("role", "", "network namespace role")
	readyFile := flags.String("ready-file", "", "exclusive readiness record")
	ttlSeconds := flags.Int("ttl-seconds", 0, "bounded anchor lifetime")
	parentPID := flags.Int("parent-pid", 0, "expected direct parent")
	expectedClientUID := flags.Uint("expected-client-uid", 0, "authorized client UID")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("anchor does not accept positional arguments")
	}
	if err := validateSocketName(*socketName); err != nil {
		return err
	}
	if !runIDPattern.MatchString(*runID) || !rolePattern.MatchString(*role) {
		return errors.New("anchor requires a canonical run ID and role")
	}
	if *ttlSeconds < minimumTTLSeconds || *ttlSeconds > maximumTTLSeconds {
		return fmt.Errorf(
			"ttl-seconds must be in [%d, %d]",
			minimumTTLSeconds,
			maximumTTLSeconds,
		)
	}
	if *parentPID <= 1 || os.Getppid() != *parentPID {
		return fmt.Errorf(
			"anchor parent mismatch: expected=%d observed=%d",
			*parentPID,
			os.Getppid(),
		)
	}
	if *expectedClientUID > uint(^uint32(0)) {
		return errors.New("expected-client-uid is out of range")
	}
	if uint(os.Geteuid()) != *expectedClientUID {
		return fmt.Errorf(
			"anchor UID mismatch: expected=%d observed=%d",
			*expectedClientUID,
			os.Geteuid(),
		)
	}
	token, err := readTokenFile(*tokenFile, uint32(os.Geteuid()))
	if err != nil {
		return err
	}
	if err := validateReadyPath(*readyFile); err != nil {
		return err
	}
	if err := unix.Prctl(
		unix.PR_SET_PDEATHSIG,
		uintptr(unix.SIGTERM),
		0,
		0,
		0,
	); err != nil {
		return fmt.Errorf("set anchor parent-death signal: %w", err)
	}
	if os.Getppid() != *parentPID {
		return errors.New("anchor parent exited while installing parent-death signal")
	}

	namespaceFD, identity, err := createAnonymousNamespace()
	if err != nil {
		return err
	}
	defer unix.Close(namespaceFD)

	deadline := time.Now().Add(time.Duration(*ttlSeconds) * time.Second)
	anchorContract := contract{
		RunID:    *runID,
		Role:     *role,
		Token:    token,
		Identity: identity,
		Deadline: deadline,
	}
	if err := anchorContract.validate(); err != nil {
		return err
	}

	listener, err := net.ListenUnix(
		"unixpacket",
		&net.UnixAddr{Name: "@" + *socketName, Net: "unixpacket"},
	)
	if err != nil {
		return fmt.Errorf("listen on abstract anchor socket: %w", err)
	}
	defer listener.Close()

	record := readyRecord{
		RunID:     *runID,
		Role:      *role,
		Socket:    *socketName,
		AnchorPID: os.Getpid(),
		AnchorUID: uint32(os.Geteuid()),
		ParentPID: *parentPID,
		Identity:  identity,
		Deadline:  deadline.Unix(),
	}
	if err := writeReadyFile(*readyFile, record); err != nil {
		return err
	}

	stopSignals := make(chan os.Signal, 1)
	signal.Notify(stopSignals, unix.SIGINT, unix.SIGTERM)
	defer signal.Stop(stopSignals)
	expiry := time.NewTimer(time.Until(deadline))
	defer expiry.Stop()
	serverStopped := make(chan struct{})
	shutdownReason := make(chan error, 1)
	go func() {
		var reason error
		select {
		case received := <-stopSignals:
			reason = fmt.Errorf(
				"anchor received %s before authenticated stop",
				received,
			)
		case <-expiry.C:
			reason = errors.New("anchor lifetime expired before authenticated stop")
		case <-serverStopped:
			return
		}
		shutdownReason <- reason
		_ = listener.Close()
	}()
	defer close(serverStopped)

	var state stopState
	for {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			if state.isStopped() {
				return nil
			}
			select {
			case reason := <-shutdownReason:
				return reason
			default:
				return fmt.Errorf("accept anchor request: %w", acceptErr)
			}
		}
		stopped, handleErr := handleAnchorConnection(
			connection,
			anchorContract,
			namespaceFD,
			uint32(*expectedClientUID),
			&state,
		)
		_ = connection.Close()
		if stopped {
			if handleErr != nil {
				return fmt.Errorf(
					"authenticated stop response failed: %w",
					handleErr,
				)
			}
			return nil
		}
		if handleErr != nil {
			// Authentication and malformed-client failures are isolated to the
			// connection; the exact namespace FD remains held by this anchor.
			continue
		}
	}
}

func handleAnchorConnection(
	connection *net.UnixConn,
	expected contract,
	namespaceFD int,
	expectedClientUID uint32,
	state *stopState,
) (bool, error) {
	if err := connection.SetDeadline(time.Now().Add(ioTimeout)); err != nil {
		return false, fmt.Errorf("set anchor connection deadline: %w", err)
	}
	credentials, err := peerCredentials(connection)
	if err != nil {
		return false, err
	}
	if credentials.Uid != expectedClientUID || credentials.Pid <= 1 {
		return false, errors.New("client peer credentials do not match anchor contract")
	}
	value, err := receiveRequest(connection)
	if err != nil {
		return false, err
	}
	if err := validateRequest(value, expected); err != nil {
		_ = sendResponse(connection, response{
			Version: protocolVersion,
			OK:      false,
			Error:   err.Error(),
		}, -1)
		return false, err
	}
	if state.isStopped() {
		err := errors.New("anchor is already stopped")
		_ = sendResponse(connection, response{
			Version: protocolVersion,
			OK:      false,
			Error:   err.Error(),
		}, -1)
		return false, err
	}
	reply := response{
		Version:  protocolVersion,
		OK:       true,
		Device:   expected.Identity.Device,
		Inode:    expected.Identity.Inode,
		Deadline: expected.Deadline.Unix(),
	}
	if value.Action == "stop" {
		if err := state.stop(); err != nil {
			_ = sendResponse(connection, response{
				Version: protocolVersion,
				OK:      false,
				Error:   err.Error(),
			}, -1)
			return false, err
		}
		if err := sendResponse(connection, reply, -1); err != nil {
			return true, err
		}
		return true, nil
	}
	if err := sendResponse(connection, reply, namespaceFD); err != nil {
		return false, err
	}
	return false, nil
}

func runInspectReadyCommand(arguments []string) error {
	flags := flag.NewFlagSet("inspect-ready", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	readyFile := flags.String("ready-file", "", "readiness record")
	runID := flags.String("run-id", "", "expected run identity")
	role := flags.String("role", "", "expected role")
	socketName := flags.String("socket", "", "expected abstract socket")
	anchorPID := flags.Int("expected-anchor-pid", 0, "expected anchor process")
	anchorUID := flags.Uint("expected-anchor-uid", 0, "expected anchor UID")
	parentPID := flags.Int("expected-parent-pid", 0, "expected anchor parent")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("inspect-ready does not accept positional arguments")
	}
	if !runIDPattern.MatchString(*runID) ||
		!rolePattern.MatchString(*role) ||
		*anchorPID <= 1 ||
		*parentPID <= 1 ||
		*anchorUID > uint(^uint32(0)) {
		return errors.New("inspect-ready expected identity is invalid")
	}
	if err := validateSocketName(*socketName); err != nil {
		return err
	}
	record, err := readReadyFile(*readyFile, uint32(*anchorUID))
	if err != nil {
		return err
	}
	if record.RunID != *runID ||
		record.Role != *role ||
		record.Socket != *socketName ||
		record.AnchorPID != *anchorPID ||
		record.AnchorUID != uint32(*anchorUID) ||
		record.ParentPID != *parentPID {
		return errors.New("readiness record does not match the requested anchor contract")
	}
	if record.AnchorPID <= 1 || record.ParentPID <= 1 {
		return errors.New("readiness record contains an invalid process identity")
	}
	if record.Identity.Device == 0 || record.Identity.Inode == 0 {
		return errors.New("readiness record contains an unsealed namespace identity")
	}
	if record.Deadline <= time.Now().Unix() {
		return errors.New("readiness record is expired")
	}
	fmt.Printf("%d %d\n", record.Identity.Device, record.Identity.Inode)
	return nil
}

func runProbeCommand(arguments []string) error {
	flags, parseErr := parseClientFlags("probe", arguments)
	if parseErr != nil {
		return parseErr
	}
	descriptor, err := acquireNamespace(flags, "probe")
	if err != nil {
		return err
	}
	return unix.Close(descriptor)
}

func runExecCommand(arguments []string) error {
	flags, command, parseErr := parseExecFlags(arguments)
	if parseErr != nil {
		return parseErr
	}
	descriptor, err := acquireNamespace(flags, "exec")
	if err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Setns(descriptor, unix.CLONE_NEWNET); err != nil {
		_ = unix.Close(descriptor)
		return fmt.Errorf("enter exact network namespace FD: %w", err)
	}
	if err := unix.Close(descriptor); err != nil {
		return fmt.Errorf("close namespace FD after setns: %w", err)
	}
	path, err := exec.LookPath(command[0])
	if err != nil {
		return fmt.Errorf("resolve command %q after setns: %w", command[0], err)
	}
	return unix.Exec(path, command, os.Environ())
}

func runCreateVethPairCommand(arguments []string) error {
	flags := flag.NewFlagSet("create-veth-pair", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	left := addPrefixedClientFlags(flags, "left-")
	right := addPrefixedClientFlags(flags, "right-")
	leftLink := flags.String("left-link", "", "left network namespace link name")
	rightLink := flags.String("right-link", "", "right network namespace link name")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("create-veth-pair does not accept positional arguments")
	}
	if err := validateVethPairContract(*left, *right, *leftLink, *rightLink); err != nil {
		return err
	}
	leftFD, err := acquireNamespace(*left, "create-veth-pair")
	if err != nil {
		return fmt.Errorf("acquire left network namespace: %w", err)
	}
	defer unix.Close(leftFD)
	rightFD, err := acquireNamespace(*right, "create-veth-pair")
	if err != nil {
		return fmt.Errorf("acquire right network namespace: %w", err)
	}
	defer unix.Close(rightFD)
	return createVethPairOnDedicatedThread(
		*leftLink,
		*rightLink,
		leftFD,
		rightFD,
		Identity{
			Device: left.expectedDevice,
			Inode:  left.expectedInode,
		},
		vethPairThreadOperations{
			setNamespace:             unix.Setns,
			currentNamespaceIdentity: currentThreadNetworkNamespaceIdentity,
			newLinkHandle:            newVethLinkHandle,
		},
	)
}

func validateVethPairContract(
	left clientFlags,
	right clientFlags,
	leftLink string,
	rightLink string,
) error {
	if err := left.validate(); err != nil {
		return fmt.Errorf("invalid left namespace contract: %w", err)
	}
	if err := right.validate(); err != nil {
		return fmt.Errorf("invalid right namespace contract: %w", err)
	}
	if left.runID != right.runID ||
		left.tokenFile != right.tokenFile ||
		left.expectedAnchorUID != right.expectedAnchorUID {
		return errors.New("veth namespace contracts do not share one run identity")
	}
	if right.role != "r" || (left.role != "a" && left.role != "b") {
		return errors.New("veth pair must connect endpoint role a or b to router role r")
	}
	if left.socket == right.socket ||
		left.expectedAnchorPID == right.expectedAnchorPID ||
		(left.expectedDevice == right.expectedDevice &&
			left.expectedInode == right.expectedInode) {
		return errors.New("veth pair requires two distinct anonymous network namespaces")
	}
	expectedLeft := "wm" + left.role + left.runID + "0"
	expectedRight := "wmr" + left.runID + left.role
	if leftLink != expectedLeft || rightLink != expectedRight {
		return fmt.Errorf(
			"veth names do not match the sealed run contract: expected=%s,%s observed=%s,%s",
			expectedLeft,
			expectedRight,
			leftLink,
			rightLink,
		)
	}
	return nil
}

func createVethPairOnDedicatedThread(
	leftLink string,
	rightLink string,
	leftFD int,
	rightFD int,
	expectedLeft Identity,
	operations vethPairThreadOperations,
) error {
	if err := validateVethPairThreadContract(
		leftLink,
		rightLink,
		leftFD,
		rightFD,
		expectedLeft,
		operations,
	); err != nil {
		return err
	}
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// Deliberately do not call runtime.UnlockOSThread. Once setns succeeds,
		// this OS thread belongs to the isolated left namespace. The documented
		// LockOSThread contract terminates a locked thread when its goroutine
		// returns without unlocking it, so it can never re-enter the Go thread
		// pool carrying that namespace.
		result <- createVethPairInExactLeftNamespace(
			leftLink,
			rightLink,
			leftFD,
			rightFD,
			expectedLeft,
			operations,
		)
	}()
	return <-result
}

func validateVethPairThreadContract(
	leftLink string,
	rightLink string,
	leftFD int,
	rightFD int,
	expectedLeft Identity,
	operations vethPairThreadOperations,
) error {
	if leftLink == "" || rightLink == "" || leftLink == rightLink ||
		leftFD < 0 || rightFD < 0 || leftFD == rightFD ||
		expectedLeft.Device == 0 || expectedLeft.Inode == 0 ||
		operations.setNamespace == nil ||
		operations.currentNamespaceIdentity == nil ||
		operations.newLinkHandle == nil {
		return errors.New("veth creation descriptor contract is invalid")
	}
	return nil
}

func createVethPairInExactLeftNamespace(
	leftLink string,
	rightLink string,
	leftFD int,
	rightFD int,
	expectedLeft Identity,
	operations vethPairThreadOperations,
) error {
	if err := validateVethPairThreadContract(
		leftLink,
		rightLink,
		leftFD,
		rightFD,
		expectedLeft,
		operations,
	); err != nil {
		return err
	}
	if err := operations.setNamespace(leftFD, unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("enter exact left network namespace FD: %w", err)
	}
	currentIdentity, err := operations.currentNamespaceIdentity()
	if err != nil {
		return err
	}
	if err := verifyIdentity(currentIdentity, expectedLeft); err != nil {
		return fmt.Errorf("current thread after left namespace setns: %w", err)
	}
	// github.com/vishvananda/netlink v1.3.1 Handle.LinkAdd calls
	// Handle.ensureIndex (and therefore Handle.LinkByName) after RTM_NEWLINK.
	// Open this route handle only after setns and identity revalidation so both
	// link creation and that lookup execute in the exact isolated left namespace.
	handle, err := operations.newLinkHandle()
	if err != nil {
		return fmt.Errorf("open netlink route handle in exact left namespace: %w", err)
	}
	if handle == nil {
		return errors.New("open netlink route handle returned nil")
	}
	defer handle.Close()
	link := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:      leftLink,
			Namespace: nil,
		},
		PeerName:      rightLink,
		PeerNamespace: netlink.NsFd(rightFD),
	}
	if err := handle.LinkAdd(link); err != nil {
		return fmt.Errorf(
			"atomically create veth pair %s/%s in exact namespace FDs: %w",
			leftLink,
			rightLink,
			err,
		)
	}
	return nil
}

func currentThreadNetworkNamespaceIdentity() (Identity, error) {
	descriptor, err := unix.Open(
		"/proc/thread-self/ns/net",
		unix.O_RDONLY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return Identity{}, fmt.Errorf(
			"open current thread network namespace after setns: %w",
			err,
		)
	}
	identity, identityErr := validateNetworkNamespaceFD(descriptor)
	closeErr := unix.Close(descriptor)
	if identityErr != nil {
		return Identity{}, fmt.Errorf(
			"validate current thread network namespace after setns: %w",
			identityErr,
		)
	}
	if closeErr != nil {
		return Identity{}, fmt.Errorf(
			"close current thread network namespace FD: %w",
			closeErr,
		)
	}
	return identity, nil
}

func newVethLinkHandle() (vethLinkHandle, error) {
	return netlink.NewHandle(unix.NETLINK_ROUTE)
}

func runStopCommand(arguments []string) error {
	flags, parseErr := parseClientFlags("stop", arguments)
	if parseErr != nil {
		return parseErr
	}
	pidfd, err := unix.PidfdOpen(flags.expectedAnchorPID, 0)
	if err != nil {
		return fmt.Errorf("open exact anchor pidfd: %w", err)
	}
	defer unix.Close(pidfd)
	reply, _, requestErr := requestAnchor(flags, "stop", false)
	var responseErr error
	if requestErr == nil {
		responseErr = verifyIdentity(
			Identity{Device: reply.Device, Inode: reply.Inode},
			Identity{Device: flags.expectedDevice, Inode: flags.expectedInode},
		)
		if responseErr != nil {
			responseErr = fmt.Errorf("stop response: %w", responseErr)
		} else if reply.Deadline <= time.Now().Unix() {
			responseErr = errors.New("stop response is expired")
		}
	}
	exitErr := waitForAnchorExit(pidfd, ioTimeout)
	if requestErr != nil {
		if exitErr == nil {
			return fmt.Errorf(
				"anchor exited after an invalid stop response: %w",
				requestErr,
			)
		}
		return fmt.Errorf(
			"stop request failed (%v) and anchor exit was not confirmed (%v)",
			requestErr,
			exitErr,
		)
	}
	if responseErr != nil {
		if exitErr != nil {
			return fmt.Errorf(
				"%v; anchor exit was not confirmed: %v",
				responseErr,
				exitErr,
			)
		}
		return responseErr
	}
	if exitErr != nil {
		return exitErr
	}
	return nil
}

func waitForAnchorExit(pidfd int, timeout time.Duration) error {
	if pidfd < 0 || timeout <= 0 || timeout > ioTimeout {
		return errors.New("anchor exit wait contract is invalid")
	}
	pollDescriptors := []unix.PollFd{{
		Fd:     int32(pidfd),
		Events: unix.POLLIN,
	}}
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errors.New(
				"exact anchor process did not exit before the bounded deadline",
			)
		}
		milliseconds := int((remaining + time.Millisecond - 1) / time.Millisecond)
		pollDescriptors[0].Revents = 0
		ready, err := unix.Poll(pollDescriptors, milliseconds)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("wait for exact anchor pidfd: %w", err)
		}
		if ready == 0 {
			return errors.New(
				"exact anchor process did not exit before the bounded deadline",
			)
		}
		if ready != 1 ||
			pollDescriptors[0].Revents&(unix.POLLIN|unix.POLLHUP) == 0 {
			return fmt.Errorf(
				"exact anchor pidfd returned no exit event: ready=%d events=%#x",
				ready,
				pollDescriptors[0].Revents,
			)
		}
		if unexpected := pollDescriptors[0].Revents &
			^(unix.POLLIN | unix.POLLHUP); unexpected != 0 {
			return fmt.Errorf(
				"exact anchor pidfd returned unexpected poll events %#x",
				unexpected,
			)
		}
		return nil
	}
}

func parseClientFlags(name string, arguments []string) (clientFlags, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addClientFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return clientFlags{}, err
	}
	if flags.NArg() != 0 {
		return clientFlags{}, fmt.Errorf("%s does not accept positional arguments", name)
	}
	if err := common.validate(); err != nil {
		return clientFlags{}, err
	}
	return *common, nil
}

func parseExecFlags(arguments []string) (clientFlags, []string, error) {
	flags := flag.NewFlagSet("exec", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addClientFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return clientFlags{}, nil, err
	}
	command := flags.Args()
	if len(command) == 0 {
		return clientFlags{}, nil, errors.New("exec requires a command after --")
	}
	if err := common.validate(); err != nil {
		return clientFlags{}, nil, err
	}
	return *common, command, nil
}

func addClientFlags(flags *flag.FlagSet) *clientFlags {
	return addPrefixedClientFlags(flags, "")
}

func addPrefixedClientFlags(flags *flag.FlagSet, prefix string) *clientFlags {
	value := &clientFlags{}
	flags.StringVar(
		&value.socket,
		prefix+"socket",
		"",
		"abstract unixpacket socket name",
	)
	flags.StringVar(
		&value.tokenFile,
		prefix+"token-file",
		"",
		"authentication token file",
	)
	flags.StringVar(&value.runID, prefix+"run-id", "", "run identity")
	flags.StringVar(&value.role, prefix+"role", "", "network namespace role")
	flags.Uint64Var(
		&value.expectedDevice,
		prefix+"expected-device",
		0,
		"sealed namespace device",
	)
	flags.Uint64Var(
		&value.expectedInode,
		prefix+"expected-inode",
		0,
		"sealed namespace inode",
	)
	flags.IntVar(
		&value.expectedAnchorPID,
		prefix+"expected-anchor-pid",
		0,
		"sealed anchor process",
	)
	flags.UintVar(
		&value.expectedAnchorUID,
		prefix+"expected-anchor-uid",
		0,
		"sealed anchor UID",
	)
	return value
}

func (flags clientFlags) validate() error {
	if err := validateSocketName(flags.socket); err != nil {
		return err
	}
	if !runIDPattern.MatchString(flags.runID) ||
		!rolePattern.MatchString(flags.role) {
		return errors.New("client requires a canonical run ID and role")
	}
	if flags.expectedDevice == 0 || flags.expectedInode == 0 {
		return errors.New("client network namespace identity is unsealed")
	}
	if flags.expectedAnchorPID <= 1 {
		return errors.New("client anchor PID is invalid")
	}
	if flags.expectedAnchorUID > uint(^uint32(0)) {
		return errors.New("client anchor UID is out of range")
	}
	if flags.tokenFile == "" || !filepath.IsAbs(flags.tokenFile) {
		return errors.New("token file must be an absolute path")
	}
	return nil
}

func acquireNamespace(flags clientFlags, action string) (int, error) {
	reply, descriptor, err := requestAnchor(flags, action, true)
	if err != nil {
		return -1, err
	}
	observed, err := validateNetworkNamespaceFD(descriptor)
	if err != nil {
		_ = unix.Close(descriptor)
		return -1, err
	}
	expected := Identity{
		Device: flags.expectedDevice,
		Inode:  flags.expectedInode,
	}
	replyIdentity := Identity{Device: reply.Device, Inode: reply.Inode}
	if err := verifyIdentity(replyIdentity, expected); err != nil {
		_ = unix.Close(descriptor)
		return -1, fmt.Errorf("anchor response: %w", err)
	}
	if err := verifyIdentity(observed, expected); err != nil {
		_ = unix.Close(descriptor)
		return -1, fmt.Errorf("received namespace FD: %w", err)
	}
	if reply.Deadline <= time.Now().Unix() {
		_ = unix.Close(descriptor)
		return -1, errors.New("anchor response is expired")
	}
	return descriptor, nil
}

func requestAnchor(
	flags clientFlags,
	action string,
	wantDescriptor bool,
) (response, int, error) {
	token, err := readTokenFile(flags.tokenFile, uint32(os.Geteuid()))
	if err != nil {
		return response{}, -1, err
	}
	dialer := net.Dialer{Timeout: ioTimeout}
	genericConnection, err := dialer.Dial(
		"unixpacket",
		"@"+flags.socket,
	)
	if err != nil {
		return response{}, -1, fmt.Errorf("connect to abstract anchor socket: %w", err)
	}
	connection, ok := genericConnection.(*net.UnixConn)
	if !ok {
		_ = genericConnection.Close()
		return response{}, -1, fmt.Errorf(
			"anchor connection has unexpected type %T",
			genericConnection,
		)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(ioTimeout)); err != nil {
		return response{}, -1, fmt.Errorf("set client connection deadline: %w", err)
	}
	credentials, err := peerCredentials(connection)
	if err != nil {
		return response{}, -1, err
	}
	if int(credentials.Pid) != flags.expectedAnchorPID ||
		credentials.Uid != uint32(flags.expectedAnchorUID) {
		return response{}, -1, fmt.Errorf(
			"anchor peer credentials mismatch: expected=%d:%d observed=%d:%d",
			flags.expectedAnchorPID,
			flags.expectedAnchorUID,
			credentials.Pid,
			credentials.Uid,
		)
	}
	if err := sendRequest(connection, request{
		Version: protocolVersion,
		Action:  action,
		RunID:   flags.runID,
		Role:    flags.role,
		Token:   token,
	}); err != nil {
		return response{}, -1, err
	}
	return receiveResponse(connection, wantDescriptor)
}

func openSelfImage() (*selfImage, error) {
	descriptor, err := unix.Open(
		"/proc/self/exe",
		unix.O_PATH|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open current helper image through /proc/self/exe: %w", err)
	}
	var metadata unix.Stat_t
	if err := unix.Fstat(descriptor, &metadata); err != nil {
		_ = unix.Close(descriptor)
		return nil, fmt.Errorf("stat current helper image: %w", err)
	}
	if metadata.Mode&unix.S_IFMT != unix.S_IFREG ||
		metadata.Dev == 0 ||
		metadata.Ino == 0 {
		_ = unix.Close(descriptor)
		return nil, errors.New("current helper image has an invalid file identity")
	}
	file := os.NewFile(uintptr(descriptor), "wg-mix-ebpf-netns-anchor-image")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("wrap current helper image FD")
	}
	return &selfImage{
		file: file,
		identity: fileIdentity{
			Device: uint64(metadata.Dev),
			Inode:  metadata.Ino,
		},
	}, nil
}

func (image *selfImage) command(
	arguments []string,
	additionalFiles ...*os.File,
) *exec.Cmd {
	command := exec.Command("/proc/self/fd/3", arguments...)
	command.ExtraFiles = append([]*os.File{image.file}, additionalFiles...)
	return command
}

func (image *selfImage) close() error {
	if image == nil || image.file == nil {
		return nil
	}
	err := image.file.Close()
	image.file = nil
	return err
}

func validateWorkerImage(descriptor int, expected fileIdentity) error {
	if descriptor < 0 || expected.Device == 0 || expected.Inode == 0 {
		return errors.New("worker helper image contract is unsealed")
	}
	var heldMetadata unix.Stat_t
	if err := unix.Fstat(descriptor, &heldMetadata); err != nil {
		return fmt.Errorf("stat held helper image FD: %w", err)
	}
	heldIdentity := fileIdentity{
		Device: uint64(heldMetadata.Dev),
		Inode:  heldMetadata.Ino,
	}
	if heldMetadata.Mode&unix.S_IFMT != unix.S_IFREG ||
		heldIdentity != expected {
		return fmt.Errorf(
			"held helper image mismatch: expected=%d:%d observed=%d:%d",
			expected.Device,
			expected.Inode,
			heldIdentity.Device,
			heldIdentity.Inode,
		)
	}
	currentDescriptor, err := unix.Open(
		"/proc/self/exe",
		unix.O_PATH|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf("worker open current helper image: %w", err)
	}
	defer unix.Close(currentDescriptor)
	var currentMetadata unix.Stat_t
	if err := unix.Fstat(currentDescriptor, &currentMetadata); err != nil {
		return fmt.Errorf("worker stat current helper image: %w", err)
	}
	currentIdentity := fileIdentity{
		Device: uint64(currentMetadata.Dev),
		Inode:  currentMetadata.Ino,
	}
	if currentMetadata.Mode&unix.S_IFMT != unix.S_IFREG ||
		currentIdentity != expected {
		return fmt.Errorf(
			"executed helper image mismatch: expected=%d:%d observed=%d:%d",
			expected.Device,
			expected.Inode,
			currentIdentity.Device,
			currentIdentity.Inode,
		)
	}
	return nil
}

func createAnonymousNamespace() (int, Identity, error) {
	descriptors, err := unix.Socketpair(
		unix.AF_UNIX,
		unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return -1, Identity{}, fmt.Errorf("create namespace transfer socketpair: %w", err)
	}
	parentFD := descriptors[0]
	childFile := os.NewFile(uintptr(descriptors[1]), "netns-transfer-child")
	if childFile == nil {
		_ = unix.Close(parentFD)
		_ = unix.Close(descriptors[1])
		return -1, Identity{}, errors.New("wrap namespace transfer child socket")
	}
	defer childFile.Close()
	image, err := openSelfImage()
	if err != nil {
		_ = unix.Close(parentFD)
		return -1, Identity{}, err
	}
	defer image.close()
	if err := unix.SetsockoptTimeval(
		parentFD,
		unix.SOL_SOCKET,
		unix.SO_RCVTIMEO,
		&unix.Timeval{Sec: int64(workerTimeout / time.Second)},
	); err != nil {
		_ = unix.Close(parentFD)
		return -1, Identity{}, fmt.Errorf("bound namespace transfer receive: %w", err)
	}

	command := image.command(
		[]string{
			"__worker",
			"--transfer-fd", "4",
			"--image-fd", "3",
			"--expected-image-device", strconv.FormatUint(image.identity.Device, 10),
			"--expected-image-inode", strconv.FormatUint(image.identity.Inode, 10),
		},
		childFile,
	)
	command.Stdin = nil
	command.Stdout = nil
	command.Stderr = os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: unix.CLONE_NEWNET,
		Pdeathsig:  syscall.SIGKILL,
	}
	// Linux ties Pdeathsig to the parent thread, not only the parent process.
	// Keep the fork/exec thread alive until the direct worker is reaped.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := command.Start(); err != nil {
		_ = unix.Close(parentFD)
		return -1, Identity{}, fmt.Errorf("start network namespace worker: %w", err)
	}
	workerPIDFD, err := unix.PidfdOpen(command.Process.Pid, 0)
	if err != nil {
		_ = unix.Close(parentFD)
		_ = childFile.Close()
		_ = image.close()
		reapErr := terminateAndReapDirectChild(command, ioTimeout)
		if reapErr != nil {
			return -1, Identity{}, fmt.Errorf(
				"pin exact network namespace worker: %v; direct-child reap failed: %w",
				err,
				reapErr,
			)
		}
		return -1, Identity{}, fmt.Errorf(
			"pin exact network namespace worker: %w",
			err,
		)
	}
	defer unix.Close(workerPIDFD)
	closeChildErr := childFile.Close()
	closeImageErr := image.close()
	workerWait := make(chan error, 1)
	go func() {
		workerWait <- command.Wait()
	}()
	namespaceFD, receiveErr := receiveWorkerNamespaceFD(parentFD)
	_ = unix.Close(parentFD)
	var waitErr error
	workerExit := time.NewTimer(workerTimeout)
	select {
	case waitErr = <-workerWait:
		if !workerExit.Stop() {
			select {
			case <-workerExit.C:
			default:
			}
		}
	case <-workerExit.C:
		if namespaceFD >= 0 {
			_ = unix.Close(namespaceFD)
		}
		reapErr := terminateAndReapWorker(
			workerPIDFD,
			workerWait,
			ioTimeout,
		)
		if reapErr != nil {
			return -1, Identity{}, fmt.Errorf(
				"network namespace worker did not exit before the bounded deadline; exact-child reap failed: %w",
				reapErr,
			)
		}
		return -1, Identity{}, errors.New(
			"network namespace worker did not exit before the bounded deadline and was reaped through its pidfd",
		)
	}
	if receiveErr != nil {
		if namespaceFD >= 0 {
			_ = unix.Close(namespaceFD)
		}
		return -1, Identity{}, receiveErr
	}
	if waitErr != nil {
		_ = unix.Close(namespaceFD)
		return -1, Identity{}, fmt.Errorf("network namespace worker failed: %w", waitErr)
	}
	if closeChildErr != nil {
		_ = unix.Close(namespaceFD)
		return -1, Identity{}, fmt.Errorf(
			"close parent copy of worker socket: %w",
			closeChildErr,
		)
	}
	if closeImageErr != nil {
		_ = unix.Close(namespaceFD)
		return -1, Identity{}, fmt.Errorf(
			"close parent copy of held helper image: %w",
			closeImageErr,
		)
	}
	identity, err := validateNetworkNamespaceFD(namespaceFD)
	if err != nil {
		_ = unix.Close(namespaceFD)
		return -1, Identity{}, err
	}
	hostFD, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(namespaceFD)
		return -1, Identity{}, fmt.Errorf("open anchor host network namespace: %w", err)
	}
	hostIdentity, hostErr := validateNetworkNamespaceFD(hostFD)
	_ = unix.Close(hostFD)
	if hostErr != nil {
		_ = unix.Close(namespaceFD)
		return -1, Identity{}, hostErr
	}
	if identity == hostIdentity {
		_ = unix.Close(namespaceFD)
		return -1, Identity{}, errors.New("worker did not create a distinct network namespace")
	}
	return namespaceFD, identity, nil
}

func terminateAndReapDirectChild(command *exec.Cmd, timeout time.Duration) error {
	if command == nil || command.Process == nil ||
		timeout <= 0 || timeout > ioTimeout {
		return errors.New("direct-child process contract is invalid")
	}
	return terminateAndReapDirectChildWithKill(
		command,
		timeout,
		command.Process.Kill,
	)
}

func terminateAndReapDirectChildWithKill(
	command *exec.Cmd,
	timeout time.Duration,
	kill func() error,
) error {
	if command == nil || command.Process == nil || kill == nil ||
		timeout <= 0 || timeout > ioTimeout {
		return errors.New("direct-child process contract is invalid")
	}
	killErr := kill()
	workerWait := make(chan error, 1)
	go func() {
		workerWait <- command.Wait()
	}()
	var signalErr error
	if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
		signalErr = fmt.Errorf("terminate unpinned direct child: %w", killErr)
	}
	reapErr := waitForBoundedChildReap(
		workerWait,
		timeout,
		"unpinned direct child",
	)
	return errors.Join(signalErr, reapErr)
}

func terminateAndReapWorker(
	pidfd int,
	workerWait <-chan error,
	timeout time.Duration,
) error {
	return terminateAndReapWorkerWithSignal(
		pidfd,
		workerWait,
		timeout,
		func(descriptor int, signal unix.Signal) error {
			return unix.PidfdSendSignal(descriptor, signal, nil, 0)
		},
	)
}

func terminateAndReapWorkerWithSignal(
	pidfd int,
	workerWait <-chan error,
	timeout time.Duration,
	sendSignal func(int, unix.Signal) error,
) error {
	if pidfd < 0 || workerWait == nil || sendSignal == nil ||
		timeout <= 0 || timeout > ioTimeout {
		return errors.New("worker pidfd reap contract is invalid")
	}
	rawSignalErr := sendSignal(pidfd, unix.SIGKILL)
	var signalErr error
	if rawSignalErr != nil && !errors.Is(rawSignalErr, unix.ESRCH) {
		signalErr = fmt.Errorf(
			"terminate exact network namespace worker: %w",
			rawSignalErr,
		)
	}
	reapErr := waitForBoundedChildReap(
		workerWait,
		timeout,
		"exact network namespace worker",
	)
	return errors.Join(signalErr, reapErr)
}

func waitForBoundedChildReap(
	workerWait <-chan error,
	timeout time.Duration,
	subject string,
) error {
	if workerWait == nil || timeout <= 0 || timeout > ioTimeout ||
		subject == "" {
		return errors.New("bounded child reap contract is invalid")
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case waitErr, ok := <-workerWait:
		if !ok {
			return fmt.Errorf("%s wait channel closed without a result", subject)
		}
		var exitErr *exec.ExitError
		if waitErr != nil && !errors.As(waitErr, &exitErr) {
			return fmt.Errorf("reap %s: %w", subject, waitErr)
		}
		return nil
	case <-timer.C:
		return fmt.Errorf(
			"%s was not reaped before the bounded deadline",
			subject,
		)
	}
}

func runWorkerCommand(arguments []string) error {
	flags := flag.NewFlagSet("__worker", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	transferFD := flags.Int("transfer-fd", -1, "inherited transfer socket")
	imageFD := flags.Int("image-fd", -1, "inherited held helper image")
	expectedImageDevice := flags.Uint64(
		"expected-image-device",
		0,
		"held helper image device",
	)
	expectedImageInode := flags.Uint64(
		"expected-image-inode",
		0,
		"held helper image inode",
	)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *imageFD != 3 || *transferFD != 4 ||
		*expectedImageDevice == 0 || *expectedImageInode == 0 {
		return errors.New("worker requires fixed held-image FD 3 and transfer FD 4")
	}
	if err := validateWorkerImage(
		*imageFD,
		fileIdentity{
			Device: *expectedImageDevice,
			Inode:  *expectedImageInode,
		},
	); err != nil {
		return err
	}
	if err := unix.Close(*imageFD); err != nil {
		return fmt.Errorf("worker close held helper image FD: %w", err)
	}
	namespaceFD, err := unix.Open(
		"/proc/self/ns/net",
		unix.O_RDONLY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf("worker open self network namespace: %w", err)
	}
	defer unix.Close(namespaceFD)
	if _, err := validateNetworkNamespaceFD(namespaceFD); err != nil {
		return err
	}
	payload := []byte("wg-mix-ebpf-netns-fd-v1")
	if err := unix.Sendmsg(
		*transferFD,
		payload,
		unix.UnixRights(namespaceFD),
		nil,
		0,
	); err != nil {
		return fmt.Errorf("worker transfer network namespace FD: %w", err)
	}
	return nil
}

func receiveWorkerNamespaceFD(socketFD int) (int, error) {
	payload := make([]byte, 64)
	control := make([]byte, unix.CmsgSpace(4))
	count, controlCount, flags, _, err := unix.Recvmsg(
		socketFD,
		payload,
		control,
		unix.MSG_CMSG_CLOEXEC,
	)
	if err != nil {
		return -1, fmt.Errorf("receive worker network namespace FD: %w", err)
	}
	messages, err := unix.ParseSocketControlMessage(control[:controlCount])
	if err != nil {
		return -1, fmt.Errorf("parse worker control message: %w", err)
	}
	var descriptors []int
	for _, message := range messages {
		rights, rightsErr := unix.ParseUnixRights(&message)
		if rightsErr != nil {
			closeDescriptors(descriptors)
			return -1, fmt.Errorf("parse worker descriptor rights: %w", rightsErr)
		}
		descriptors = append(descriptors, rights...)
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 ||
		string(payload[:count]) != "wg-mix-ebpf-netns-fd-v1" {
		closeDescriptors(descriptors)
		return -1, errors.New("invalid worker namespace transfer message")
	}
	if len(descriptors) != 1 {
		closeDescriptors(descriptors)
		return -1, fmt.Errorf(
			"worker returned %d descriptors, expected exactly one",
			len(descriptors),
		)
	}
	unix.CloseOnExec(descriptors[0])
	return descriptors[0], nil
}

func validateNetworkNamespaceFD(descriptor int) (Identity, error) {
	var metadata unix.Stat_t
	if err := unix.Fstat(descriptor, &metadata); err != nil {
		return Identity{}, fmt.Errorf("stat network namespace FD: %w", err)
	}
	namespaceType, err := unix.IoctlRetInt(descriptor, unix.NS_GET_NSTYPE)
	if err != nil {
		return Identity{}, fmt.Errorf("query namespace type: %w", err)
	}
	if namespaceType != unix.CLONE_NEWNET {
		return Identity{}, fmt.Errorf(
			"descriptor is namespace type %#x, expected network namespace %#x",
			namespaceType,
			unix.CLONE_NEWNET,
		)
	}
	identity := Identity{Device: uint64(metadata.Dev), Inode: metadata.Ino}
	if identity.Device == 0 || identity.Inode == 0 {
		return Identity{}, errors.New("network namespace FD has an invalid identity")
	}
	return identity, nil
}

func peerCredentials(connection *net.UnixConn) (*unix.Ucred, error) {
	rawConnection, err := connection.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("access unix connection: %w", err)
	}
	var credentials *unix.Ucred
	var socketErr error
	if err := rawConnection.Control(func(descriptor uintptr) {
		credentials, socketErr = unix.GetsockoptUcred(
			int(descriptor),
			unix.SOL_SOCKET,
			unix.SO_PEERCRED,
		)
	}); err != nil {
		return nil, fmt.Errorf("inspect peer credentials: %w", err)
	}
	if socketErr != nil {
		return nil, fmt.Errorf("inspect peer credentials: %w", socketErr)
	}
	if credentials == nil {
		return nil, errors.New("peer credentials are unavailable")
	}
	return credentials, nil
}

func validateSocketName(value string) error {
	if len(value) < 16 || len(value) > 90 {
		return errors.New("abstract socket name length must be in [16, 90]")
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '-' {
			return errors.New("abstract socket name contains a forbidden character")
		}
	}
	return nil
}

func readTokenFile(path string, expectedUID uint32) (string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("token file must be a canonical absolute path")
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", fmt.Errorf("open authentication token file: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), "netns-anchor-token")
	if file == nil {
		_ = unix.Close(descriptor)
		return "", errors.New("wrap authentication token file")
	}
	defer file.Close()
	var metadata unix.Stat_t
	if err := unix.Fstat(descriptor, &metadata); err != nil {
		return "", fmt.Errorf("stat authentication token file: %w", err)
	}
	if metadata.Mode&unix.S_IFMT != unix.S_IFREG ||
		metadata.Mode&0777 != 0600 ||
		metadata.Uid != expectedUID ||
		metadata.Nlink != 1 {
		return "", errors.New("authentication token file identity or mode is invalid")
	}
	content, err := io.ReadAll(io.LimitReader(file, 66))
	if err != nil {
		return "", fmt.Errorf("read authentication token file: %w", err)
	}
	token := strings.TrimSuffix(string(content), "\n")
	probe := contract{
		RunID:    "00000000",
		Role:     "a",
		Token:    token,
		Identity: Identity{Device: 1, Inode: 1},
		Deadline: time.Now().Add(time.Minute),
	}
	if err := probe.validate(); err != nil {
		return "", fmt.Errorf("invalid authentication token file: %w", err)
	}
	return token, nil
}

func validateReadyPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("ready file must be a canonical absolute path")
	}
	if filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return errors.New("ready file basename is invalid")
	}
	parentMetadata, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("inspect ready file parent: %w", err)
	}
	parentStat, ok := parentMetadata.Sys().(*syscall.Stat_t)
	if !parentMetadata.IsDir() ||
		parentMetadata.Mode()&os.ModeSymlink != 0 ||
		parentMetadata.Mode().Perm() != 0700 ||
		!ok ||
		parentStat.Uid != uint32(os.Geteuid()) {
		return errors.New(
			"ready file parent must be an owned non-symlink mode-0700 directory",
		)
	}
	return nil
}

func readyPayload(record readyRecord) string {
	return fmt.Sprintf(
		"format=%s\nrun_id=%s\nrole=%s\nsocket=%s\nanchor_pid=%d\nanchor_uid=%d\nparent_pid=%d\nnamespace_device=%d\nnamespace_inode=%d\ndeadline_unix=%d\n",
		readyFormat,
		record.RunID,
		record.Role,
		record.Socket,
		record.AnchorPID,
		record.AnchorUID,
		record.ParentPID,
		record.Identity.Device,
		record.Identity.Inode,
		record.Deadline,
	)
}

func writeReadyFile(path string, record readyRecord) error {
	descriptor, err := unix.Open(
		path,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0600,
	)
	if err != nil {
		return fmt.Errorf("create exclusive ready file: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), "netns-anchor-ready")
	if file == nil {
		_ = unix.Close(descriptor)
		return errors.New("wrap ready file")
	}
	payload := readyPayload(record)
	if _, err := io.WriteString(file, payload); err != nil {
		_ = file.Close()
		return fmt.Errorf("write ready file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync ready file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close ready file: %w", err)
	}
	return nil
}

func readReadyFile(path string, expectedUID uint32) (readyRecord, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return readyRecord{}, errors.New("ready file must be a canonical absolute path")
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return readyRecord{}, fmt.Errorf("open ready file: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), "netns-anchor-ready")
	if file == nil {
		_ = unix.Close(descriptor)
		return readyRecord{}, errors.New("wrap ready file")
	}
	defer file.Close()
	var metadata unix.Stat_t
	if err := unix.Fstat(descriptor, &metadata); err != nil {
		return readyRecord{}, fmt.Errorf("stat ready file: %w", err)
	}
	if metadata.Mode&unix.S_IFMT != unix.S_IFREG ||
		metadata.Mode&0777 != 0600 ||
		metadata.Uid != expectedUID ||
		metadata.Nlink != 1 {
		return readyRecord{}, errors.New("ready file identity or mode is invalid")
	}
	content, err := io.ReadAll(io.LimitReader(file, 2049))
	if err != nil {
		return readyRecord{}, fmt.Errorf("read ready file: %w", err)
	}
	if len(content) == 0 || len(content) > 2048 {
		return readyRecord{}, errors.New("ready file size is invalid")
	}
	if content[len(content)-1] != '\n' ||
		strings.ContainsRune(string(content), '\x00') ||
		strings.ContainsRune(string(content), '\r') {
		return readyRecord{}, errors.New("ready file framing is invalid")
	}
	values := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), "=")
		if !found || key == "" {
			return readyRecord{}, errors.New("ready file contains a malformed field")
		}
		if _, duplicate := values[key]; duplicate {
			return readyRecord{}, fmt.Errorf("ready file repeats field %q", key)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return readyRecord{}, fmt.Errorf("scan ready file: %w", err)
	}
	expectedKeys := []string{
		"format",
		"run_id",
		"role",
		"socket",
		"anchor_pid",
		"anchor_uid",
		"parent_pid",
		"namespace_device",
		"namespace_inode",
		"deadline_unix",
	}
	if len(values) != len(expectedKeys) {
		return readyRecord{}, errors.New("ready file field count is invalid")
	}
	for _, key := range expectedKeys {
		if _, present := values[key]; !present {
			return readyRecord{}, fmt.Errorf("ready file is missing field %q", key)
		}
	}
	if values["format"] != readyFormat {
		return readyRecord{}, errors.New("ready file format is unsupported")
	}
	parseInt := func(key string, bitSize int) (int64, error) {
		value, parseErr := strconv.ParseInt(values[key], 10, bitSize)
		if parseErr != nil {
			return 0, fmt.Errorf("ready field %s is invalid: %w", key, parseErr)
		}
		return value, nil
	}
	parseUint := func(key string, bitSize int) (uint64, error) {
		value, parseErr := strconv.ParseUint(values[key], 10, bitSize)
		if parseErr != nil {
			return 0, fmt.Errorf("ready field %s is invalid: %w", key, parseErr)
		}
		return value, nil
	}
	anchorPID, err := parseInt("anchor_pid", 32)
	if err != nil {
		return readyRecord{}, err
	}
	anchorUID, err := parseUint("anchor_uid", 32)
	if err != nil {
		return readyRecord{}, err
	}
	parentPID, err := parseInt("parent_pid", 32)
	if err != nil {
		return readyRecord{}, err
	}
	device, err := parseUint("namespace_device", 64)
	if err != nil {
		return readyRecord{}, err
	}
	inode, err := parseUint("namespace_inode", 64)
	if err != nil {
		return readyRecord{}, err
	}
	deadline, err := parseInt("deadline_unix", 64)
	if err != nil {
		return readyRecord{}, err
	}
	return readyRecord{
		RunID:     values["run_id"],
		Role:      values["role"],
		Socket:    values["socket"],
		AnchorPID: int(anchorPID),
		AnchorUID: uint32(anchorUID),
		ParentPID: int(parentPID),
		Identity: Identity{
			Device: device,
			Inode:  inode,
		},
		Deadline: deadline,
	}, nil
}
