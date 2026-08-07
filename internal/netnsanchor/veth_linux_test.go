//go:build linux

package netnsanchor

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type recordingVethLinkHandle struct {
	add   func(netlink.Link) error
	close func()
}

func (handle *recordingVethLinkHandle) LinkAdd(link netlink.Link) error {
	return handle.add(link)
}

func (handle *recordingVethLinkHandle) Close() {
	handle.close()
}

type vethThreadObservation struct {
	stage string
	tid   int
}

func testVethClient(role string) clientFlags {
	return clientFlags{
		socket:            "wme-netns-01234567-" + role + "-0123456789abcdef",
		tokenFile:         "/run/wg-mix-ebpf-tests/01234567/secrets/netns-anchor-token",
		runID:             "01234567",
		role:              role,
		expectedDevice:    42,
		expectedInode:     100 + uint64(role[0]),
		expectedAnchorPID: 1000 + int(role[0]),
		expectedAnchorUID: 0,
	}
}

func TestValidateVethPairContractBindsBothAnonymousNamespaces(t *testing.T) {
	left := testVethClient("a")
	right := testVethClient("r")
	if err := validateVethPairContract(
		left,
		right,
		"wma012345670",
		"wmr01234567a",
	); err != nil {
		t.Fatalf("valid veth pair contract was rejected: %v", err)
	}

	tests := []struct {
		name      string
		mutate    func(*clientFlags, *clientFlags)
		leftLink  string
		rightLink string
	}{
		{
			name: "same socket",
			mutate: func(left, right *clientFlags) {
				right.socket = left.socket
			},
			leftLink:  "wma012345670",
			rightLink: "wmr01234567a",
		},
		{
			name: "same pid",
			mutate: func(left, right *clientFlags) {
				right.expectedAnchorPID = left.expectedAnchorPID
			},
			leftLink:  "wma012345670",
			rightLink: "wmr01234567a",
		},
		{
			name: "same namespace identity",
			mutate: func(left, right *clientFlags) {
				right.expectedDevice = left.expectedDevice
				right.expectedInode = left.expectedInode
			},
			leftLink:  "wma012345670",
			rightLink: "wmr01234567a",
		},
		{
			name: "different run",
			mutate: func(_ *clientFlags, right *clientFlags) {
				right.runID = "89abcdef"
			},
			leftLink:  "wma012345670",
			rightLink: "wmr01234567a",
		},
		{
			name: "wrong right role",
			mutate: func(_ *clientFlags, right *clientFlags) {
				right.role = "b"
			},
			leftLink:  "wma012345670",
			rightLink: "wmr01234567a",
		},
		{
			name:      "wrong left name",
			mutate:    func(_, _ *clientFlags) {},
			leftLink:  "foreign0",
			rightLink: "wmr01234567a",
		},
		{
			name:      "wrong right name",
			mutate:    func(_, _ *clientFlags) {},
			leftLink:  "wma012345670",
			rightLink: "foreign1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changedLeft := left
			changedRight := right
			test.mutate(&changedLeft, &changedRight)
			if err := validateVethPairContract(
				changedLeft,
				changedRight,
				test.leftLink,
				test.rightLink,
			); err == nil {
				t.Fatal("unsafe veth pair contract was accepted")
			}
		})
	}
}

func TestCreateVethPairEntersExactLeftNamespaceBeforeLinkAdd(t *testing.T) {
	expectedLeft := Identity{Device: 42, Inode: 141}
	var calls []string
	handle := &recordingVethLinkHandle{
		add: func(link netlink.Link) error {
			calls = append(calls, "link-add")
			veth, ok := link.(*netlink.Veth)
			if !ok {
				t.Fatalf("link type = %T, want *netlink.Veth", link)
			}
			if veth.Name != "wma012345670" ||
				veth.PeerName != "wmr01234567a" {
				t.Fatalf("unexpected veth names: %+v", veth)
			}
			if veth.Namespace != nil {
				t.Fatalf(
					"left namespace = %T(%v), want nil in current exact namespace",
					veth.Namespace,
					veth.Namespace,
				)
			}
			rightFD, rightOK := veth.PeerNamespace.(netlink.NsFd)
			if !rightOK || rightFD != 42 {
				t.Fatalf(
					"peer namespace FD = %T(%v), want NsFd(42)",
					veth.PeerNamespace,
					veth.PeerNamespace,
				)
			}
			return nil
		},
		close: func() {
			calls = append(calls, "close-handle")
		},
	}
	err := createVethPairInExactLeftNamespace(
		"wma012345670",
		"wmr01234567a",
		41,
		42,
		expectedLeft,
		vethPairThreadOperations{
			setNamespace: func(descriptor int, namespaceType int) error {
				calls = append(calls, "setns")
				if descriptor != 41 || namespaceType != unix.CLONE_NEWNET {
					t.Fatalf(
						"setns = (%d, %#x), want (41, %#x)",
						descriptor,
						namespaceType,
						unix.CLONE_NEWNET,
					)
				}
				return nil
			},
			currentNamespaceIdentity: func() (Identity, error) {
				calls = append(calls, "identity")
				return expectedLeft, nil
			},
			newLinkHandle: func() (vethLinkHandle, error) {
				calls = append(calls, "new-handle")
				return handle, nil
			},
		},
	)
	if err != nil {
		t.Fatalf("create atomic veth pair: %v", err)
	}
	wantCalls := "setns,identity,new-handle,link-add,close-handle"
	if got := strings.Join(calls, ","); got != wantCalls {
		t.Fatalf("veth operation order = %q, want %q", got, wantCalls)
	}

	calls = nil
	err = createVethPairInExactLeftNamespace(
		"wma012345670",
		"wmr01234567a",
		41,
		41,
		expectedLeft,
		vethPairThreadOperations{
			setNamespace: func(int, int) error {
				calls = append(calls, "unsafe-setns")
				return errors.New("must not be called")
			},
			currentNamespaceIdentity: func() (Identity, error) {
				return Identity{}, errors.New("must not be called")
			},
			newLinkHandle: func() (vethLinkHandle, error) {
				return nil, errors.New("must not be called")
			},
		},
	)
	if err == nil {
		t.Fatal("same namespace FD was accepted")
	}
	if len(calls) != 0 {
		t.Fatalf("invalid descriptor contract invoked operations %v", calls)
	}
}

func TestCreateVethPairRejectsCurrentNamespaceIdentityMismatch(t *testing.T) {
	expectedLeft := Identity{Device: 42, Inode: 141}
	handleCalls := 0
	err := createVethPairInExactLeftNamespace(
		"wma012345670",
		"wmr01234567a",
		41,
		42,
		expectedLeft,
		vethPairThreadOperations{
			setNamespace: func(int, int) error {
				return nil
			},
			currentNamespaceIdentity: func() (Identity, error) {
				return Identity{Device: 42, Inode: 142}, nil
			},
			newLinkHandle: func() (vethLinkHandle, error) {
				handleCalls++
				return nil, errors.New("must not be called")
			},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("mismatched current namespace result = %v", err)
	}
	if handleCalls != 0 {
		t.Fatalf("identity mismatch opened %d netlink handles", handleCalls)
	}
}

func TestCreateVethPairDedicatedThreadRestoresNamespaceWithoutChangingCaller(
	t *testing.T,
) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	callerTID := unix.Gettid()
	callerIdentityBefore, err := currentThreadNetworkNamespaceIdentity()
	if err != nil {
		t.Fatalf("inspect caller network namespace before wrapper: %v", err)
	}

	var observations []vethThreadObservation
	record := func(stage string) {
		observations = append(observations, vethThreadObservation{
			stage: stage,
			tid:   unix.Gettid(),
		})
	}
	var setDescriptors []int
	var setNamespaceTypes []int
	handle := &recordingVethLinkHandle{
		add: func(netlink.Link) error {
			record("link-add")
			return nil
		},
		close: func() {},
	}
	err = createVethPairOnDedicatedThread(
		"wma012345670",
		"wmr01234567a",
		41,
		42,
		callerIdentityBefore,
		vethPairThreadOperations{
			setNamespace: func(descriptor int, namespaceType int) error {
				setDescriptors = append(setDescriptors, descriptor)
				setNamespaceTypes = append(setNamespaceTypes, namespaceType)
				record("setns")
				return nil
			},
			currentNamespaceIdentity: func() (Identity, error) {
				record("identity")
				return callerIdentityBefore, nil
			},
			newLinkHandle: func() (vethLinkHandle, error) {
				record("new-handle")
				return handle, nil
			},
		},
	)
	if err != nil {
		t.Fatalf("run dedicated-thread veth wrapper: %v", err)
	}
	if len(setDescriptors) != 2 ||
		setDescriptors[0] != 41 ||
		setDescriptors[1] < 0 ||
		len(setNamespaceTypes) != 2 ||
		setNamespaceTypes[0] != unix.CLONE_NEWNET ||
		setNamespaceTypes[1] != unix.CLONE_NEWNET {
		t.Fatalf(
			"setns arguments = descriptors:%v types:%v, want enter 41 then restore an original namespace FD",
			setDescriptors,
			setNamespaceTypes,
		)
	}
	wantStages := []string{
		"setns",
		"identity",
		"new-handle",
		"link-add",
		"setns",
		"identity",
	}
	if len(observations) != len(wantStages) {
		t.Fatalf(
			"dedicated-thread observations = %+v, want stages %v",
			observations,
			wantStages,
		)
	}
	workerTID := observations[0].tid
	if workerTID <= 0 || workerTID == callerTID {
		t.Fatalf(
			"dedicated worker TID = %d, caller TID = %d",
			workerTID,
			callerTID,
		)
	}
	for index, observation := range observations {
		if observation.stage != wantStages[index] ||
			observation.tid != workerTID {
			t.Fatalf(
				"observation[%d] = %+v, want stage %q on TID %d",
				index,
				observation,
				wantStages[index],
				workerTID,
			)
		}
	}

	if currentTID := unix.Gettid(); currentTID != callerTID {
		t.Fatalf(
			"caller migrated across wrapper: before=%d after=%d",
			callerTID,
			currentTID,
		)
	}
	callerIdentityAfter, err := currentThreadNetworkNamespaceIdentity()
	if err != nil {
		t.Fatalf("inspect caller network namespace after wrapper: %v", err)
	}
	if callerIdentityAfter != callerIdentityBefore {
		t.Fatalf(
			"caller network namespace changed: before=%+v after=%+v",
			callerIdentityBefore,
			callerIdentityAfter,
		)
	}
}

func TestCreateVethPairDedicatedThreadFailsClosedOnRestoreError(t *testing.T) {
	originalIdentity, err := currentThreadNetworkNamespaceIdentity()
	if err != nil {
		t.Fatalf("inspect original test network namespace: %v", err)
	}
	restoreFailure := errors.New("injected namespace restore failure")
	setCalls := 0
	handle := &recordingVethLinkHandle{
		add:   func(netlink.Link) error { return nil },
		close: func() {},
	}
	err = createVethPairOnDedicatedThread(
		"wma012345670",
		"wmr01234567a",
		41,
		42,
		originalIdentity,
		vethPairThreadOperations{
			setNamespace: func(int, int) error {
				setCalls++
				if setCalls == 2 {
					return restoreFailure
				}
				return nil
			},
			currentNamespaceIdentity: func() (Identity, error) {
				return originalIdentity, nil
			},
			newLinkHandle: func() (vethLinkHandle, error) {
				return handle, nil
			},
		},
	)
	if !errors.Is(err, restoreFailure) || setCalls != 2 {
		t.Fatalf("restore failure result = calls:%d err:%v", setCalls, err)
	}
}
